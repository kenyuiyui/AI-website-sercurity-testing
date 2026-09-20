/**
 * M13 — project-map
 *
 * 職責:多檔案專案的「檔案地圖」。從網頁檔(index.html 等)沿 import／require／資源路徑一路往下追,
 * 標出每個檔案的角色,並附上檢查範圍與「入口用到哪些檔案」的引用關係。
 * 輸入: files [{filename, code}]、coverage(選用,見 assets/github-import.js)、isTest(filename)(選用)
 * 輸出: { analyzed, certain, note, entries, primary, entrySkipped, nodes: [{path, status}], edges, counts, coverage }
 *
 * 狀態: used(使用中) / page(另一個網頁,沒有被首頁連到) / build(建置設定) / test(測試範例)
 *       / unused(疑似沒用到) / unknown(無法判斷)
 *
 * 兩段追蹤:
 *   1. 網頁檔(.html)都是入口 → 追到的檔案是「使用中」(多頁網站的其他頁面也會被送上線)
 *   2. 建置腳本與測試檔當第二批起點 → 它們用到的檔案標成 建置／測試,而不是「沒用到」
 *      (只被測試腳本 require 的檔案不該被當成可以刪)
 *
 * 只用 regex 追引用(acorn 解析不了 TypeScript),也追不到動態拼出來的路徑,
 * 所以「沒用到」一律稱「疑似」;無法確定時(缺檔、動態載入、多頁面設定、入口沒引用任何程式檔)
 * certain = false,scan-orchestrator 就不會把任何檔案的發現降級。
 *
 * 為什麼:引用與動態載入只看真正的程式碼(source-mask),否則註解裡寫的 import(…) 會讓整個專案變成「無法判斷」。(背景見 docs/CHANGELOG.md)
 */

const PM_EXTS = ['', '.ts', '.tsx', '.js', '.jsx', '.mjs', '.vue', '.svelte', '/index.ts', '/index.tsx', '/index.js', '/index.jsx', '/index.vue'];
// import x from 'a' / export * from 'a' / import 'a' / import('a') / require('a') / <script src> / <link href> / <a href>
const PM_IMPORT_RE = /(?:import|export)\s[^'"`;]*?from\s*['"]([^'"]+)['"]|import\s*['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"]\s*\)|require\(\s*['"]([^'"]+)['"]\s*\)|<(?:script|a)[^>]*?\s(?:src|href)=["']([^"']+)["']|<link[^>]*?\shref=["']([^"']+)["']/g;
// 其他用「字串路徑」載入的寫法:navigator.serviceWorker.register('/sw.js')、new Worker('./w.js')、fetch('./data.json')
const PM_PATH_STRING_RE = /['"`]((?:\.{0,2}\/)?[\w./-]+\.[A-Za-z0-9]{2,5})['"`]/g;
// 追不到的載入方式:import(變數)、import.meta.glob、require.context
const PM_DYNAMIC_RE = /import\(\s*[^'"\s)]|import\.meta\.glob|require\.context/;
// 用檔案位置決定頁面的框架:入口不是 index.html,這裡不判斷
const PM_FILE_ROUTING_RE = /(^|\/)(next|nuxt|astro|svelte|remix)\.config\.[cm]?[jt]s$/i;
// 不在引用鏈上、但有它的用途:建置與驗證腳本、部署設定、.env
const PM_BUILD_RE = /(^|\/)(scripts?|deployment|deploy|tools|supabase|\.github|eval|benchmarks?)\/|\.config\.[cm]?[jt]s$|(^|\/)(vercel|netlify|firebase)\.json$|(^|\/)\.env(\.|$)/i;
const PM_HTML_RE = /\.html?$/i;

function pmNormalize(p) {
  const out = [];
  p.split('/').forEach(s => { if (s === '..') out.pop(); else if (s && s !== '.') out.push(s); });
  return out.join('/');
}

/** source-mask 的三個函式:瀏覽器是全域,Node 走 require;拿不到就不遮罩 */
function pmSourceMask() {
  if (typeof blankNonCode === 'function') return { blankNonCode: blankNonCode, buildCodeMask: buildCodeMask, languageFromFilename: languageFromFilename };
  try { return require('./source-mask'); } catch (e) { return null; }
}

/**
 * 兩種「只看程式碼」的版本:
 *   imports — 只抹掉註解與正則,字串留著(引用路徑本身就是字串)
 *   strict  — 連字串也抹掉,用來判斷有沒有動態載入(字串裡提到 import.meta.glob 不算)
 */
function pmCodeViews(file) {
  const sm = pmSourceMask();
  if (!sm) return { imports: file.code, strict: file.code };
  try {
    const mask = sm.buildCodeMask(file.code, { language: sm.languageFromFilename(file.filename) });
    // 1 = 連兩個字以上的字串都抹掉(動態載入是語法,不會寫在字串裡);Infinity = 字串全留(引用路徑本身就是字串)
    return { imports: sm.blankNonCode(file.code, mask, Infinity), strict: sm.blankNonCode(file.code, mask, 1) };
  } catch (e) {
    return { imports: file.code, strict: file.code };
  }
}

/** vite.config 裡的 '@': path.resolve(__dirname, './src') 之類;讀不到就用最常見的 @、~ → src */
function pmAliases(files) {
  const cfg = files.find(f => /(^|\/)vite\.config\.[cm]?[jt]s$/.test(f.filename));
  const out = [];
  if (cfg) for (const m of cfg.code.matchAll(/['"]?([@~][\w-]*)['"]?\s*:[^\n]*?['"]\.\/?([\w./-]+)['"]/g)) out.push([m[1], m[2].replace(/\/$/, '')]);
  return out.length ? out : [['@', 'src'], ['~', 'src']];
}

function pmResolve(from, spec, paths, aliases, base) {
  spec = spec.replace(/[?#].*$/, '');
  if (!spec || /^(data:|https?:|\/\/|mailto:)/i.test(spec)) return null;
  let p = null;
  for (const [key, dir] of aliases) if (spec.startsWith(key + '/')) p = base + dir + '/' + spec.slice(key.length + 1);
  if (p === null && spec.startsWith('/')) p = base + spec.slice(1);
  // HTML 裡的 assets/app.js(沒有 ./)也是相對於該 HTML;JS 裡的裸名稱是 npm 套件,不追
  if (p === null && (spec.startsWith('./') || spec.startsWith('../') || PM_HTML_RE.test(from))) p = from.slice(0, from.lastIndexOf('/') + 1) + spec;
  if (p === null) return null;
  p = pmNormalize(p);
  for (const e of PM_EXTS) if (paths.has(p + e)) return p + e;
  return null;
}

function pmImportsOf(code) {
  const out = new Set();
  for (const m of code.matchAll(PM_IMPORT_RE)) out.add(m[1] || m[2] || m[3] || m[4] || m[5] || m[6]);
  // 字串路徑:只有「剛好對得上專案裡某個檔案」時才算,否則忽略
  for (const m of code.matchAll(PM_PATH_STRING_RE)) out.add(m[1]);
  out.delete(undefined);
  return [...out];
}

/**
 * @param {Array<{filename: string, code: string}>} files
 * @param {{total?: number, skippedLimit?: string[], skippedLarge?: string[], failed?: string[], notChecked?: object}|null} coverage
 * @param {(filename: string) => boolean} [isTest]
 */
function buildProjectMap(files, coverage, isTest) {
  const paths = new Set(files.map(f => f.filename));
  const views = new Map(files.map(f => [f.filename, pmCodeViews(f)]));
  const cov = coverage || null;
  const missing = cov ? cov.skippedLimit.length + cov.skippedLarge.length + cov.failed.length : 0;
  const map = {
    analyzed: false, certain: false, note: null, entries: [], primary: '', entrySkipped: [],
    nodes: [], edges: {}, counts: { used: 0, page: 0, unused: 0, build: 0, test: 0, unknown: 0 }, coverage: cov
  };
  // 入口本身沒被檢查(太大／被上限擠掉／下載失敗)時,整份結果都不能當作「沒問題」,要單獨講清楚
  const skippedPaths = cov ? [].concat(cov.skippedLimit, cov.skippedLarge, cov.failed) : [];
  map.entrySkipped = skippedPaths.filter(p => /(^|\/)index\.html?$/i.test(p));

  // 入口:所有網頁檔(放上線後每一頁都打得開);主要入口取最上層的 index.html
  const pages = files.map(f => f.filename).filter(p => PM_HTML_RE.test(p));
  const indexes = pages.filter(p => /(^|\/)index\.html?$/i.test(p));
  const primary = indexes.sort((a, b) => a.split('/').length - b.split('/').length)[0] || pages[0] || '';
  const base = primary ? primary.slice(0, primary.lastIndexOf('/') + 1) : '';
  const aliases = pmAliases(files);
  map.entries = pages;
  map.primary = primary;

  let dynamic = false;
  /** 從 seeds 出發沿引用往下走;回傳走到的檔案集合,同時把引用關係記進 map.edges */
  function walk(seeds, visited) {
    const reached = new Set();
    const queue = [];
    seeds.forEach(s => { if (!visited.has(s)) { reached.add(s); queue.push(s); } });
    while (queue.length) {
      const from = queue.shift();
      const view = views.get(from) || { imports: '', strict: '' };
      if (PM_DYNAMIC_RE.test(view.strict)) dynamic = true;
      const children = [];
      pmImportsOf(view.imports).forEach(spec => {
        const to = pmResolve(from, spec, paths, aliases, base);
        if (!to || to === from) return;
        children.push(to);
        if (!reached.has(to) && !visited.has(to)) { reached.add(to); queue.push(to); }
      });
      if (children.length) map.edges[from] = [...new Set(children)];
    }
    return reached;
  }

  if (!pages.length || files.some(f => PM_FILE_ROUTING_RE.test(f.filename))) {
    map.note = !pages.length && map.entrySkipped.length
      ? `網站主檔 ${map.entrySkipped[0]} 這次沒有被檢查（檔案太大或下載失敗），所以這次幾乎沒有看到你的網站內容。`
      : !pages.length
        ? '找不到網站入口（index.html），所以沒有判斷哪些檔案有在使用。'
        : '這個專案用 Next.js／Nuxt 之類的框架，頁面由檔案位置決定，本工具沒有判斷哪些檔案有在使用。';
    map.nodes = files.map(f => ({ path: f.filename, status: 'unknown' }));
    map.counts.unknown = files.length;
    return map;
  }

  // 第一段:首頁 → 沿引用往下(其他網頁各自再走一次,它們自己的引用也算「有在使用」)
  const fromPrimary = walk([primary], new Set());
  const used = new Set(fromPrimary);
  pages.forEach(p => { if (!used.has(p)) walk([p], used).forEach(x => used.add(x)); });

  // 第二段:建置腳本與測試檔是另一批起點,它們用到的檔案不是「沒用到」,而是工具用
  const toolCat = new Map();
  files.forEach(f => {
    if (used.has(f.filename)) return;
    const cat = isTest && isTest(f.filename) ? 'test' : PM_BUILD_RE.test(f.filename) ? 'build' : null;
    if (cat) walk([f.filename], used).forEach(p => { if (!toolCat.has(p) || cat === 'test') toolCat.set(p, cat); });
  });

  const multiPage = files.some(f => /(^|\/)vite\.config\.[cm]?[jt]s$/.test(f.filename) && /rollupOptions[\s\S]{0,300}input/.test(f.code));
  const codeFiles = files.filter(f => !PM_HTML_RE.test(f.filename)).length;
  let uncertain = null;
  if (missing) uncertain = '有檔案沒檢查到（見上方檢查範圍），無法確定哪些檔案沒在使用';
  else if (dynamic) uncertain = '專案裡有動態載入（例如 import.meta.glob、import(變數)），追蹤可能漏掉檔案';
  else if (multiPage) uncertain = '專案設定了多個頁面入口，追蹤可能漏掉檔案';
  else if (used.size <= pages.length && codeFiles) uncertain = '入口網頁沒有直接引用任何程式檔（可能是打包後的網站），追蹤不到引用關係';

  map.analyzed = true;
  map.certain = !uncertain;
  if (uncertain) map.note = uncertain + '，所以沒有把任何檔案標成「疑似沒用到」。';
  else if (used.size <= pages.length) map.note = '這是單檔式網站（程式碼都寫在網頁檔裡），沒有其他程式檔要追蹤。';
  files.forEach(f => {
    let status;
    if (fromPrimary.has(f.filename)) status = 'used';
    else if (PM_HTML_RE.test(f.filename)) status = f.filename === primary ? 'used' : 'page';
    else if (used.has(f.filename)) status = 'used';
    else if (toolCat.has(f.filename)) status = toolCat.get(f.filename);
    else if (isTest && isTest(f.filename)) status = 'test';
    else if (PM_BUILD_RE.test(f.filename)) status = 'build';
    else status = uncertain ? 'unknown' : 'unused';
    map.nodes.push({ path: f.filename, status });
    map.counts[status]++;
  });
  return map;
}

// ── 環境相容匯出:Node.js(require)與瀏覽器(<script src>)共用同一份檔案 ──
// Node 測試環境: module 物件存在 → 走 module.exports,供 require() 使用
// 瀏覽器環境: module 不存在 → 略過這段,函式/常數已是全域作用域下的宣告,
//            可直接被 index.html 或其他 <script> 使用
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { buildProjectMap };
}
