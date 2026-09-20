/**
 * M13 — project-map
 *
 * 職責:多檔案專案的「檔案地圖」。從網站入口(index.html)沿 import 一路往下追,
 * 標出每個檔案是 使用中／疑似沒用到／建置設定／測試,並附上檢查範圍(掃了幾個、哪些沒掃)。
 * 輸入: files [{filename, code}]、coverage(選用,見 assets/github-import.js)、isTest(filename)(選用)
 * 輸出: { analyzed, certain, note, entries, nodes: [{path, status}], counts, coverage }
 *
 * 只用 regex 追 import(acorn 解析不了 TypeScript),也追不到動態拼出來的路徑,
 * 所以「沒用到」一律稱「疑似」;無法確定時(缺檔、動態載入、多頁面設定)certain = false,
 * scan-orchestrator 就不會把任何檔案的發現降級,避免把正在使用的檔案當成沒用到。
 * 純函式,不依賴其他模組。
 */

const PM_EXTS = ['', '.ts', '.tsx', '.js', '.jsx', '.mjs', '.vue', '.svelte', '/index.ts', '/index.tsx', '/index.js', '/index.jsx', '/index.vue'];
// import x from 'a' / export * from 'a' / import 'a' / import('a') / <script src> / <link href>
const PM_IMPORT_RE = /(?:import|export)\s[^'"`;]*?from\s*['"]([^'"]+)['"]|import\s*['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"]\s*\)|<script[^>]*?\ssrc=["']([^"']+)["']|<link[^>]*?\shref=["']([^"']+)["']/g;
// 追不到的載入方式:import(變數)、import.meta.glob、require.context
const PM_DYNAMIC_RE = /import\(\s*[^'"\s)]|import\.meta\.glob|require\.context/;
// 用檔案位置決定頁面的框架:入口不是 index.html,這裡不判斷
const PM_FILE_ROUTING_RE = /(^|\/)(next|nuxt|astro|svelte|remix)\.config\.[cm]?[jt]s$/i;
// 不在 import 鏈上、但有它的用途:建置腳本、部署設定、.env
const PM_BUILD_RE = /(^|\/)(scripts?|deployment|deploy|tools|supabase|\.github)\/|\.config\.[cm]?[jt]s$|(^|\/)(vercel|netlify|firebase)\.json$|(^|\/)\.env(\.|$)/i;

function pmNormalize(p) {
  const out = [];
  p.split('/').forEach(s => { if (s === '..') out.pop(); else if (s && s !== '.') out.push(s); });
  return out.join('/');
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
  if (p === null && (spec.startsWith('./') || spec.startsWith('../') || /\.html?$/i.test(from))) p = from.slice(0, from.lastIndexOf('/') + 1) + spec;
  if (p === null) return null;
  p = pmNormalize(p);
  for (const e of PM_EXTS) if (paths.has(p + e)) return p + e;
  return null;
}

function pmImportsOf(code) {
  const out = new Set();
  for (const m of code.matchAll(PM_IMPORT_RE)) out.add(m[1] || m[2] || m[3] || m[4] || m[5]);
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
  const byPath = new Map(files.map(f => [f.filename, f]));
  const cov = coverage || null;
  const missing = cov ? cov.skippedLimit.length + cov.skippedLarge.length + cov.failed.length : 0;
  const map = { analyzed: false, certain: false, note: null, entries: [], nodes: [], counts: { used: 0, unused: 0, build: 0, test: 0, unknown: 0 }, coverage: cov };

  // 入口:最上層的 index.html
  const htmls = files.map(f => f.filename).filter(p => /(^|\/)index\.html$/i.test(p));
  const minDepth = Math.min(...htmls.map(p => p.split('/').length));
  const entries = htmls.filter(p => p.split('/').length === minDepth);
  const base = entries.length ? entries[0].slice(0, entries[0].lastIndexOf('/') + 1) : '';

  const reached = new Set(entries);
  const queue = entries.slice();
  const aliases = pmAliases(files);
  let dynamic = false;
  while (queue.length) {
    const from = queue.shift();
    const code = byPath.get(from).code;
    if (PM_DYNAMIC_RE.test(code)) dynamic = true;
    pmImportsOf(code).forEach(spec => {
      const to = pmResolve(from, spec, paths, aliases, base);
      if (to && !reached.has(to)) { reached.add(to); queue.push(to); }
    });
  }

  let note = null;
  if (!entries.length) note = '找不到網站入口（index.html），所以沒有判斷哪些檔案有在使用。';
  else if (files.some(f => PM_FILE_ROUTING_RE.test(f.filename))) note = '這個專案用 Next.js／Nuxt 之類的框架，頁面由檔案位置決定，本工具沒有判斷哪些檔案有在使用。';
  else if (reached.size <= entries.length) note = '入口 index.html 沒有引用任何程式檔，所以沒有判斷哪些檔案有在使用。';
  if (note) { map.note = note; map.nodes = files.map(f => ({ path: f.filename, status: 'unknown' })); map.counts.unknown = files.length; return map; }

  const multiPage = files.some(f => /(^|\/)vite\.config\.[cm]?[jt]s$/.test(f.filename) && /rollupOptions[\s\S]{0,300}input/.test(f.code));
  let uncertain = null;
  if (missing) uncertain = '有檔案沒檢查到（見上方檢查範圍），無法確定哪些檔案沒在使用';
  else if (dynamic) uncertain = '專案裡有動態載入（例如 import.meta.glob、import(變數)），追蹤可能漏掉檔案';
  else if (multiPage) uncertain = '專案設定了多個頁面入口，追蹤可能漏掉檔案';

  map.analyzed = true;
  map.certain = !uncertain;
  map.entries = entries;
  if (uncertain) map.note = uncertain + '，所以沒有把任何檔案標成「疑似沒用到」。';
  files.forEach(f => {
    let status;
    if (reached.has(f.filename)) status = 'used';
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
