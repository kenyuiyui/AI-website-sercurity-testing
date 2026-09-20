/**
 * scan-orchestrator — 掃描流程的唯一來源
 *
 * 職責:依序呼叫各偵測模組、合併 Finding[]、補上行號、組出「本次檢查的限制」提示。
 * 瀏覽器(assets/app.js)與 Node 驗證腳本(eval/eval-orchestrator.js)共用這一份,
 * 新增偵測模組時只需要改 getSingleFileDetectors() 與 index.html 的 <script> 清單。
 *
 * 依賴:其他 modules/*.js 必須先載入(瀏覽器靠 <script> 順序,Node 靠下方自動 require)。
 */

// Node 環境:把各模組的匯出掛到 globalThis,讓下方以「全域名稱」呼叫的寫法與瀏覽器完全一致。
if (typeof module !== 'undefined' && module.exports && typeof keyDetector === 'undefined') {
  [
    'source-mask', 'key-detector', 'jwt-analyzer', 'hash-detector', 'secret-heuristics', 'csp-detector', 'project-map',
    'idor-detector', 'language-detector', 'finding-renderer', 'sql-injection-detector',
    'insecure-deserialize-detector', 'rate-limit-coverage-detector', 'field-masking-consistency-detector', 'xss-detector'
  ].forEach(name => Object.assign(globalThis, require('./' + name)));
}

const IDOR_AST_DEGRADED_NOTICE = '「權限檢查」這一項這次改用較簡單的比對方式（程式碼含 TypeScript 型別語法，精確分析無法解析），箭頭函式寫法可能抓不到，建議自行確認。';
const MINIFIED_NOTICE = '這段看起來是打包壓縮過的程式碼（常見於「檢視網頁原始碼」或 build 後的 .js 檔）。金鑰外洩的檢查仍然有效；但「權限檢查」「SQL 拼接」這類要看懂程式邏輯的項目，在壓縮後幾乎無法判斷。想檢查這些，請改用原始檔（例如用上方「從 GitHub 匯入」）。';

/**
 * 單檔案偵測器清單(順序即模組執行順序;畫面顯示順序由 finding-renderer 依嚴重度重排)。
 * 每個偵測器: (code, ctx) => Finding[];ctx.byId 可取得先前偵測器的結果
 * (M4 secretHeuristics 用 M1、M2 的結果去重複)。
 */
function getSingleFileDetectors() {
  return [
    { id: 'M1', run: code => keyDetector(code) },
    { id: 'M2', run: code => jwtAnalyzer(code) },
    { id: 'M3', run: (code, ctx) => hashDetector(code, ctx) },
    { id: 'M4', run: (code, ctx) => secretHeuristics(code, ctx.byId.M1.concat(ctx.byId.M2)) },
    { id: 'M5', run: code => cspDetector(code) },
    // 為什麼:正則版 IDOR 只看真正的程式碼,否則字串裡的範例程式碼(單檔版網頁內嵌的示範字串)會誤報。(背景見 docs/CHANGELOG.md)
    { id: 'M6', run: (code, ctx) => { const r = idorDetectorWithMeta(code, blankNonCode(code, ctx.mask)); ctx.astUsed = r.astUsed; return r.findings; } },
    { id: 'M9', run: code => sqlInjectionDetector(code) },
    { id: 'M10', run: (code, ctx) => insecureDeserializeDetector(code, ctx) },
    { id: 'M14', run: (code, ctx) => xssDetector(code, ctx) },
    // M12 需要看字串裡的路由路徑,所以只把註解換成空白(字串保留)
    { id: 'M12', run: (code, ctx) => rateLimitCoverageDetector(blankNonCode(code, ctx.mask, Infinity)) }
  ];
}

/**
 * 依偵測模組提供的 index(字元位置)或 match(原始片段)補上 line(1-based)、start、end。
 * 同一片段出現多次時,依序對應到下一個出現位置。找不到位置的 Finding 不加 line(畫面不顯示行號)。
 * match 欄位只供定位用,畫面層絕不可直接輸出(可能含未遮罩的金鑰)。
 */
function attachLocations(code, findings) {
  const cursors = {};
  findings.forEach(f => {
    let start = -1;
    let len = 0;
    if (typeof f.index === 'number' && f.index >= 0) {
      start = f.index;
      if (typeof f.match === 'string' && code.substr(start, f.match.length) === f.match) {
        len = f.match.length;
      } else {
        const nl = code.indexOf('\n', start);
        len = (nl < 0 ? code.length : nl) - start;
      }
    } else if (typeof f.match === 'string' && f.match) {
      const from = cursors[f.match] || 0;
      start = code.indexOf(f.match, from);
      if (start < 0) start = code.indexOf(f.match);
      if (start >= 0) cursors[f.match] = start + 1;
      len = f.match.length;
    }
    if (start < 0) return;
    f.start = start;
    f.end = start + len;
    f.line = code.slice(0, start).split('\n').length;
  });
  return findings;
}

/**
 * 粗略判斷是否為打包壓縮過的程式碼:有超長且語句密集的單行,或平均每行很長。
 * @param {string} code
 * @returns {boolean}
 */
function looksMinified(code) {
  if (!code || code.length < 400) return false;
  const lines = code.split('\n');
  const longest = lines.reduce((m, l) => Math.max(m, l.length), 0);
  const avg = code.length / lines.length;
  const denseLine = lines.some(l => l.length > 1000 && (l.match(/[;{}]/g) || []).length > l.length / 40);
  return denseLine || (code.length > 2000 && avg > 300) || longest > 5000;
}

/**
 * 本次檢查的限制提示,畫面放在結果最上方(level=warn 醒目、info 次要)。
 * @returns {Array<{id: string, level: 'warn'|'info', text: string}>}
 */
function buildNotices(code, astUsed) {
  const notices = [];
  const minified = looksMinified(code);
  if (minified) notices.push({ id: 'minified', level: 'warn', text: MINIFIED_NOTICE });
  // 只在程式碼真的有資料庫查詢時,「權限檢查退回簡易版」才有意義;壓縮檔已有上面的提示
  if (!minified && !astUsed && looksLikeJsxOrTypeScript(code) && DB_CALL_PATTERN.test(code)) {
    notices.push({ id: 'idor-degraded', level: 'info', text: IDOR_AST_DEGRADED_NOTICE });
  }
  const lang = languageDetector(code);
  if (lang) notices.push({ id: 'language', level: 'info', text: lang });
  return notices;
}

// ── 檔案情境:依檔名與內容調整結果(不改偵測規則本身) ──

// 測試／範例檔:目錄或檔名含 test、spec、fixture、sample、mock、e2e 等字樣
const TEST_DIR_RE = /(^|\/)(tests?|__tests__|specs?|e2e|cypress|playwright|fixtures?|__fixtures__|__mocks__|mocks?|examples?|samples?|demos?|benchmarks?)\//i;
const TEST_NAME_RE = /(^|[._-])(tests?|specs?|smoke|regression|fixtures?|samples?|mocks?|e2e|stories)([._-]|$)/i;
// 金鑰類 kind:在測試檔裡若「看起來是真的」仍維持原層級(公開 repo 的測試檔外洩一樣是外洩)
const SECRET_KINDS = new Set(['plain_key', 'supabase_service_role', 'supabase_anon', 'jwt_unknown_role', 'line_bot_token_suspected', 'firebase_config_exposed', 'endpoint_url', 'env_file_secret']);
const FRAMEWORK_CONFIG_RE = /(^|\/)((next|nuxt|vite|astro|svelte|remix)\.config\.[cm]?[jt]s|(vercel|netlify|firebase)\.json|netlify\.toml)$/i;

function isTestLikePath(filename) {
  if (!filename) return false;
  const base = String(filename).split('/').pop().replace(/\.[^.]+$/, '');
  return TEST_DIR_RE.test(filename) || TEST_NAME_RE.test(base);
}

function hasSequentialRun(s, len) {
  let run = 1;
  for (let i = 1; i < s.length; i++) {
    const seq = /[a-z0-9]/i.test(s[i]) && s.charCodeAt(i) === s.charCodeAt(i - 1) + 1;
    run = seq ? run + 1 : 1;
    if (run >= len) return true;
  }
  return false;
}

/** 明顯是範例用的假金鑰:含 test/fake/example 等字樣、連續字元(abcdefgh、12345678)、或字元種類極少 */
function looksLikePlaceholderSecret(value) {
  if (!value) return false;
  const v = String(value);
  if (/(test|fake|dummy|example|sample|placeholder|demo|xxxx|your[-_]?(api|key|token|secret)|change[-_]?me|redacted|not[-_]?a[-_]?real)/i.test(v)) return true;
  // 連續字元,也檢查只取字母、只取數字後的序列(a1B2c3D4… 這類交錯寫法)
  if (hasSequentialRun(v, 8) || hasSequentialRun(v.replace(/[^a-z]/gi, '').toLowerCase(), 8) || hasSequentialRun(v.replace(/\D/g, ''), 8)) return true;
  const body = v.replace(/^[a-z]{2,4}[-_](proj[-_]|ant[-_])?/i, '');
  return body.length >= 16 && new Set(body).size <= 4;
}

/**
 * 依檔案情境調整:
 * - 明顯的假金鑰 → 參考
 * - 測試／範例檔裡的非金鑰發現 → 參考;看起來是真的金鑰維持原層級並加註
 * - 同一行同一種問題只留一筆
 * 被調整的 Finding 會帶 context('placeholder' | 'test')與 originalTier,畫面與報告據此標示。
 */
function applyFileContext(findings, filename) {
  const testFile = isTestLikePath(filename);
  const seen = new Set();
  return findings.filter(f => {
    if (typeof f.line === 'number') {
      const key = f.kind + '@' + f.line;
      if (seen.has(key)) return false;
      seen.add(key);
    }
    return true;
  }).map(f => {
    if (SECRET_KINDS.has(f.kind) && looksLikePlaceholderSecret(f.match)) {
      return Object.assign({}, f, { tier: 3, originalTier: f.tier, context: 'placeholder' });
    }
    if (testFile) {
      if (SECRET_KINDS.has(f.kind)) return Object.assign({}, f, { context: 'test-real-secret' });
      return Object.assign({}, f, { tier: 3, originalTier: f.tier, context: 'test' });
    }
    return f;
  });
}

/**
 * 依「網站入口有沒有用到這個檔案」調整(見 project-map.js):
 * - 疑似沒用到的檔案裡的發現 → 參考(建議刪檔);金鑰類維持原層級,因為公開專案裡沒在用的金鑰照樣外洩
 * - 追不確定時(certain = false)完全不調整
 */
function applyUsageContext(findings, projectMap) {
  if (!projectMap || !projectMap.analyzed || !projectMap.certain) return findings;
  const unused = new Set(projectMap.nodes.filter(n => n.status === 'unused').map(n => n.path));
  return findings.map(f => {
    if (!unused.has(f.filename) || f.context || f.tier === 3) return f;
    if (SECRET_KINDS.has(f.kind)) return Object.assign({}, f, { context: 'unused-secret' });
    return Object.assign({}, f, { tier: 3, originalTier: f.tier, context: 'unused' });
  });
}

/** 檢查範圍的提示:有沒檢查到的檔案 → warn;不檢查的檔案類型、無法判斷使用狀態的原因 → info */
function buildCoverageNotices(projectMap, scanned) {
  const notices = [];
  const cov = projectMap.coverage;
  if (cov) {
    const reasons = [];
    if (cov.skippedLimit.length) reasons.push(`${cov.skippedLimit.length} 個超過一次檢查的檔案數上限`);
    if (cov.skippedLarge.length) reasons.push(`${cov.skippedLarge.length} 個超過 2MB`);
    if (cov.failed.length) reasons.push(`${cov.failed.length} 個下載失敗`);
    if (reasons.length) {
      notices.push({ id: 'coverage', level: 'warn', text: `這次沒有檢查全部檔案：專案有 ${cov.total} 個程式碼檔，實際檢查了 ${scanned} 個，其餘 ${cov.total - scanned} 個沒檢查到（${reasons.join('、')}）。想檢查其他檔案，可改貼子資料夾的網址。` });
    }
    const types = Object.keys(cov.notChecked || {});
    if (types.length) {
      notices.push({ id: 'not-checked', level: 'info', text: `本工具不檢查資料庫規則與部署設定檔（${types.map(t => `.${t} ${cov.notChecked[t]} 個`).join('、')}）。其中的權限設定（例如 Supabase 的 RLS 規則就寫在 .sql 檔）請自行確認。` });
    }
  }
  if (projectMap.entrySkipped && projectMap.entrySkipped.length) {
    notices.unshift({ id: 'entry-skipped', level: 'warn', text: `網站主檔 ${projectMap.entrySkipped[0]} 沒有被檢查到（檔案太大或下載失敗）。單檔式網站的程式碼幾乎都在這個檔案裡，所以這次的結果不能當作「沒問題」。請把這個檔案直接拖進來，或用「開啟檔案」單獨檢查它。` });
  }
  // 貼上的幾段程式碼(沒有真實專案結構)不需要「找不到入口」的提示;GitHub 匯入或有入口時才說明
  if (projectMap.note && (cov || projectMap.analyzed)) notices.push({ id: 'usage', level: 'info', text: projectMap.note });
  return notices;
}

// ── 舊版本資料夾 ──
// 為什麼:一個 repo 放 v1.0.0/ v2.0/ 好幾版網站時,舊版的問題會蓋過現役版本。(背景見 docs/CHANGELOG.md)
const VERSION_DIR_RE = /^v?\d+(?:[._-][\w.]+)*$/i;

/** 版本資料夾名稱 → 可比較的數字陣列(非數字段落算 0):v3.2.x → [3,2,0] */
function versionRank(dir) {
  return dir.replace(/^v/i, '').split(/[._-]/).map(seg => (/^\d+$/.test(seg) ? Number(seg) : 0));
}

function newerVersion(a, b) {
  const ra = versionRank(a);
  const rb = versionRank(b);
  for (let i = 0; i < Math.max(ra.length, rb.length); i++) {
    const x = ra[i] || 0;
    const y = rb[i] || 0;
    if (x !== y) return x > y ? a : b;
  }
  return ra.length >= rb.length ? a : b;
}

/**
 * 舊版本資料夾裡的發現降為參考(金鑰不降:公開的舊版一樣會外洩)
 * @param {Array} findings
 * @param {Array<{filename: string}>} files
 */
function applyOldVersionContext(findings, files) {
  const dirs = [...new Set(files.map(f => String(f.filename || '').split('/')[0]).filter(d => VERSION_DIR_RE.test(d)))];
  if (dirs.length < 2) return findings;
  const latest = dirs.reduce(newerVersion);
  const oldDirs = dirs.filter(d => d !== latest);
  return findings.map(f => {
    if (!f.filename || f.context || f.tier === 3) return f;
    if (!oldDirs.some(d => f.filename.indexOf(d + '/') === 0)) return f;
    if (SECRET_KINDS.has(f.kind)) return Object.assign({}, f, { context: 'old-version-secret' });
    return Object.assign({}, f, { tier: 3, originalTier: f.tier, context: 'old-version' });
  });
}

// ── 這個專案有沒有後端? ──
// 為什麼:純前端單機工具(資料只存在使用者自己的瀏覽器)沒有「別人的資料」,IDOR 規則只會製造噪音。(背景見 docs/CHANGELOG.md)
// 判斷刻意寬鬆:只要有一點像後端就算有,寧可照常報 IDOR,也不要把真的越權問題降級。
const BACKEND_SIGNALS = [
  /(?:require|from)\s*\(?\s*['"](?:express|koa|fastify|@hapi\/|next|nuxt|mongoose|prisma|@prisma\/|knex|pg|mysql2?|sqlite3|sequelize|typeorm|@supabase\/|firebase|firebase-admin|aws-sdk|@aws-sdk\/|mongodb|redis)/i,
  /\b(?:app|router|server)\s*\.\s*(?:get|post|put|patch|delete|use)\s*\(\s*['"`]/,
  /\b(?:createServer|listen)\s*\(\s*(?:process\.env\.PORT|\d{2,5})/,
  /\b(?:from|import)\s+(?:flask|django|fastapi|sqlalchemy|psycopg2)\b/i,
  /\bsupabase\s*\.\s*from\s*\(|\bcreateClient\s*\(|getFirestore\s*\(|firebase\.firestore\s*\(/,
  /\bfetch\s*\(\s*[`'"]https?:\/\//,
  // 任何「路徑字串」或樣板網址都算:fetch('/users/'+id) 這種相對於自家後端的呼叫最常見。
  // fetch(event.request)(Service Worker 快取)不算,那不是呼叫後端。
  /\bfetch\s*\(\s*[`'"]\//,
  /\bfetch\s*\(\s*`[^`]*\$\{/,
  /\$\.(?:get|post|ajax)\s*\(/,
  /\baxios\b|\bXMLHttpRequest\b|\$\.ajax\s*\(/,
  /\bfunctions\.https\.|\bonRequest\s*\(|\bexports\.handler\s*=/
];
const BACKEND_PATH_RE = /(^|\/)(api|server|backend|functions|routes|controllers|handlers)\/|\.(py|php|rb|go|java|cs)$/i;
const NO_BACKEND_KINDS = new Set(['possible_idor']);

/** @param {Array<{filename: string, code: string}>} files */
function projectHasBackend(files) {
  return files.some(f => {
    if (BACKEND_PATH_RE.test(f.filename || '')) return true;
    const language = languageFromFilename(f.filename) || guessMaskLanguage(f.code || '');
    // Infinity:字串全留(fetch 的網址本身就是字串),只抹掉註解
    const code = blankNonCode(f.code || '', buildCodeMask(f.code || '', { language }), Infinity);
    return BACKEND_SIGNALS.some(re => re.test(code));
  });
}

/** 沒有後端時,把「越權存取」類的發現降為參考並說明原因(已有其他情境註記的不動) */
function applyNoBackendContext(findings, hasBackend) {
  if (hasBackend) return findings;
  return findings.map(f => {
    if (!NO_BACKEND_KINDS.has(f.kind) || f.context || f.tier === 3) return f;
    return Object.assign({}, f, { tier: 3, originalTier: f.tier, context: 'no-backend' });
  });
}

/**
 * 專案裡只要有一處「整站生效」的 CSP(伺服器標頭／helmet／設定檔),其他網頁就不必各自再寫一份,
 * 所以把那些網頁的「完全沒有 CSP」降為參考。<meta> 寫的只管自己那一頁,不算數。
 * 為什麼:整個專案丟進來時,每個 .html 都跳「需要處理」會把真正要處理的事淹掉。(背景見 docs/CHANGELOG.md)
 */
function applySiteWideCspContext(findings, files) {
  if (!files.some(f => cspSiteWide(f.code))) return findings;
  return findings.map(f => {
    if (f.kind !== 'no_csp_html' || f.context || f.tier === 3) return f;
    return Object.assign({}, f, { tier: 3, originalTier: f.tier, context: 'site-csp' });
  });
}

/** 有檔名時,副檔名優先於內容猜測:.js 檔不檢查網頁 CSP、不提示 Python 特徵 */
function applyFilenameRules(findings, notices, filename, language) {
  if (!filename) return { findings, notices };
  const ext = (String(filename).toLowerCase().match(/\.([a-z0-9]+)$/) || [])[1] || '';
  const isConfig = FRAMEWORK_CONFIG_RE.test(filename);
  findings = findings.filter(f => {
    if (f.kind === 'no_csp_html') return language === 'html' || ['php', 'erb', 'hbs', 'ejs', 'njk'].indexOf(ext) >= 0;
    if (f.kind === 'no_csp_config') return isConfig;
    return true;
  });
  if (language === 'js' || language === 'html') notices = notices.filter(n => n.id !== 'language');
  return { findings, notices };
}

function joinNotices(notices) {
  return notices.length ? notices.map(n => n.text).join(' ') : null;
}

/**
 * 單檔案掃描
 * @param {string} code
 * @returns {{findings: Array, notices: Array, languageCaveat: string|null, astUsed: boolean}}
 */
function scanCode(code, opts) {
  code = code || '';
  const filename = opts && opts.filename;
  const language = languageFromFilename(filename) || guessMaskLanguage(code);
  const ctx = { byId: {}, astUsed: false, language, mask: buildCodeMask(code, { language }) };
  let findings = [];
  getSingleFileDetectors().forEach(d => {
    const out = d.run(code, ctx) || [];
    ctx.byId[d.id] = out;
    findings = findings.concat(out);
  });
  attachLocations(code, findings);
  findings = applyFileContext(findings, filename);
  const byName = applyFilenameRules(findings, buildNotices(code, ctx.astUsed), filename, language);
  const notices = byName.notices;
  return {
    findings: byName.findings,
    notices,
    languageCaveat: joinNotices(notices),
    astUsed: ctx.astUsed,
    language // 'js' | 'html' | 'python':語法分析只適用於 js/html
  };
}

/**
 * 多檔案掃描:逐檔案跑 scanCode,多於一個檔案時標上 filename,再跑跨檔案模組 M11,
 * 最後建立檔案地圖(M13):哪些檔案有在使用、檢查範圍。
 * @param {Array<{filename: string|null, code: string}>} files
 * @param {{coverage?: object|null}} [opts] - coverage:GitHub 匯入時的檢查範圍(assets/github-import.js)
 * @returns {{findings: Array, notices: Array, languageCaveat: string|null, astUsed: boolean, analysis: {full: number, simple: number, other: number}, projectMap: object|null}}
 */
function scanFiles(files, opts) {
  files = (files || []).map((f, idx) => ({ filename: f.filename || ('檔案' + (idx + 1)), code: f.code || '' }));
  const isMultiFile = files.length > 1;
  let findings = [];
  const notices = [];
  const analysis = { full: 0, simple: 0, other: 0 }; // 語法分析:完整／退回簡易比對／不適用(HTML、Python)

  files.forEach(f => {
    const r = scanCode(f.code, { filename: isMultiFile ? f.filename : (f.filename && !/^檔案\d+$/.test(f.filename) ? f.filename : null) });
    if (r.language === 'python' || r.language === 'html') analysis.other++; // 語法分析只適用 JS/TS
    else if (r.astUsed) analysis.full++;
    else analysis.simple++;
    findings = findings.concat(isMultiFile ? r.findings.map(x => Object.assign({}, x, { filename: f.filename })) : r.findings);
    r.notices.forEach(n => notices.push(isMultiFile ? Object.assign({}, n, { text: '【' + f.filename + '】' + n.text }) : n));
  });

  // 跨檔案遮罩比對:排除測試／範例檔,並把註解、說明文字、字串裡的範例程式碼換成空白,只比對真正的輸出路徑
  const m11Files = files
    .filter(f => !isTestLikePath(f.filename))
    .map(f => {
      const language = languageFromFilename(f.filename) || guessMaskLanguage(f.code);
      return { filename: f.filename, code: blankNonCode(f.code, buildCodeMask(f.code, { language })) };
    });
  findings = findings.concat(fieldMaskingConsistencyDetector(m11Files));

  let projectMap = null;
  if (isMultiFile) {
    findings = applyOldVersionContext(findings, files);
    findings = applyNoBackendContext(findings, projectHasBackend(files));
    findings = applySiteWideCspContext(findings, files);
    projectMap = buildProjectMap(files, opts && opts.coverage, isTestLikePath);
    findings = applyUsageContext(findings, projectMap);
    notices.unshift(...buildCoverageNotices(projectMap, files.length));
  }
  return { findings, notices, languageCaveat: joinNotices(notices), astUsed: analysis.simple === 0 && analysis.full > 0, analysis, projectMap };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { scanCode, scanFiles, projectHasBackend, applyNoBackendContext, applySiteWideCspContext, applyOldVersionContext, applyUsageContext, attachLocations, buildNotices, looksMinified, applyFileContext, isTestLikePath, looksLikePlaceholderSecret, getSingleFileDetectors, IDOR_AST_DEGRADED_NOTICE, MINIFIED_NOTICE };
}
