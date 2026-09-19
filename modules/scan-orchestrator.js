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
    'key-detector', 'jwt-analyzer', 'hash-detector', 'secret-heuristics', 'csp-detector',
    'idor-detector', 'language-detector', 'finding-renderer', 'sql-injection-detector',
    'insecure-deserialize-detector', 'rate-limit-coverage-detector', 'field-masking-consistency-detector'
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
    { id: 'M3', run: code => hashDetector(code) },
    { id: 'M4', run: (code, ctx) => secretHeuristics(code, ctx.byId.M1.concat(ctx.byId.M2)) },
    { id: 'M5', run: code => cspDetector(code) },
    { id: 'M6', run: (code, ctx) => { const r = idorDetectorWithMeta(code); ctx.astUsed = r.astUsed; return r.findings; } },
    { id: 'M9', run: code => sqlInjectionDetector(code) },
    { id: 'M10', run: code => insecureDeserializeDetector(code) },
    { id: 'M12', run: code => rateLimitCoverageDetector(code) }
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

function joinNotices(notices) {
  return notices.length ? notices.map(n => n.text).join(' ') : null;
}

/**
 * 單檔案掃描
 * @param {string} code
 * @returns {{findings: Array, notices: Array, languageCaveat: string|null, astUsed: boolean}}
 */
function scanCode(code) {
  code = code || '';
  const ctx = { byId: {}, astUsed: false };
  let findings = [];
  getSingleFileDetectors().forEach(d => {
    const out = d.run(code, ctx) || [];
    ctx.byId[d.id] = out;
    findings = findings.concat(out);
  });
  attachLocations(code, findings);
  const notices = buildNotices(code, ctx.astUsed);
  return { findings, notices, languageCaveat: joinNotices(notices), astUsed: ctx.astUsed };
}

/**
 * 多檔案掃描:逐檔案跑 scanCode,多於一個檔案時標上 filename,再跑跨檔案模組 M11。
 * @param {Array<{filename: string|null, code: string}>} files
 * @returns {{findings: Array, notices: Array, languageCaveat: string|null, astUsed: boolean}}
 */
function scanFiles(files) {
  files = (files || []).map((f, idx) => ({ filename: f.filename || ('檔案' + (idx + 1)), code: f.code || '' }));
  const isMultiFile = files.length > 1;
  let findings = [];
  const notices = [];
  let astUsed = files.length > 0;

  files.forEach(f => {
    const r = scanCode(f.code);
    if (!r.astUsed) astUsed = false;
    findings = findings.concat(isMultiFile ? r.findings.map(x => Object.assign({}, x, { filename: f.filename })) : r.findings);
    r.notices.forEach(n => notices.push(isMultiFile ? Object.assign({}, n, { text: '【' + f.filename + '】' + n.text }) : n));
  });

  findings = findings.concat(fieldMaskingConsistencyDetector(files));
  return { findings, notices, languageCaveat: joinNotices(notices), astUsed };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { scanCode, scanFiles, attachLocations, buildNotices, looksMinified, getSingleFileDetectors, IDOR_AST_DEGRADED_NOTICE, MINIFIED_NOTICE };
}
