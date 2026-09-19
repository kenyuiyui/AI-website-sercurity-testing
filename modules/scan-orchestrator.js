/**
 * scan-orchestrator — 掃描流程的唯一來源
 *
 * 職責:依序呼叫各偵測模組、合併 Finding[]、補上行號、組出語言提示。
 * 瀏覽器(assets/app.js)與 Node 驗證腳本(eval/eval-orchestrator.js)共用這一份,
 * 新增偵測模組時只需要改 SINGLE_FILE_DETECTORS 與 index.html 的 <script> 清單。
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

const IDOR_AST_DEGRADED_NOTICE = '此外，本次程式碼含 JSX 或 TypeScript 型別語法特徵，但「疑似缺少擁有權驗證」這項偵測這次使用的是涵蓋範圍較窄的正則比對版本（無法辨識箭頭函式等寫法），不是更精確的語法樹分析版本——這通常是因為程式碼包含 interface、型別標註等 TypeScript 專屬語法，目前的分析能力不支援這部分語法。若這份程式碼裡有用到參數查詢資料的箭頭函式，建議額外自行確認。';

/**
 * 單檔案偵測器清單(順序即結果顯示順序)。
 * 每個偵測器: (code, ctx) => Finding[];ctx.previous 為先前偵測器的結果,
 * 供 M4 secretHeuristics 對 M1 去重複使用。
 * 新增偵測器:在這裡加一行,並在 index.html 的 <script src="modules/..."> 清單加上檔案。
 */
function getSingleFileDetectors() {
  return [
    { id: 'M1', run: code => keyDetector(code) },
    { id: 'M2', run: code => jwtAnalyzer(code) },
    { id: 'M3', run: code => hashDetector(code) },
    { id: 'M4', run: (code, ctx) => secretHeuristics(code, ctx.byId.M1) },
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
      const nl = code.indexOf('\n', start);
      len = (nl < 0 ? code.length : nl) - start;
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

function buildLanguageCaveat(code, astUsed) {
  const base = languageDetector(code);
  if (astUsed || !looksLikeJsxOrTypeScript(code)) return base;
  return base ? base + ' ' + IDOR_AST_DEGRADED_NOTICE : IDOR_AST_DEGRADED_NOTICE;
}

/**
 * 單檔案掃描
 * @param {string} code
 * @returns {{findings: Array, languageCaveat: string|null, astUsed: boolean}}
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
  return { findings, languageCaveat: buildLanguageCaveat(code, ctx.astUsed), astUsed: ctx.astUsed };
}

/**
 * 多檔案掃描:逐檔案跑 scanCode,多於一個檔案時標上 filename,再跑跨檔案模組 M11。
 * @param {Array<{filename: string|null, code: string}>} files
 * @returns {{findings: Array, languageCaveat: string|null}}
 */
function scanFiles(files) {
  files = (files || []).map((f, idx) => ({ filename: f.filename || ('檔案' + (idx + 1)), code: f.code || '' }));
  const isMultiFile = files.length > 1;
  let findings = [];
  const caveats = [];

  files.forEach(f => {
    const r = scanCode(f.code);
    findings = findings.concat(isMultiFile ? r.findings.map(x => Object.assign({}, x, { filename: f.filename })) : r.findings);
    if (r.languageCaveat) caveats.push(isMultiFile ? '【' + f.filename + '】' + r.languageCaveat : r.languageCaveat);
  });

  findings = findings.concat(fieldMaskingConsistencyDetector(files));
  return { findings, languageCaveat: caveats.length ? caveats.join(' ') : null };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { scanCode, scanFiles, attachLocations, buildLanguageCaveat, getSingleFileDetectors, IDOR_AST_DEGRADED_NOTICE };
}
