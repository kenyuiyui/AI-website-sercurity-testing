/**
 * M11 — field-masking-consistency-detector
 * 詳細規格見 docs/modules/MODULE_11_field-masking-consistency-detector.md
 *
 * 職責:偵測「同一份敏感資料，在程式碼裡有多個輸出／回傳路徑，但只有部分
 *       路徑做了遮罩或過濾處理」的模式(欄位遮罩不一致)
 * 輸入: files (Array<{filename: string, code: string}>) — 多檔案輸入,
 *       跟 M1-M10、M12 不同,這是本專案第一個多檔案分析模組
 * 輸出: Finding[]
 *
 * ⚠️ 這是本專案目前所有模組中,先天限制最大、誤判空間最大的一個。
 * 只能做欄位名稱與呼叫模式的啟發式相似度比對,無法確認語意上是否真的
 * 是同一份資料、無法驗證遮罩函式是否真的正確實作。永遠固定為 tier 2,
 * 且呈現文字必須明確說明這只是「線索」不是「結論」。
 *
 * ⚠️ 修補紀錄(2026):原本這個模組雖然邏輯完整,但完全沒被打包進demo HTML,
 * UI也沒有多檔案輸入介面可以觸發它。這次補上多檔案模式後,一併打包進來。
 */

// 輸出點樣式:Response.json(...)/res.json(...)/json(...) 呼叫
const OUTPUT_PATTERN = /\b(?:return\s+)?(?:Response\.json|res\.json|json)\s*\(\s*([^;]{0,200})/g;

// 判斷命中位置是否為函式宣告本身(而非呼叫),需要排除。
const FUNCTION_DECL_CHECK_WINDOW = 15;

// 在輸出點文字片段裡,抽取所有可能的函式呼叫樣式
const CALL_REFERENCE_PATTERN = /\.map\s*\(\s*(\w+)\s*\)|\b(\w+)\s*\(\s*[\w,\s.]*\)/g;

// 常見多人連線/多使用者系統場景下的敏感欄位命名慣例(啟發式清單,非窮舉)
const SENSITIVE_FIELD_HINTS = [
  'state', 'board', 'hand', 'cards', 'hidden', 'private',
  'token', 'password', 'secret', 'role', 'permission',
  'balance', 'email', 'phone', 'address'
];

// 遮罩/過濾函式的命名慣例(啟發式,只看函式名稱長相,不驗證實作是否正確)
const MASKING_FUNCTION_NAME_HINTS = /\b\w*(mask|sanitiz|redact|filter|private|hide|obscure)\w*\s*\(/i;

/**
 * 用大括號配對找出函式體邊界
 * @param {string} code
 * @param {number} funcStartIndex
 * @returns {string|null}
 */
function extractFunctionBodyM11(code, funcStartIndex) {
  const openBraceIdx = code.indexOf('{', funcStartIndex);
  if (openBraceIdx === -1) return null;
  let depth = 0;
  for (let i = openBraceIdx; i < code.length; i++) {
    if (code[i] === '{') depth++;
    else if (code[i] === '}') {
      depth--;
      if (depth === 0) return code.slice(openBraceIdx, i + 1);
    }
  }
  return null;
}

/**
 * 在給定的程式碼裡找出指定名稱的函式定義,回傳函式體。找不到回傳 null。
 * @param {string} code
 * @param {string} funcName
 * @returns {string|null}
 */
function findFunctionDefinitionBody(code, funcName) {
  const escapedName = funcName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(`(?:export\\s+)?(?:async\\s+)?function\\s+${escapedName}\\s*\\([^)]*\\)\\s*\\{`);
  const m = pattern.exec(code);
  if (!m) return null;
  return extractFunctionBodyM11(code, m.index);
}

/**
 * 從一段程式碼裡找出所有輸出點,排除函式宣告本身造成的雜訊。
 * @param {string} code
 * @param {string} filename
 * @returns {Array<{filename:string, snippet:string}>}
 */
function findOutputPoints(code, filename) {
  const outputs = [];
  const re = new RegExp(OUTPUT_PATTERN.source, OUTPUT_PATTERN.flags);
  let m;
  while ((m = re.exec(code)) !== null) {
    const windowStart = Math.max(0, m.index - FUNCTION_DECL_CHECK_WINDOW);
    const window = code.slice(windowStart, m.index + 5);
    const isDeclaration = /function\s+\w+\s*\($/.test(window);
    if (isDeclaration) continue;

    outputs.push({ filename, snippet: m[0].slice(0, 200) });
  }
  return outputs;
}

/**
 * 從一個輸出點片段裡,抽取所有可能的函式呼叫名稱(不判斷是否為「單純呼叫」)。
 * @param {string} snippet
 * @returns {string[]}
 */
function extractCalledFunctionNames(snippet) {
  const re = new RegExp(CALL_REFERENCE_PATTERN.source, CALL_REFERENCE_PATTERN.flags);
  const names = [];
  let m;
  while ((m = re.exec(snippet)) !== null) {
    const name = m[1] || m[2];
    if (name) names.push(name);
  }
  return [...new Set(names)];
}

/**
 * 建立「分析範圍文字」:輸出點片段本身 + 所有能找到定義的函式體(只追一層)。
 * @param {{filename:string, snippet:string}} output
 * @param {Array<{filename:string, code:string}>} files
 * @returns {{combinedText: string, tracedContext: string|null}}
 */
function buildAnalysisScope(output, files) {
  let combinedText = output.snippet;
  let tracedContext = null;

  const calledNames = extractCalledFunctionNames(output.snippet);
  calledNames.forEach(name => {
    for (const f of files) {
      const body = findFunctionDefinitionBody(f.code, name);
      if (body) {
        combinedText += '\n' + body;
        if (!tracedContext) tracedContext = name;
        break;
      }
    }
  });

  return { combinedText, tracedContext };
}

/**
 * @param {string} text
 * @returns {string[]}
 */
function detectSensitiveFields(text) {
  return SENSITIVE_FIELD_HINTS.filter(field => new RegExp(`\\b${field}\\b`, 'i').test(text));
}

/**
 * @param {string} text
 * @returns {boolean}
 */
function looksMasked(text) {
  return MASKING_FUNCTION_NAME_HINTS.test(text);
}

/**
 * @param {Array<{filename: string, code: string}>} files
 * @returns {Array<{tier:number, category:string, name:string, kind:string, evidence:string, visualData:object}>}
 */
function fieldMaskingConsistencyDetector(files) {
  files = files || [];
  if (files.length < 2) return [];

  let allOutputs = [];
  files.forEach(f => {
    allOutputs = allOutputs.concat(findOutputPoints(f.code || '', f.filename));
  });
  if (allOutputs.length === 0) return [];

  const analyzedOutputs = allOutputs.map(output => {
    const { combinedText, tracedContext } = buildAnalysisScope(output, files);
    return {
      filename: output.filename,
      context: tracedContext,
      fields: detectSensitiveFields(combinedText),
      masked: looksMasked(combinedText)
    };
  }).filter(o => o.fields.length > 0);

  const fieldGroups = {};
  analyzedOutputs.forEach(o => {
    o.fields.forEach(field => {
      if (!fieldGroups[field]) fieldGroups[field] = { masked: [], unmasked: [] };
      const location = { file: o.filename, context: o.context };
      if (o.masked) fieldGroups[field].masked.push(location);
      else fieldGroups[field].unmasked.push(location);
    });
  });

  const findings = [];
  Object.keys(fieldGroups).forEach(field => {
    const group = fieldGroups[field];
    if (group.masked.length === 0 || group.unmasked.length === 0) return;

    const dedupe = (locations) => {
      const seen = new Set();
      return locations.filter(loc => {
        const key = `${loc.file}::${loc.context}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
    };
    const maskedLocations = dedupe(group.masked);
    const unmaskedLocations = dedupe(group.unmasked);

    const maskedDesc = maskedLocations.map(l => `${l.file}${l.context ? ' 的 ' + l.context : ''}`).join('、');
    const unmaskedDesc = unmaskedLocations.map(l => `${l.file}${l.context ? ' 的 ' + l.context : ''}`).join('、');

    findings.push({
      tier: 2,
      category: '建議人工複查',
      name: '疑似欄位遮罩處理不一致',
      kind: 'inconsistent_field_masking',
      evidence: `偵測到「${field}」欄位在多個輸出路徑中被回傳，其中部分路徑（如 ${maskedDesc}）呼叫了看起來像過濾/遮罩的函式，但另一部分路徑（如 ${unmaskedDesc}）未偵測到類似處理。這只是命名與呼叫模式的相似度比對，不代表確診有資料外洩，請人工確認這兩處是否真的處理同一種敏感資料、以及是否都需要相同的遮罩邏輯。`,
      visualData: {
        fieldHint: field,
        maskedLocations,
        unmaskedLocations
      }
    });
  });

  return findings;
}

// ── 環境相容匯出:Node.js(require)與瀏覽器(<script src>)共用同一份檔案 ──
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    fieldMaskingConsistencyDetector,
    findOutputPoints,
    extractCalledFunctionNames,
    findFunctionDefinitionBody,
    detectSensitiveFields,
    looksMasked,
    OUTPUT_PATTERN,
    CALL_REFERENCE_PATTERN,
    SENSITIVE_FIELD_HINTS,
    MASKING_FUNCTION_NAME_HINTS
  };
}
