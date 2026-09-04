/**
 * eval-orchestrator.js — 供 eval/ 底下的驗證腳本使用的協調層。
 *
 * 這份檔案的邏輯與實際上線版本(demo_split/index.html 內的主邏輯 script)完全一致，
 * 只是把「呼叫 12 個模組、合併結果」這件事抽成獨立可 require 的函式，
 * 方便 run_eval.js / run_fp_eval.js 重新驗證 EVAL_REPORT.md 與
 * FALSE_POSITIVE_REPORT.md 裡的數字。
 *
 * 模組本體一律從 ../demo_split/modules 讀取，不依賴任何未公開的內部開發檔案，
 * 確保任何人 clone 這個 repo 下來都能直接執行、得到與報告一致的結果。
 */

const path = require('path');
const modulesDir = path.join(__dirname, '..', 'demo_split', 'modules');

const { keyDetector } = require(path.join(modulesDir, 'key-detector'));
const { jwtAnalyzer } = require(path.join(modulesDir, 'jwt-analyzer'));
const { hashDetector } = require(path.join(modulesDir, 'hash-detector'));
const { secretHeuristics } = require(path.join(modulesDir, 'secret-heuristics'));
const { cspDetector } = require(path.join(modulesDir, 'csp-detector'));
const { idorDetectorWithMeta, looksLikeJsxOrTypeScript } = require(path.join(modulesDir, 'idor-detector'));
const { languageDetector } = require(path.join(modulesDir, 'language-detector'));
const { findingRenderer } = require(path.join(modulesDir, 'finding-renderer'));
const { sqlInjectionDetector } = require(path.join(modulesDir, 'sql-injection-detector'));
const { insecureDeserializeDetector } = require(path.join(modulesDir, 'insecure-deserialize-detector'));
const { rateLimitCoverageDetector } = require(path.join(modulesDir, 'rate-limit-coverage-detector'));
const { fieldMaskingConsistencyDetector } = require(path.join(modulesDir, 'field-masking-consistency-detector'));

// M6(idor-detector)在 AST 解析失敗時(常見於含 TypeScript 型別標註的 .tsx)會
// 靜默退回涵蓋率較低的正則版。這則文字只在「程式碼看起來像 JSX/TS，但這次
// IDOR 分析沒有用到 AST 版」時附加在 languageCaveat 後面提示使用者。
const IDOR_AST_DEGRADED_NOTICE = '此外,本次程式碼含 JSX 或 TypeScript 型別語法特徵，但「疑似缺少擁有權驗證」這項偵測這次使用的是涵蓋範圍較窄的正則比對版本（無法辨識箭頭函式等寫法），不是更精確的語法樹分析版本——這通常是因為程式碼包含 interface、型別標註等 TypeScript 專屬語法，目前的分析能力不支援這部分語法。若這份程式碼裡有用到參數查詢資料的箭頭函式，建議額外自行確認。';

function appendIdorDegradedNoticeIfNeeded(code, astUsed, existingCaveat) {
  if (astUsed) return existingCaveat;
  if (!looksLikeJsxOrTypeScript(code)) return existingCaveat;
  return existingCaveat ? existingCaveat + ' ' + IDOR_AST_DEGRADED_NOTICE : IDOR_AST_DEGRADED_NOTICE;
}

/**
 * 執行完整掃描流程(單檔案)
 * @param {string} code - 使用者貼上的原始程式碼文字
 * @returns {{findings: Array, languageCaveat: string|null, html: string}}
 */
function runScan(code) {
  const m1 = keyDetector(code);
  const m2 = jwtAnalyzer(code);
  const m3 = hashDetector(code);
  const m4 = secretHeuristics(code, m1); // 唯一的模組相依:M4 讀 M1 結果去重複
  const m5 = cspDetector(code);
  const m6Meta = idorDetectorWithMeta(code);
  const m9 = sqlInjectionDetector(code);
  const m10 = insecureDeserializeDetector(code);
  const m12 = rateLimitCoverageDetector(code);

  const allFindings = [...m1, ...m2, ...m3, ...m4, ...m5, ...m6Meta.findings, ...m9, ...m10, ...m12];

  const baseCaveat = languageDetector(code);
  const languageCaveat = appendIdorDegradedNoticeIfNeeded(code, m6Meta.astUsed, baseCaveat);
  const html = findingRenderer(allFindings, languageCaveat);

  return { findings: allFindings, languageCaveat, html };
}

/**
 * 執行完整掃描流程(多檔案)，用於未來可能新增的 M11 專屬驗證腳本。
 * @param {Array<{filename: string|null, code: string}>} files
 * @returns {{findings: Array, languageCaveat: string|null, html: string}}
 */
function runMultiFileScan(files) {
  files = files || [];
  const isMultiFile = files.length > 1;

  let allFindings = [];
  const caveatParts = [];

  files.forEach((f, idx) => {
    const code = f.code || '';
    const filename = f.filename || `檔案${idx + 1}`;
    const result = runScan(code);

    const taggedFindings = isMultiFile
      ? result.findings.map(finding => Object.assign({}, finding, { filename }))
      : result.findings;
    allFindings = allFindings.concat(taggedFindings);

    if (result.languageCaveat) {
      caveatParts.push(isMultiFile ? `【${filename}】${result.languageCaveat}` : result.languageCaveat);
    }
  });

  const m11 = fieldMaskingConsistencyDetector(files);
  allFindings = allFindings.concat(m11);

  const languageCaveat = caveatParts.length > 0 ? caveatParts.join(' ') : null;
  const html = findingRenderer(allFindings, languageCaveat);
  return { findings: allFindings, languageCaveat, html };
}

module.exports = { runScan, runMultiFileScan, appendIdorDegradedNoticeIfNeeded, IDOR_AST_DEGRADED_NOTICE };
