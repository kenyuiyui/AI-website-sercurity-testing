/**
 * scan-orchestrator.js — 唯一的協調層
 *
 * ⚠️ 這個檔案不建議單獨外包給只知道單一模組任務的 AI 修改,
 *    除非任務明確是「新增一個模組」或「調整模組執行順序」。
 *    見 README_START_HERE.md 第 5、6 節與 docs/CHANGE_MAP.md。
 *
 * 職責:依序呼叫 M1-M10,合併結果,交給 M8 渲染成 HTML。
 * 這是唯一知道全部 10 個模組存在的地方。
 */

const { keyDetector } = require('./modules/key-detector');
const { jwtAnalyzer } = require('./modules/jwt-analyzer');
const { hashDetector } = require('./modules/hash-detector');
const { secretHeuristics } = require('./modules/secret-heuristics');
const { cspDetector } = require('./modules/csp-detector');
const { idorDetector } = require('./modules/idor-detector');
const { languageDetector } = require('./modules/language-detector');
const { findingRenderer } = require('./modules/finding-renderer');
const { sqlInjectionDetector } = require('./modules/sql-injection-detector');
const { insecureDeserializeDetector } = require('./modules/insecure-deserialize-detector');

/**
 * 執行完整掃描流程
 * @param {string} code - 使用者貼上的原始程式碼文字
 * @returns {{findings: Array, languageCaveat: string|null, html: string}}
 */
function runScan(code) {
  const m1 = keyDetector(code);
  const m2 = jwtAnalyzer(code);
  const m3 = hashDetector(code);
  const m4 = secretHeuristics(code, m1); // 唯一的模組相依:M4 讀 M1 結果去重複
  const m5 = cspDetector(code);
  const m6 = idorDetector(code);
  const m9 = sqlInjectionDetector(code);
  const m10 = insecureDeserializeDetector(code);

  const allFindings = [...m1, ...m2, ...m3, ...m4, ...m5, ...m6, ...m9, ...m10];

  const languageCaveat = languageDetector(code);
  const html = findingRenderer(allFindings, languageCaveat);

  return { findings: allFindings, languageCaveat, html };
}

module.exports = { runScan };
