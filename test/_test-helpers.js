/**
 * 測試共用小工具 — 刻意不依賴任何測試框架(jest/mocha/vitest),
 * 讓每個測試檔案可以用 `node test/xxx.test.js` 直接執行,
 * 方便交給不同 AI 個別開發時,不需要先搞定共用的測試環境設定。
 *
 * 若團隊已有慣用的測試框架,可以把這幾個函式替換成對應框架的 API,
 * 測試案例本身的邏輯(true positive/negative/邊界)不需要重寫。
 */

function assertEqual(description, actual, expected) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  return { description, pass, actual, expected };
}

function assertTrue(description, actual) {
  return { description, pass: actual === true, actual, expected: true };
}

function report(suiteName, results) {
  const failed = results.filter(r => !r.pass);
  console.log(`\n=== ${suiteName} ===`);
  results.forEach(r => {
    const mark = r.pass ? '✓' : '✗';
    console.log(`${mark} ${r.description}`);
    if (!r.pass) {
      console.log(`   期望: ${JSON.stringify(r.expected)}`);
      console.log(`   實際: ${JSON.stringify(r.actual)}`);
    }
  });
  console.log(`${results.length - failed.length}/${results.length} 通過`);
  if (failed.length > 0) {
    process.exitCode = 1;
  }
}

module.exports = { assertEqual, assertTrue, report };
