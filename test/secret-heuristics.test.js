/**
 * 測試: M4 secret-heuristics
 * 規格見 docs/modules/MODULE_04_secret-heuristics.md
 * 執行方式: node test/secret-heuristics.test.js
 *
 * ⚠️ 這個模組有相依:需要 M1 的輸出(existingFindings)來測試去重複邏輯。
 *    不需要真的呼叫 M1,直接手工造假資料即可,見下方 fakeM1Output。
 */

const { secretHeuristics, scanEnvFormatLines } = require('../src/modules/secret-heuristics');
const { assertEqual, assertTrue, report } = require('./_test-helpers');

const results = [];

// --- 4.1 自訂密鑰變數: True positive ---
results.push(assertTrue(
  '自訂密鑰變數應被偵測到',
  secretHeuristics('const mySecretToken = "abc123xyz789";', []).some(f => f.kind === 'custom_secret_var')
));

// --- 4.1 佔位字樣應被排除 ---
results.push(assertEqual(
  '佔位字樣 "your-token-here" 不應被偵測到',
  secretHeuristics('const secretToken = "your-token-here";', []).filter(f => f.kind === 'custom_secret_var').length,
  0
));

// --- 4.1 去重複邏輯: 已被 M1 抓過的字串不應在 M4 重複列出 ---
results.push((() => {
  const secretVal = 'abc123xyz789secretvalue';
  const code = `const apiSecretKey = "${secretVal}";`;
  const fakeM1Output = [
    { tier: 1, category: '明文金鑰', name: 'Fake Key', kind: 'plain_key', evidence: secretVal.slice(0,4)+'…mask [MASKED]' }
  ];
  // 模擬 M1 已抓過這段字串開頭(去重複邏輯用前8字元比對,見規格文件)
  fakeM1Output[0].evidence = secretVal.slice(0, 8); // 直接把前8字元放進 evidence 讓比對命中
  const findings = secretHeuristics(code, fakeM1Output);
  return assertEqual('已被 M1 抓過的字串,M4 不應重複列出', findings.filter(f => f.kind === 'custom_secret_var').length, 0);
})());

// --- 4.2 內部端點 URL ---
results.push(assertTrue(
  'Slack Webhook URL 應被偵測到',
  secretHeuristics('const url = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX";', [])
    .some(f => f.kind === 'endpoint_url')
));

// --- 4.3 環境變數明文 fallback ---
results.push(assertTrue(
  'process.env fallback 應被偵測到',
  secretHeuristics('const key = process.env.API_KEY || "actualSecretValue123";', [])
    .some(f => f.kind === 'env_fallback')
));

results.push(assertEqual(
  'fallback 為 localhost 應被排除(視為合理預設值而非密鑰)',
  secretHeuristics('const url = process.env.DB_HOST || "localhost";', [])
    .filter(f => f.kind === 'env_fallback').length,
  0
));

results.push(assertEqual(
  'fallback 為純數字(如連接埠號5432)不應被偵測到(誤判率評測fp-8發現的修正,密鑰不可能是純數字)',
  secretHeuristics('const dbPort = process.env.DB_PORT || "5432";', [])
    .filter(f => f.kind === 'env_fallback').length,
  0
));

// --- 4.4 .env 格式內容: True positive ---
results.push(assertTrue(
  '.env 格式含明文密鑰應被偵測到',
  scanEnvFormatLines('API_SECRET_KEY=realvalue1234567890').some(f => f.kind === 'env_file_secret')
));

// --- 4.4 佔位字樣應被排除 ---
results.push(assertEqual(
  '.env 格式佔位字樣不應被偵測到',
  scanEnvFormatLines('API_SECRET_KEY=your-secret-here').filter(f => f.kind === 'env_file_secret').length,
  0
));

// --- 4.4 過短的值應被排除 ---
results.push(assertEqual(
  '.env 格式值過短(<8字元)不應被偵測到',
  scanEnvFormatLines('API_TOKEN=short').filter(f => f.kind === 'env_file_secret').length,
  0
));

// --- 4.4 非密鑰命名的變數不應被偵測 ---
results.push(assertEqual(
  '.env 格式非密鑰命名變數不應被偵測到',
  scanEnvFormatLines('APP_NAME=my-cool-application').length,
  0
));

// --- 4.3/4.4 不應對同一行重複回報(程式碼賦值 vs .env 字面值) ---
results.push(assertEqual(
  '程式碼形式的 fallback 不應被 .env 逐行規則誤判',
  scanEnvFormatLines('const key = process.env.API_KEY || "value123";').length,
  0
));

// --- 空輸入 ---
results.push(assertEqual('空字串應回傳空陣列', secretHeuristics('', []).length, 0));

report('M4 secret-heuristics', results);
