/**
 * 測試: M1 key-detector
 * 規格見 docs/modules/MODULE_01_key-detector.md
 *
 * 執行方式: node test/key-detector.test.js
 * (骨架用最小手工斷言,無外部測試框架依賴,可依團隊習慣換成 jest/vitest)
 */

const { keyDetector, firebaseConfigDetector } = require('../src/modules/key-detector');
const { assertEqual, assertTrue, report } = require('./_test-helpers');

const results = [];

// --- True positive: 各種已知格式金鑰 ---
results.push(assertTrue(
  'OpenAI 金鑰應被偵測到',
  keyDetector('const key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456";').some(f => f.name === 'OpenAI API Key')
));

results.push(assertTrue(
  'Anthropic 金鑰應被偵測到',
  keyDetector('const key = "sk-ant-abcdefghijklmnopqrstuvwxyz123456";').some(f => f.name === 'Anthropic API Key')
));

results.push(assertTrue(
  'Google/Gemini 金鑰應被偵測到',
  keyDetector('const key = "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567";').some(f => f.name === 'Google / Gemini API Key')
));

results.push(assertTrue(
  'AWS Access Key 應被偵測到',
  keyDetector('const key = "AKIAABCDEFGHIJKLMNOP";').some(f => f.name === 'AWS Access Key ID')
));

// --- tier 與 kind 應正確 ---
results.push((() => {
  const f = keyDetector('const key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456";')[0];
  return assertEqual('偵測到的金鑰 tier 應為 1', f.tier, 1);
})());

results.push((() => {
  const f = keyDetector('const key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456";')[0];
  return assertEqual('偵測到的金鑰 kind 應為 plain_key', f.kind, 'plain_key');
})());

// --- evidence 必須遮罩,不可含完整明文金鑰 ---
results.push((() => {
  const fullKey = 'sk-proj-abcdefghijklmnopqrstuvwxyz123456';
  const f = keyDetector(`const key = "${fullKey}";`)[0];
  return assertTrue('evidence 不應包含完整明文金鑰', !f.evidence.includes(fullKey));
})());

// --- 邊界: 多種金鑰同時出現,應各自產生一筆 Finding ---
results.push((() => {
  const code = `
    const openai = "sk-proj-abcdefghijklmnopqrstuvwxyz123456";
    const aws = "AKIAABCDEFGHIJKLMNOP";
  `;
  const findings = keyDetector(code);
  return assertTrue('多種金鑰應各自產生 Finding', findings.length >= 2);
})());

// --- 邊界: 空輸入 ---
results.push(assertEqual('空字串應回傳空陣列', keyDetector('').length, 0));

// --- Firebase apiKey: 獨立處理,tier2提醒性質,不是明文金鑰外洩 ---
results.push((() => {
  const code = '{ "apiKey": "XyZ123abcDEF456ghiJKL789mnoPQR" }';
  const f = keyDetector(code).find(x => x.kind === 'firebase_config_exposed');
  return assertTrue('Firebase apiKey應被偵測到,且kind為firebase_config_exposed', !!f);
})());

results.push((() => {
  const code = '{ "apiKey": "XyZ123abcDEF456ghiJKL789mnoPQR" }';
  const f = keyDetector(code).find(x => x.kind === 'firebase_config_exposed');
  return assertEqual('Firebase apiKey應為tier2(提醒性質),不是tier1(明文金鑰外洩)', f.tier, 2);
})());

results.push((() => {
  const code = '{ "apiKey": "XyZ123abcDEF456ghiJKL789mnoPQR" }';
  const f = keyDetector(code).find(x => x.kind === 'firebase_config_exposed');
  return assertEqual('Firebase apiKey的category應為建議人工複查,不與真正機密金鑰共用「明文金鑰」分類', f.category, '建議人工複查');
})());

results.push((() => {
  // 驗證 firebaseConfigDetector 獨立函式本身也能正常運作(供未來需要單獨呼叫時使用)
  const code = '{ "apiKey": "XyZ123abcDEF456ghiJKL789mnoPQR" }';
  return assertTrue('firebaseConfigDetector獨立函式應正確運作', firebaseConfigDetector(code).length === 1);
})());



// --- visualData.vendor: 供M8查詢對應的權限知識庫 ---
results.push((() => {
  const f = keyDetector('const key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456";')[0];
  return assertEqual('OpenAI金鑰的visualData.vendor應為openai', f.visualData.vendor, 'openai');
})());

results.push((() => {
  const f = keyDetector('const key = "sk-ant-abcdefghijklmnopqrstuvwxyz123456";')[0];
  return assertEqual('Anthropic金鑰的visualData.vendor應為anthropic', f.visualData.vendor, 'anthropic');
})());

results.push((() => {
  const f = keyDetector('const key = "AKIAABCDEFGHIJKLMNOP";')[0];
  return assertEqual('AWS金鑰的visualData.vendor應為aws', f.visualData.vendor, 'aws');
})());


report('M1 key-detector', results);
