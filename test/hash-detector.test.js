/**
 * 測試: M3 hash-detector
 * 規格見 docs/modules/MODULE_03_hash-detector.md
 * 執行方式: node test/hash-detector.test.js
 */

const { hashDetector } = require('../src/modules/hash-detector');
const { assertEqual, assertTrue, report } = require('./_test-helpers');

const results = [];

// --- True positive ---
results.push(assertTrue(
  'md5(password) 應被偵測到',
  hashDetector('const h = md5(password);').some(f => f.kind === 'weak_hash')
));

results.push(assertTrue(
  'sha1(pwd) 應被偵測到',
  hashDetector('const h = sha1(pwd);').some(f => f.kind === 'weak_hash')
));

results.push(assertTrue(
  '大小寫不敏感: MD5(PASSWORD) 應被偵測到',
  hashDetector('const h = MD5(PASSWORD);').some(f => f.kind === 'weak_hash')
));

// --- True negative ---
results.push(assertEqual(
  'md5(username) 不應被偵測到',
  hashDetector('const h = md5(username);').length,
  0
));

results.push(assertEqual(
  'bcrypt(password) 不應被偵測到',
  hashDetector('const h = bcrypt(password);').length,
  0
));

// --- 已知限制(記錄用,非必須修): md5(passwordHash) 目前會誤判 ---
// 規格文件已說明此為已知限制,不擅自修改判斷邏輯範圍。
// 這裡先記錄現況,不強制斷言通過:
(() => {
  const r = hashDetector('const h = md5(passwordHash);');
  console.log('[已知限制記錄] md5(passwordHash) 現況偵測筆數:', r.length, '(預期未來可能需要調整,暫不視為失敗)');
})();

// --- 空輸入 ---
results.push(assertEqual('空字串應回傳空陣列', hashDetector('').length, 0));

report('M3 hash-detector', results);
