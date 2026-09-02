/**
 * 測試: M9 sql-injection-detector
 * 執行方式: node test/sql-injection-detector.test.js
 */

const { sqlInjectionDetector } = require('../src/modules/sql-injection-detector');
const { assertEqual, assertTrue, report } = require('./_test-helpers');

const results = [];

// --- True positive: 字串拼接 ---
results.push(assertTrue(
  '字串拼接組成SQL查詢應被偵測到',
  sqlInjectionDetector('db.query("SELECT * FROM users WHERE id=" + userId)').length > 0
));

results.push(assertTrue(
  '變數在前的字串拼接應被偵測到',
  sqlInjectionDetector('db.query(userId + " SELECT * FROM users")').length > 0
));

// --- True positive: 模板字面值插值 ---
results.push(assertTrue(
  '模板字面值插值組成SQL查詢應被偵測到',
  sqlInjectionDetector('db.query(`SELECT * FROM users WHERE id=${userId}`)').length > 0
));

// --- True positive: Python f-string ---
results.push(assertTrue(
  'Python f-string插值組成SQL查詢應被偵測到',
  sqlInjectionDetector('cursor.execute(f"SELECT * FROM users WHERE id={user_id}")').length > 0
));

results.push(assertTrue(
  'Python字串拼接組成SQL查詢應被偵測到',
  sqlInjectionDetector('cursor.execute("SELECT * FROM users WHERE id=" + str(user_id))').length > 0
));

// --- True negative: 參數化查詢不應誤判 ---
results.push(assertEqual(
  '參數化查詢(?佔位符)不應被偵測到',
  sqlInjectionDetector('db.query("SELECT * FROM users WHERE id=?", [userId])').length,
  0
));

results.push(assertEqual(
  'Python參數化查詢(%s佔位符)不應被偵測到',
  sqlInjectionDetector('cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))').length,
  0
));

results.push(assertEqual(
  'ORM方法呼叫不應被偵測到',
  sqlInjectionDetector('User.findOne({where: {id: userId}})').length,
  0
));

// --- tier/kind 正確性 ---
results.push((() => {
  const f = sqlInjectionDetector('db.query("SELECT * FROM users WHERE id=" + userId)')[0];
  return assertEqual('偵測到的結果 tier 應為 2(建議複查,非確診)', f.tier, 2);
})());

results.push((() => {
  const f = sqlInjectionDetector('db.query("SELECT * FROM users WHERE id=" + userId)')[0];
  return assertEqual('偵測到的結果 kind 應為 possible_sql_injection', f.kind, 'possible_sql_injection');
})());

results.push((() => {
  // 這是從真實案例(仿AI生成登入功能)實測中發現的漏判修正:
  // 修正前的正則因為SQL字串內部自己就含有單引號(username='...'),
  // 導致字串邊界比對提早截斷,反而漏判了最常見的字串拼接寫法。
  const code = "const query = \"SELECT * FROM users WHERE username='\" + username + \"' AND password='\" + password + \"'\";";
  return assertTrue('字串內含單引號的SQL拼接應被偵測到(修正前會漏判,見模組內修正紀錄)', sqlInjectionDetector(code).length > 0);
})());

results.push(assertEqual(
  'SQL關鍵字出現在一般文字說明裡(非真正SQL語句)不應被偵測到(誤判率評測fp-26發現的修正)',
  sqlInjectionDetector('const helpText = "Use SELECT statements carefully" + userNote;').length,
  0
));

results.push(assertTrue(
  '長欄位清單的SELECT語句拼接仍應正確偵測到(確認修正沒有引入新漏判)',
  sqlInjectionDetector('db.query("SELECT id, name, email, phone FROM users WHERE id=" + userId)').length > 0
));

results.push(assertTrue(
  'UPDATE ... SET拼接應正確偵測到(確認第二關鍵字涵蓋UPDATE語法)',
  sqlInjectionDetector('db.query("UPDATE users SET name=" + newName)').length > 0
));

// --- 空輸入 ---
results.push(assertEqual('空字串應回傳空陣列', sqlInjectionDetector('').length, 0));

report('M9 sql-injection-detector', results);
