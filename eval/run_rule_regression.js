/**
 * run_rule_regression.js — 規則邊界回歸測試
 *
 * 針對 reference_cases/HANDOFF_rule_boundary_fixes.md 修正的四條規則(M3/M6/M9/M10),
 * 逐條驗證「該命中的有命中、不該命中的沒命中」,並確認 reference_cases/ 內所有案例
 * 都命中 EXPECTED。這裡的正負向小片段是手寫的規則邊界測試,不是真實蒐集樣本,
 * 所以放在這裡而不是 cases/(避免影響 run_scaled_eval.js 信賴區間的統計意義)。
 *
 * 執行方式(必須用全新的 Node 進程,不能事先 require('acorn'),才是測正則保底版):
 *   node run_rule_regression.js
 *   node -e "global.acorn=require('acorn');require('./run_rule_regression.js');"  (AST版)
 */

const fs = require('fs');
const path = require('path');
const { runScan } = require('./eval-orchestrator');
const { parseCaseFile } = require('./case-loader');

const kinds = code => runScan(code).findings.map(f => f.kind);
let failCount = 0;

function check(label, code, kind, expected) {
  const ok = kinds(code).includes(kind) === expected;
  if (!ok) failCount++;
  console.log(`${ok ? '✅' : '❌'} [${kind} ${expected ? '應命中' : '不應命中'}] ${label}`);
}

console.log('模式: ' + (typeof global.acorn !== 'undefined' ? 'AST版(acorn已載入)' : '正則保底版(acorn未載入)'));
console.log();

// M3 hash-detector — hashlib.new 兩段式
check('hashlib.new md5 + update(Password)', `hasher = hashlib.new('md5')\nhasher.update(Password)`, 'weak_hash', true);
check('hashlib.new sha1 + update(pwd)', `h = hashlib.new("sha1")\nh.update(pwd.encode())`, 'weak_hash', true);
check('hashlib.new md5 用於檔案校驗', `def get_checksum(file_data):\n    hasher = hashlib.new('md5')\n    hasher.update(file_data)\n    return hasher.hexdigest()`, 'weak_hash', false);
check('hashlib.new sha256 + password', `h = hashlib.new('sha256')\nh.update(password)`, 'weak_hash', false);

// M9 sql-injection-detector — Python % 格式化
check('SELECT 用 %s 格式化', `cursor.execute("SELECT * FROM users WHERE username = '%s'" % username)`, 'possible_sql_injection', true);
check('DELETE 用 %s 格式化', `cursor.execute("DELETE FROM users WHERE username = '%s'" % username)`, 'possible_sql_injection', true);
check('UPDATE 用 % tuple 格式化', `cur.execute("UPDATE t SET a = %s WHERE id = %s" % (a, b))`, 'possible_sql_injection', true);
check('一般字串 % 格式化', `print("%d items found" % count)`, 'possible_sql_injection', false);
check('日誌訊息提到 SELECT', `log.info("User %s logged in with SELECT permission" % username)`, 'possible_sql_injection', false);
check('參數化查詢 %s + list', `cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])`, 'possible_sql_injection', false);
check("參數化查詢 '%s' + tuple", `cursor.execute("SELECT * FROM users WHERE name = '%s'", (name,))`, 'possible_sql_injection', false);
check('LIKE 萬用字元常值', `cursor.execute("SELECT * FROM t WHERE name LIKE '%foo%'")`, 'possible_sql_injection', false);

// M10 insecure-deserialize-detector — Python exec()
check('exec 用 %s 格式化', `exec("import urllib%s as urllib" % module)`, 'insecure_python_exec', true);
check('exec 用 f-string', `exec(f"result = {expr}")`, 'insecure_python_exec', true);
check('exec 用 .format()', `exec("x = {}".format(user_code))`, 'insecure_python_exec', true);
check('exec 固定字串', `exec("print('hello')")`, 'insecure_python_exec', false);
check('Node execSync 固定字串', `execSync("ls -la")`, 'insecure_python_exec', false);
check('Node exec(變數) 仍歸 insecure_exec', `exec(cmd, cb)`, 'insecure_exec', true);
check('Node exec(變數) 不歸 insecure_python_exec', `exec(cmd, cb)`, 'insecure_python_exec', false);

// M6 idor-detector — Express 路由 callback
check('Express 箭頭 callback 無擁有權檢查', `app.get('/api/users/:userId/token', async (req, res) => {\n  const record = await db.tokens.findOne({ userId: req.params.userId });\n  res.json({ token: record.authToken });\n});`, 'possible_idor', true);
check('function(req, res) callback', `router.delete('/o/:id', function (req, res) {\n  db.orders.delete(req.params.id);\n  res.end();\n});`, 'possible_idor', true);
check('字串內的大括號不影響主體配對', `app.get('/x/:id', (req, res) => {\n  const msg = "}}}";\n  const o = db.items.find(req.params.id);\n  res.json(o);\n});`, 'possible_idor', true);
check('Express callback 有擁有權比較', `app.get('/o/:id', async (req, res) => {\n  const { id } = req.params;\n  const o = await db.orders.findOne({ id });\n  if (o.ownerId !== req.user.id) return res.status(403).end();\n  res.json(o);\n});`, 'possible_idor', false);
check('Express callback 沒有 DB 呼叫', `app.get('/health', (req, res) => {\n  res.json({ ok: true });\n});`, 'possible_idor', false);

// reference_cases/ 全部應命中 EXPECTED
console.log();
const refDir = path.join(__dirname, 'reference_cases');
fs.readdirSync(refDir).filter(f => f.endsWith('.txt')).forEach(f => {
  const c = parseCaseFile(fs.readFileSync(path.join(refDir, f), 'utf-8'), f);
  const got = kinds(c.code);
  const miss = c.expected.filter(k => !got.includes(k));
  if (miss.length) failCount++;
  console.log(`${miss.length ? '❌' : '✅'} [reference_cases] ${f} → ${got.join(', ') || '(無)'}${miss.length ? '  漏判: ' + miss.join(', ') : ''}`);
});

console.log();
console.log(failCount ? `❌ ${failCount} 項失敗` : '✅ 全部通過');
process.exitCode = failCount ? 1 : 0;
