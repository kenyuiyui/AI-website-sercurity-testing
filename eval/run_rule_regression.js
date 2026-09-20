/**
 * run_rule_regression.js — 規則邊界回歸測試
 *
 * 針對 reference_cases/HANDOFF_rule_boundary_fixes.md 修正的四條規則(M3/M6/M9/M10),
 * 逐條驗證「該命中的有命中、不該命中的沒命中」,並確認 reference_cases/ 內所有案例
 * 都命中 EXPECTED。這裡的正負向小片段是手寫的規則邊界測試,不是真實蒐集樣本,
 * 所以放在這裡而不是 cases/(避免影響 run_scaled_eval.js 信賴區間的統計意義)。
 *
 * 執行方式(必須用全新的 Node 進程,不能事先 require('./load-ast'),才是測正則保底版):
 *   node run_rule_regression.js
 *   node -e "require('./load-ast');require('./run_rule_regression.js');"  (AST版)
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

// M1/M4 — Firebase 設定不當成外洩;同一個值不重複回報
const FB_KEY = 'AIzaSy' + 'A1b2C3d4E5f6G7h8I9j0KlMnOpQrStUvW';
const fbConfig = `const firebaseConfig = {\n  apiKey: '${FB_KEY}',\n  authDomain: 'demo.firebaseapp.com',\n  projectId: 'demo'\n};`;
check('Firebase 設定物件 → firebase_config_exposed', fbConfig, 'firebase_config_exposed', true);
check('Firebase 設定物件 → 不報 Gemini 外洩', fbConfig, 'plain_key', false);
check('Firebase 設定物件 → 不重複報自訂密鑰', fbConfig, 'custom_secret_var', false);
check('Firebase JSON 設定', `{"apiKey": "${FB_KEY}", "projectId": "demo"}`, 'firebase_config_exposed', true);
check('GEMINI_API_KEY 變數 → 仍是明文金鑰', `const GEMINI_API_KEY = '${FB_KEY}';`, 'plain_key', true);
check('Gemini SDK 的 apiKey(無 Firebase 特徵) → 仍是明文金鑰', `new GoogleGenerativeAI({ apiKey: '${FB_KEY}' })`, 'plain_key', true);
check('Gemini SDK 的 apiKey → 不當成 Firebase', `new GoogleGenerativeAI({ apiKey: '${FB_KEY}' })`, 'firebase_config_exposed', false);
check('OPENAI_API_KEY 已報明文金鑰 → 不重複報自訂密鑰', `const OPENAI_API_KEY = 'sk-proj-abcdefghijklmnopqrstuvwxyz1234567890';`, 'custom_secret_var', false);
check('一般密碼變數仍報自訂密鑰', `const adminPassword = "hunter2hunter2";`, 'custom_secret_var', true);

// 本次檢查的限制提示(notices)
const { scanCode } = require('../modules/scan-orchestrator');
function checkNotice(label, code, id, expected) {
  const ok = scanCode(code).notices.some(n => n.id === id) === expected;
  if (!ok) failCount++;
  console.log(`${ok ? '✅' : '❌'} [notice:${id} ${expected ? '應出現' : '不應出現'}] ${label}`);
}
checkNotice('壓縮過的 bundle', '!function(){' + 'var a=1;b.c(d);'.repeat(200) + '}();', 'minified', true);
checkNotice('一般多行程式碼', 'function f(x) {\n  return x + 1;\n}\n'.repeat(200), 'minified', false);
checkNotice('普通 HTML 不出現權限檢查降級提示', '<!doctype html><html><head><title>x</title></head><body><div>hi</div></body></html>', 'idor-degraded', false);
checkNotice('無資料庫查詢的 TSX 不出現降級提示', 'interface P { a: string }\nexport const A = ({a}: P) => <div>{a}</div>;', 'idor-degraded', false);
checkNotice('有查詢且 AST 無法解析的 TSX 出現降級提示', "interface P { orderId: string }\nexport const A = ({orderId}: P) => { supabase.from('o').select('*').eq('id', orderId); return <div/>; };", 'idor-degraded', true);

// 壓縮後金鑰檢查仍有效
check('壓縮 bundle 內的 OpenAI 金鑰', '!function(){var t="sk-proj-abcdefghijklmnopqrstuvwxyz1234567890";' + 'a.b(c);'.repeat(300) + '}();', 'plain_key', true);

// ── 第三輪:整檔案輸入下的誤判(來自掃描本專案自己的結果) ──
// 方法呼叫不是危險函式
check('正則的 re.exec(code) 不是執行指令', `const re = /a/g;\nwhile ((m = re.exec(code)) !== null) {}`, 'insecure_exec', false);
check('Playwright 的 page.$eval() 不是 eval', `const t = await page.$eval('#x', el => el.textContent);`, 'insecure_eval', false);
check('page.$$eval() 不是 eval', `const t = await page.$$eval('li', els => els.length);`, 'insecure_eval', false);
check('child_process.exec(cmd) 仍是執行指令', `child_process.exec(cmd, cb);`, 'insecure_exec', true);
check('require("child_process").exec(cmd) 仍是執行指令', `require("child_process").exec(cmd);`, 'insecure_exec', true);
check('window.eval(x) 仍是 eval', `window.eval(userInput);`, 'insecure_eval', true);
// 字串、註解、正則裡「提到」不算
check('註解裡提到 eval()', `// 不要用 eval() 處理使用者輸入\nconst a = JSON.parse(s);`, 'insecure_eval', false);
check('說明字串裡提到 eval()', `const guide = { plain: '程式碼裡呼叫了 eval()，風險很高' };`, 'insecure_eval', false);
check('規則定義的正則裡有 eval\\(', `const RULE = { re: /\\beval\\s*\\(/g };`, 'insecure_eval', false);
check('樣板字串裡的範例程式碼', "const sample = `function h(password) { return md5(password); }`;", 'weak_hash', false);
check('樣板字串 ${} 內的真呼叫仍會抓', "const s = `result: ${eval(userInput)}`;", 'insecure_eval', true);
check('字串後面的真呼叫仍會抓', `const a = "eval(x)"; eval(y);`, 'insecure_eval', true);
check('HTML onclick 屬性裡的 eval 仍會抓', `<!DOCTYPE html><html><body><button onclick="eval(location.hash.slice(1))">x</button></body></html>`, 'insecure_eval', true);
check('HTML <script> 內的 eval 仍會抓', `<!DOCTYPE html><html><body><script>eval(location.hash)</script></body></html>`, 'insecure_eval', true);
check('Python 註解裡的 pickle.loads', `import pickle\n# 不要用 pickle.loads(data)\nobj = json.loads(data)`, 'insecure_pickle', false);
check('Python docstring 裡的 yaml.load', `def f(data):\n    """不要用 yaml.load(data)"""\n    return yaml.safe_load(data)`, 'insecure_yaml_load', false);
check('Python 真的 pickle.loads', `import pickle\nobj = pickle.loads(request.data)`, 'insecure_pickle', true);
// 讀取環境變數的 Python 程式碼不是 .env 內容;拆開的 JWT 片段不是 LINE 權杖
check('SECRET_KEY = environ["SECRET_KEY"] 不是 .env 明文', `SECRET_KEY = environ["SECRET_KEY"]`, 'env_file_secret', false);
check('拆開的 JWT payload 不是 LINE 權杖', `const parts = ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', 'eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InByb2plY3RyZWYiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjIwMTU1NzYwMDB9'];`, 'line_bot_token_suspected', false);

// 第四輪:整專案掃描實例(公開的 Vue + Supabase 專案)裡出現的誤判。字串一律拆開組合,避免本檔案在自我掃描時被當成外洩。
const B64_BLOB = 'QUJD'.repeat(30); // 120 字元的 base64,長度足以觸發 LINE 權杖比對
check('data URI 內的 base64 內容不是 LINE 權杖', `<link rel="preload" as="image" href="data:image/avif;base64,${B64_BLOB}">`, 'line_bot_token_suspected', false);
check('一般變數裡的長 base64 仍會提示可能是 LINE 權杖', `const t = "${B64_BLOB}";`, 'line_bot_token_suspected', true);
check('網址預設值不是備用密碼', `const baseURL = process.env.VITE_SEO_URL || 'https://example.com'`, 'env_fallback', false);
check('名稱像密鑰的備用值仍會報', `const s = process.env.JWT_SECRET || 'hunter2-hardcoded'`, 'env_fallback', true);
check('帶帳密的網址備用值仍會報', `const u = process.env.API_BASE || 'https://admin:hunter2@' + 'api.internal.test/v1'`, 'env_fallback', true);
const SB_PUBLISHABLE = 'sb_publishable_' + 'Ab3dEf6hIj9kLm2nOp5qRs8t';
check('.env 的 Supabase publishable 金鑰 → 歸為公開金鑰', `VITE_SUPABASE_ANON_KEY=${SB_PUBLISHABLE}`, 'supabase_anon', true);
check('.env 的 Supabase publishable 金鑰 → 不當成 .env 密鑰外洩', `VITE_SUPABASE_ANON_KEY=${SB_PUBLISHABLE}`, 'env_file_secret', false);
const SB_SECRET = 'sb_secret_' + 'Zx9Cv8Bn7Mq6Wr5Ty4Ui3Op2A';
check('Supabase secret 金鑰 → 高風險（同 service_role）', `const admin = createClient(url, '${SB_SECRET}')`, 'supabase_service_role', true);
check('.env 的 Supabase secret 金鑰 → 高風險', `SUPABASE_SERVICE_KEY=${SB_SECRET}`, 'supabase_service_role', true);
check('.env 的 Supabase secret 金鑰 → 不重複報 .env 密鑰', `SUPABASE_SERVICE_KEY=${SB_SECRET}`, 'env_file_secret', false);
check('.env 的管理者密碼仍報 .env 密鑰', `VITE_ADMIN_PASSWORD=Sup3rS3cretPw`, 'env_file_secret', true);
check('.env 的 OpenAI 金鑰 → 只報明文金鑰', 'OPENAI_API_KEY=sk-proj-' + 'Xa7Qm2Lp9Rt4Vn8Kc3Zw6Hy1Bd5Fg0Js', 'plain_key', true);
check('.env 的 OpenAI 金鑰 → 不重複報 .env 密鑰', 'OPENAI_API_KEY=sk-proj-' + 'Xa7Qm2Lp9Rt4Vn8Kc3Zw6Hy1Bd5Fg0Js', 'env_file_secret', false);

// 第六輪:單檔式網頁(所有程式碼都寫在一個 index.html)造成的誤判
check('組 HTML 的模板字串不是 SQL 拼接', 'const h = `<span onblur="Card.update(${id}, v)">${esc(t)}</span>`;', 'possible_sql_injection', false);
check('真正的 SELECT 模板字串仍會報', 'const q = `SELECT * FROM users WHERE id = ${id}`;', 'possible_sql_injection', true);
check('真正的 UPDATE 模板字串仍會報', 'const q = `UPDATE users SET name = \'${n}\'`;', 'possible_sql_injection', true);
check('一般 f-string 不是 SQL', 'msg = f"update {n} rows"', 'possible_sql_injection', false);
check('SQL f-string 仍會報', 'q = f"SELECT * FROM t WHERE id={x}"', 'possible_sql_injection', true);
check('字串裡的範例程式碼不算缺少擁有權檢查',
  "const demo = ['export async function deleteProperty(propertyId) {', '  const r = await db.from(\"p\").delete().eq(\"id\", propertyId);', '  return r;', '}'].join('\\n');",
  'possible_idor', false);
check('真正的函式仍會報缺少擁有權檢查',
  'export async function deleteProperty(propertyId) {\n  const r = await db.from("p").delete().eq("id", propertyId);\n  return r;\n}',
  'possible_idor', true);

// 第八輪:CSP 的內容品質、以及「這個專案有沒有後端」
const cspMeta = v => `<!DOCTYPE html><html><head><meta http-equiv="Content-Security-Policy" content="${v}"></head><body></body></html>`;
check('CSP 有 unsafe-inline 要提醒', cspMeta("default-src 'self'; script-src 'self' 'unsafe-inline';"), 'csp_weak', true);
check('CSP 有 unsafe-eval 要提醒', cspMeta("script-src 'self' 'unsafe-eval';"), 'csp_weak', true);
check('script-src 用萬用字元要提醒', cspMeta('script-src *;'), 'csp_weak', true);
check('嚴格的 CSP 不提醒', cspMeta("default-src 'none'; script-src 'self';"), 'csp_weak', false);
check('只有 style-src 放寬不提醒', cspMeta("script-src 'self'; style-src 'self' 'unsafe-inline';"), 'csp_weak', false);
check('有 CSP 就不再報「沒有 CSP」', cspMeta("script-src 'self' 'unsafe-inline';"), 'no_csp_html', false);

// 第十四輪:CSP 內容品質。有 nonce／雜湊時 'unsafe-inline' 會被瀏覽器忽略、有 'strict-dynamic' 時白名單與協定會被忽略,
// 這些常見的相容寫法不能被冤枉;反過來,瀏覽器默默略過的錯誤與可被借用的白名單要抓得到。
const CSP_KINDS = ['csp_weak', 'csp_allowlist_bypass', 'csp_missing_directive', 'csp_syntax', 'csp_not_enforced'];
function checkCspClean(label, code) {
  const got = kinds(code).filter(k => CSP_KINDS.includes(k));
  const ok = got.length === 0;
  if (!ok) failCount++;
  console.log(`${ok ? '✅' : '❌'} [CSP 應完全乾淨] ${label}${ok ? '' : ' → ' + got.join(', ')}`);
}
const NONCE_OK = "'nonce-${nonce}'";
const STRICT = `script-src ${NONCE_OK} 'strict-dynamic'; object-src 'none'; base-uri 'none'`;
// 放行了什麼(csp_weak)
check('script-src 放行 data: 要提醒', cspMeta("script-src 'self' data:; object-src 'none'"), 'csp_weak', true);
check('script-src 放行整個 https: 要提醒', cspMeta("script-src 'self' https:; object-src 'none'"), 'csp_weak', true);
check('script-src 放行 http:// 來源要提醒', cspMeta("script-src 'self' http://cdn.example.com; object-src 'none'"), 'csp_weak', true);
check('script-src 放行 *.com 這類頂層網域要提醒', cspMeta("script-src 'self' *.com; object-src 'none'"), 'csp_weak', true);
check('http://localhost 不算「可被竄改」', cspMeta("script-src 'self' http://localhost:3000; object-src 'none'"), 'csp_weak', false);
check('有 nonce 時 unsafe-inline 會被忽略,不報', cspMeta("script-src 'self' 'nonce-${nonce}' 'unsafe-inline'; object-src 'none'; base-uri 'none'"), 'csp_weak', false);
check('有雜湊時 unsafe-inline 會被忽略,不報', cspMeta("script-src 'self' 'sha256-" + 'A'.repeat(43) + "=' 'unsafe-inline'; object-src 'none'"), 'csp_weak', false);
check("有 strict-dynamic 時 https: 會被忽略,不報", cspMeta(`script-src ${NONCE_OK} 'strict-dynamic' https:; object-src 'none'; base-uri 'none'`), 'csp_weak', false);
check('寫死的 nonce 要提醒', cspMeta("script-src 'nonce-abc123def456ghi'; object-src 'none'; base-uri 'none'"), 'csp_weak', true);
check('執行時才填入的 nonce 不算寫死', cspMeta(STRICT), 'csp_weak', false);
check('名字就叫 NONCE 的佔位字不算寫死', cspMeta("script-src 'nonce-__NONCE__'; object-src 'none'; base-uri 'none'"), 'csp_weak', false);
check('有 style-src 卻完全沒管腳本要提醒', cspMeta("style-src 'self'; img-src 'self'"), 'csp_weak', true);
check('只用 frame-ancestors 的 CSP 不用求它管腳本', "res.setHeader('Content-Security-Policy', \"frame-ancestors 'none'\");", 'csp_weak', false);
check('object-src 放行 * 要提醒', cspMeta("default-src 'self'; object-src *"), 'csp_weak', true);
check('default-src 放行 https: 連帶讓 object-src 沒管住,要提醒', cspMeta("default-src 'self' https:; script-src 'self'"), 'csp_weak', true);
// 白名單放了可被借用的網域(csp_allowlist_bypass)
check('放行 cdn.jsdelivr.net 要提醒', cspMeta("script-src 'self' https://cdn.jsdelivr.net; object-src 'none'"), 'csp_allowlist_bypass', true);
check('放行 ajax.googleapis.com 要提醒', cspMeta("script-src 'self' https://ajax.googleapis.com; object-src 'none'"), 'csp_allowlist_bypass', true);
check('放行 *.github.io 要提醒', cspMeta("script-src 'self' https://*.github.io; object-src 'none'"), 'csp_allowlist_bypass', true);
check('放行自己的 github.io 網址不報', cspMeta("script-src 'self' https://someone.github.io; object-src 'none'"), 'csp_allowlist_bypass', false);
check('自己的網域不報', cspMeta("script-src 'self' https://static.example.com; object-src 'none'"), 'csp_allowlist_bypass', false);
check('公共 CDN 只出現在 img-src 不報', cspMeta("script-src 'self'; img-src https://cdn.jsdelivr.net; object-src 'none'"), 'csp_allowlist_bypass', false);
check("有 strict-dynamic 時白名單會被忽略,不報", cspMeta(`script-src ${NONCE_OK} 'strict-dynamic' https://cdn.jsdelivr.net; object-src 'none'; base-uri 'none'`), 'csp_allowlist_bypass', false);
// 缺指令(csp_missing_directive)
check('沒有 object-src 也沒有 default-src 要提醒', cspMeta("script-src 'self'"), 'csp_missing_directive', true);
check('有 default-src 就涵蓋 object-src,不報', cspMeta("default-src 'self'; script-src 'self'"), 'csp_missing_directive', false);
check('有 object-src none 不報', cspMeta("script-src 'self'; object-src 'none'"), 'csp_missing_directive', false);
check('用 nonce 卻沒 base-uri 要提醒', cspMeta(`script-src ${NONCE_OK} 'strict-dynamic'; object-src 'none'`), 'csp_missing_directive', true);
check('用 nonce 且有 base-uri 不報', cspMeta(STRICT), 'csp_missing_directive', false);
check('只用雜湊(沒有 strict-dynamic)不需要 base-uri', cspMeta("script-src 'sha256-" + 'A'.repeat(43) + "='; object-src 'none'"), 'csp_missing_directive', false);
// 寫法錯誤(csp_syntax)
check('指令拼錯要提醒', cspMeta("default-src 'self'; scripts-src 'self'"), 'csp_syntax', true);
check('漏分號要提醒', cspMeta("script-src 'self' object-src 'none'"), 'csp_syntax', true);
check("'self' 漏單引號要提醒", cspMeta("default-src self"), 'csp_syntax', true);
check('關鍵字打錯要提醒', cspMeta("default-src 'self'; script-src 'unsafe-inlines'"), 'csp_syntax', true);
check('指令重複要提醒', cspMeta("default-src 'self'; default-src 'none'"), 'csp_syntax', true);
check('雜湊長度不對要提醒', cspMeta("default-src 'none'; script-src 'sha256-abc'"), 'csp_syntax', true);
check('指令後面多冒號要提醒', cspMeta("default-src 'self'; script-src: 'self'"), 'csp_syntax', true);
check("strict-dynamic 沒有 nonce／雜湊要提醒", cspMeta("default-src 'none'; script-src 'self' 'strict-dynamic'"), 'csp_syntax', true);
check('已淘汰的指令列為提示', cspMeta("default-src 'self'; reflected-xss block"), 'csp_syntax', true);
check('寫得正確的 CSP 不報語法問題', cspMeta("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src https://api.example.com; base-uri 'none'; form-action 'none'; object-src 'none'"), 'csp_syntax', false);
// 設了但沒生效(csp_not_enforced)
check('meta 裡的 frame-ancestors 會被忽略,要提醒', cspMeta("default-src 'self'; frame-ancestors 'none'"), 'csp_not_enforced', true);
check('標頭裡的 frame-ancestors 是正常寫法,不報', "res.setHeader('Content-Security-Policy', \"default-src 'self'; frame-ancestors 'none'\");", 'csp_not_enforced', false);
check('CSP 標籤放在腳本後面要提醒', '<!DOCTYPE html><html><head><script src="a.js"></script><meta http-equiv="Content-Security-Policy" content="default-src \'self\'"></head></html>', 'csp_not_enforced', true);
check('CSP 標籤放在腳本前面不報', '<!DOCTYPE html><html><head><meta http-equiv="Content-Security-Policy" content="default-src \'self\'"><script src="a.js"></script></head></html>', 'csp_not_enforced', false);
check('只有 Report-Only 標頭要提示', "res.setHeader('Content-Security-Policy-Report-Only', \"default-src 'self'; script-src 'self'\");", 'csp_not_enforced', true);
check('meta 的 Report-Only 瀏覽器不支援,要提醒', '<!DOCTYPE html><html><head><meta http-equiv="Content-Security-Policy-Report-Only" content="default-src \'self\'"></head></html>', 'csp_not_enforced', true);
check('正式 CSP 之外另有 Report-Only 試營運,不報', "res.setHeader('Content-Security-Policy', \"default-src 'self'\");\nres.setHeader('Content-Security-Policy-Report-Only', \"default-src 'none'\");", 'csp_not_enforced', false);
check('有 CSP 就算 Report-Only 也不再報「沒有 CSP」', '<!DOCTYPE html><html><head><meta http-equiv="Content-Security-Policy-Report-Only" content="default-src \'self\'"></head></html>', 'no_csp_html', false);
// 各種送出方式都要讀得到
const WEAK = "script-src 'self' 'unsafe-inline'; object-src 'none'";
check('讀得到 setHeader(單引號名稱、雙引號值)', `res.setHeader('Content-Security-Policy', "${WEAK}");`, 'csp_weak', true);
check('讀得到 JSON 標頭設定', `{"headers":[{"key":"Content-Security-Policy","value":"${WEAK}"}]}`, 'csp_weak', true);
check('讀得到 nginx add_header', `add_header Content-Security-Policy "${WEAK}" always;`, 'csp_weak', true);
check('讀得到 Apache Header set', `Header always set Content-Security-Policy "${WEAK}"`, 'csp_weak', true);
check('讀得到沒有引號的原始標頭(_headers 檔)', `/*\n  Content-Security-Policy: ${WEAK}\n`, 'csp_weak', true);
check('讀得到屬性順序相反的 meta', `<!DOCTYPE html><html><head><meta content="${WEAK}" http-equiv="Content-Security-Policy"></head></html>`, 'csp_weak', true);
check('讀得到 JSX 的 httpEquiv', `<meta httpEquiv="Content-Security-Policy" content="${WEAK}" />`, 'csp_weak', true);
check('讀得到先存進變數的 CSP 字串', "const csp = `default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'`;\nheaders: [{ key: 'Content-Security-Policy', value: csp }]", 'csp_weak', true);
check('HTML 註解裡的範例 CSP 不算', `<!DOCTYPE html><html><head><!-- <meta http-equiv="Content-Security-Policy" content="${WEAK}"> --><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'"></head></html>`, 'csp_weak', false);
check('說明文字裡的一句話不會被當成 CSP', "const tip = 'script-src 是控制腳本來源的指令，不要寫 unsafe-inline';", 'csp_weak', false);
// Express helmet
check("helmet 的 contentSecurityPolicy: false 要提醒", 'app.use(helmet({ contentSecurityPolicy: false }));', 'csp_weak', true);
check("helmet 的 scriptSrc 放行 unsafe-inline 要提醒", `app.use(helmet.contentSecurityPolicy({ directives: { scriptSrc: ["'self'", "'unsafe-inline'"] } }));`, 'csp_weak', true);
check('helmet 預設會補齊沒寫的指令,不報缺少', `app.use(helmet.contentSecurityPolicy({ directives: { scriptSrc: ["'self'"] } }));`, 'csp_missing_directive', false);
check('helmet useDefaults: false 時沒寫 object-src 要提醒', `app.use(helmet.contentSecurityPolicy({ useDefaults: false, directives: { scriptSrc: ["'self'"] } }));`, 'csp_missing_directive', true);
// 寫得好的 CSP 一律乾淨
checkCspClean('本站自己的 CSP', cspMeta("default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src https://api.github.com https://raw.githubusercontent.com; base-uri 'none'; form-action 'none'; object-src 'none'"));
checkCspClean('nonce + strict-dynamic 的向下相容寫法', cspMeta(`script-src ${NONCE_OK} 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'`));
checkCspClean('Next.js 風格:樣板字串 + nonce', "const cspHeader = `\n  default-src 'self';\n  script-src 'self' 'nonce-${nonce}' 'strict-dynamic';\n  style-src 'self' 'unsafe-inline';\n  object-src 'none';\n  base-uri 'self';\n  frame-ancestors 'none';\n  upgrade-insecure-requests;\n`;\nheaders: [{ key: 'Content-Security-Policy', value: cspHeader.replace(/\\s{2,}/g, ' ').trim() }]");
checkCspClean('上線後只加一條 frame-ancestors 防嵌入', "add_header Content-Security-Policy \"frame-ancestors 'self'\" always;");

// ── 檔案地圖(project-map)、檢查範圍、沒用到檔案的降級 ──
const { scanFiles } = require('../modules/scan-orchestrator');
const { findingRenderer } = require('../modules/finding-renderer');
function checkMap(label, ok) {
  if (!ok) failCount++;
  console.log(`${ok ? '✅' : '❌'} [project-map] ${label}`);
}
const OLD_KEY = 'sk-proj-' + 'Xa7Qm2Lp9Rt4Vn8Kc3Zw6Hy1Bd5Fg0Js';
const VITE_PROJECT = [
  { filename: 'index.html', code: '<!DOCTYPE html><html><head></head><body><script type="module" src="/src/main.ts"></script></body></html>' },
  { filename: 'src/main.ts', code: "import { createApp } from 'vue'\nimport App from './App.vue'\ncreateApp(App).mount('#app')" },
  { filename: 'src/App.vue', code: "<script setup lang=\"ts\">\nimport Nav from '@/components/Nav.vue'\nconst Home = () => import('./views/Home.vue')\n</script>" },
  { filename: 'src/components/Nav.vue', code: '<template><nav/></template>' },
  { filename: 'src/views/Home.vue', code: '<template><div/></template>' },
  { filename: 'src/components/Old.vue', code: '<script setup>\nconst x = eval(location.hash)\n</script>' },
  { filename: 'src/old/key.js', code: `export const OPENAI_KEY = "${OLD_KEY}";` },
  { filename: 'draft.html', code: '<!DOCTYPE html><html><head></head><body></body></html>' },
  { filename: 'vite.config.ts', code: "import path from 'node:path'\nexport default { resolve: { alias: { '@': path.resolve(__dirname, './src') } } }" }
];
const vr = scanFiles(VITE_PROJECT);
const st = (r, p) => (r.projectMap.nodes.find(n => n.path === p) || {}).status;
checkMap('入口追得到的檔案標為使用中(含 @ 別名、動態 import)', ['index.html', 'src/main.ts', 'src/App.vue', 'src/components/Nav.vue', 'src/views/Home.vue'].every(p => st(vr, p) === 'used'));
checkMap('追不到的檔案標為疑似沒用到', st(vr, 'src/components/Old.vue') === 'unused' && st(vr, 'src/old/key.js') === 'unused');
checkMap('沒被首頁連到的網頁標為「另一個網頁」而不是沒用到', st(vr, 'draft.html') === 'page');
checkMap('建置設定檔不算沒用到', st(vr, 'vite.config.ts') === 'build');
const evalF = vr.findings.find(f => f.kind === 'insecure_eval');
checkMap('沒用到檔案裡的一般問題降為參考', !!evalF && evalF.tier === 3 && evalF.context === 'unused' && evalF.originalTier === 1);
const keyF = vr.findings.find(f => f.kind === 'plain_key');
checkMap('沒用到檔案裡的金鑰維持原層級', !!keyF && keyF.tier === 1 && keyF.context === 'unused-secret');
const dyn = scanFiles(VITE_PROJECT.concat([{ filename: 'src/routes.ts', code: "export const pages = import.meta.glob('./views/*.vue')" }, { filename: 'src/main2.ts', code: "import './routes'" }]).map(f => f.filename === 'src/main.ts' ? { filename: f.filename, code: f.code + "\nimport './routes'" } : f));
checkMap('有 import.meta.glob 時不確定 → 不降級', dyn.projectMap.certain === false && dyn.findings.find(f => f.kind === 'insecure_eval').tier === 1);
const cov = { total: 12, skippedLimit: ['src/x.ts'], skippedLarge: [], failed: [], notChecked: { sql: 2 } };
const withCov = scanFiles(VITE_PROJECT, { coverage: cov });
checkMap('有檔案沒檢查到 → 不降級、提示沒檢查到的數量', withCov.projectMap.certain === false && withCov.findings.find(f => f.kind === 'insecure_eval').tier === 1 && withCov.notices.some(n => n.id === 'coverage' && n.level === 'warn' && n.text.includes('12 個程式碼檔')));
checkMap('列出不檢查的檔案類型(.sql)', withCov.notices.some(n => n.id === 'not-checked' && n.text.includes('.sql 2 個')));
const pasted = scanFiles([{ filename: null, code: 'const a = 1;' }, { filename: null, code: 'const b = 2;' }]);
checkMap('貼上的多段程式碼(沒有 index.html)不出現檔案地圖', pasted.projectMap.analyzed === false && !pasted.notices.some(n => n.id === 'usage') && !/rs-map/.test(findingRenderer(pasted.findings, pasted.languageCaveat, pasted.notices, pasted.projectMap)));
const vrHtml = findingRenderer(vr.findings, vr.languageCaveat, vr.notices, vr.projectMap);
checkMap('畫面顯示檔案地圖與疑似沒用到的數量', /pm-tree/.test(vrHtml) && /2 個疑似沒在使用/.test(vrHtml));
checkMap('畫面附上每種狀態的意思', /rs-legend/.test(vrHtml) && vrHtml.includes('疑似沒用到'));
checkMap('畫面附上入口的引用關係樹', /引用關係/.test(vrHtml) && /src\/main\.ts/.test(vrHtml));
checkMap('引用關係依層數上色(第一層 pm-l0、第二層 pm-l1…)', /pm-gnode pm-l0/.test(vrHtml) && /pm-gnode pm-l1/.test(vrHtml) && /pm-gnode pm-l2/.test(vrHtml));
checkMap('檔案樹的狀態用有顏色的標籤而不是純文字', /pm-chip pm-used/.test(vrHtml) && /pm-chip pm-unused/.test(vrHtml));

// 引用關係與分類:第六輪使用者回報「無法判斷太多」後補上的檢查
const { projectGraphText } = require('../modules/finding-renderer');
const graph = projectGraphText(vr.projectMap);
checkMap('引用關係樹從入口往下展開', /^index\.html$/m.test(graph) && /\n {2}src\/main\.ts/.test(graph) && /\n {4}src\/App\.vue/.test(graph));

// 註解裡寫 import(…) 不該讓整個專案變成「無法判斷」(本專案自己就踩過這個雷)
const COMMENT_PROJECT = VITE_PROJECT.filter(f => f.filename !== 'src/App.vue').concat([
  { filename: 'src/App.vue', code: "<script setup lang=\"ts\">\n// 說明:這裡不用 import(變數),也沒有 import.meta.glob\nimport Nav from '@/components/Nav.vue'\nimport Home from './views/Home.vue'\n</script>" }
]);
const cm = scanFiles(COMMENT_PROJECT);
checkMap('註解裡提到 import( 不算動態載入', cm.projectMap.certain === true);

// Node 工具鏈:require 也算引用,被測試腳本用到的檔案不是「沒用到」
const NODE_PROJECT = [
  { filename: 'index.html', code: '<!DOCTYPE html><html><body><script src="app.js"></script></body></html>' },
  { filename: 'app.js', code: "const sw = './sw.js';\nnavigator.serviceWorker.register(sw ? './sw.js' : '');" },
  { filename: 'sw.js', code: "self.addEventListener('install', () => {});" },
  { filename: 'scripts/run-check.js', code: "const helper = require('./helper');\nhelper();" },
  { filename: 'scripts/helper.js', code: 'module.exports = function () {};' },
  { filename: 'lonely.js', code: 'export const unusedThing = 1;' }
];
const np = scanFiles(NODE_PROJECT);
const nst = p => (np.projectMap.nodes.find(n => n.path === p) || {}).status;
checkMap('字串路徑載入(sw.js)也算有在使用', nst('sw.js') === 'used');
checkMap('被建置腳本 require 的檔案標成工具而不是沒用到', nst('scripts/helper.js') === 'build');
checkMap('真的沒人用到的檔案才標為疑似沒用到', nst('lonely.js') === 'unused' && np.projectMap.certain === true);

// 版本資料夾各放一份網站(v1/ v2/ …)時,不能把其中一個舊版當成「主要入口」、其他當成「另一個網頁」
const MULTI_SITE = [
  { filename: 'v1.0.0/index.html', code: '<!DOCTYPE html><html><body><script src="js/old.js"></script></body></html>' },
  { filename: 'v1.0.0/js/old.js', code: 'const a = 1;' },
  { filename: 'v3/index.html', code: '<!DOCTYPE html><html><body><script src="/js/new.js"></script></body></html>' },
  { filename: 'v3/js/new.js', code: 'const b = 2;' }
];
const ms = scanFiles(MULTI_SITE);
const mst = p => (ms.projectMap.nodes.find(n => n.path === p) || {}).status;
checkMap('沒有最上層 index.html 時不硬選主要入口', ms.projectMap.primary === '' && ms.projectMap.counts.page === 0);
checkMap('每個版本資料夾各自算一個網站(含各自的絕對路徑)', mst('v1.0.0/index.html') === 'used' && mst('v3/index.html') === 'used' && mst('v3/js/new.js') === 'used' && mst('v1.0.0/js/old.js') === 'used');

// 第九輪:XSS(把資料直接組成 HTML)
const XSS_BASE = 'const d = JSON.parse(localStorage.getItem("x") || "{}");\n';
check('網址內容直接進 innerHTML', 'box.innerHTML = location.hash;', 'xss_from_url', true);
check('輸入框內容直接組成 HTML', 'box.innerHTML = "<p>" + document.getElementById("q").value + "</p>";', 'xss_from_url', true);
check('資料欄位未跳脫組成 HTML', XSS_BASE + 'box.innerHTML = `<div>${d.name}</div>`;', 'html_from_data', true);
check('有跳脫就不報', XSS_BASE + 'box.innerHTML = `<div>${escapeHTML(d.name)}</div>`;', 'html_from_data', false);
check('清空 innerHTML 不報', XSS_BASE + 'box.innerHTML = "";', 'html_from_data', false);
check('寫死的字串不報', XSS_BASE + 'box.innerHTML = `<div class="x">固定文字</div>`;', 'html_from_data', false);
check('class 名稱這種非文字欄位不報', XSS_BASE + 'box.innerHTML = `<div class="${mode}">x</div>`;', 'html_from_data', false);
check('已經組好的 HTML 片段不報', XSS_BASE + 'box.innerHTML = `<table>${rowsHtml}</table>`;', 'html_from_data', false);
check('textContent 不是 HTML 注入點', XSS_BASE + 'box.textContent = d.name;', 'html_from_data', false);
check('說明文字裡的範例不算', XSS_BASE + '// 例如 box.innerHTML = `<b>${user.name}</b>`\nconst a = 1;', 'html_from_data', false);
check('沒有外部資料的純靜態頁不報', 'const t = "標題";\nbox.innerHTML = `<h1>${t}</h1>`;', 'html_from_data', false);
// 先把資料組成字串、再塞進 HTML(真實案例改寫:先把課程名稱組成字串,再塞進提示區塊)
check('先組成變數再塞進 HTML 也要追到',
  'const list = JSON.parse(localStorage.getItem("c"));\nconst conflictText = list.map(x => `${x.name}`).join("；");\nbanner.innerHTML = `<div>${conflictText}</div>`;',
  'html_from_data', true);
// 真實回報:跳脫後才指派給變數的寫法被誤判成最高層級(const task = escapeHtml(it.task))
const ESCAPED_VAR = 'const data = JSON.parse(localStorage.getItem("d") || "{}");\n' +
  'list.innerHTML = data.items.map(it => {\n' +
  '  const task = Utils.escapeHtml(it.task || "");\n' +
  '  const owner = it.owner ? `<span>${Utils.escapeHtml(it.owner)}</span>` : "";\n' +
  '  return `<li>${task}${owner}</li>`;\n' +
  '}).join("");';
check('跳脫後才指派給變數,不算 XSS', ESCAPED_VAR, 'html_from_data', false);
check('跳脫後才指派給變數,更不該算成網址來源', ESCAPED_VAR, 'xss_from_url', false);
// 讀到的是一整個程式區塊時,區塊裡的變數宣告不是「插進 HTML 的值」
check('區塊裡的變數宣告不算插值',
  'const rows = JSON.parse(localStorage.getItem("r") || "[]");\n' +
  'out.innerHTML = rows.map(row => {\n' +
  '  const label = row.label || "（未命名）";\n' +
  '  let html = `<div>`;\n' +
  '  html += `<b>${Utils.escapeHtml(label)}</b>`;\n' +
  '  html += `</div>`;\n' +
  '  return html;\n' +
  '}).join("");',
  'html_from_data', false);
check('組成變數時有跳脫就不報',
  'const list = JSON.parse(localStorage.getItem("c"));\nconst conflictText = list.map(x => `${escapeHTML(x.name)}`).join("；");\nbanner.innerHTML = `<div>${conflictText}</div>`;',
  'html_from_data', false);

// 純前端單機工具:沒有後端就沒有「別人的資料」,IDOR 只會製造噪音
const { projectHasBackend } = require('../modules/scan-orchestrator');
const IDOR_CODE = 'function getItem(itemId) {\n  const item = db.find(itemId);\n  return item;\n}';
const FRONT_ONLY = [
  { filename: 'index.html', code: '<!DOCTYPE html><html><body><script src="app.js"></script></body></html>' },
  { filename: 'app.js', code: 'const db = JSON.parse(localStorage.getItem("data") || "[]");\n' + IDOR_CODE }
];
const fo = scanFiles(FRONT_ONLY);
const foIdor = fo.findings.find(f => f.kind === 'possible_idor');
checkMap('純前端專案的越權提醒降為參考', !projectHasBackend(FRONT_ONLY) && !!foIdor && foIdor.tier === 3 && foIdor.context === 'no-backend' && foIdor.originalTier === 2);

const WITH_BACKEND = FRONT_ONLY.concat([{ filename: 'lib/db.js', code: "const supabase = createClient(url, key);\nexport const q = () => supabase.from('t').select('*');" }]);
const wb = scanFiles(WITH_BACKEND);
const wbIdor = wb.findings.find(f => f.kind === 'possible_idor');
checkMap('有後端(Supabase)時越權提醒維持原層級', projectHasBackend(WITH_BACKEND) && !!wbIdor && wbIdor.tier === 2 && !wbIdor.context);

const WITH_API = FRONT_ONLY.concat([{ filename: 'api/users.js', code: 'module.exports = (req, res) => res.json({});' }]);
checkMap('有 api/ 資料夾就算有後端', projectHasBackend(WITH_API));
checkMap('註解裡提到 axios 不算有後端', !projectHasBackend([{ filename: 'a.js', code: '// 之後可能改用 axios 呼叫後端\nconst x = 1;' }]));
checkMap('相對路徑的 fetch 也算有後端', projectHasBackend([{ filename: 'a.js', code: 'fetch("/users/" + id).then(r => r.json());' }]));
checkMap('Service Worker 的快取 fetch 不算有後端', !projectHasBackend([{ filename: 'sw.js', code: 'self.addEventListener("fetch", e => e.respondWith(fetch(e.request)));' }]));

// 舊版本資料夾:一個 repo 放好幾版網站時,舊版的問題不該蓋過現役版本
const VERSIONED = [
  { filename: 'v1.0.0/index.html', code: '<!DOCTYPE html><html><body><script src="js/a.js"></script></body></html>' },
  { filename: 'v1.0.0/js/a.js', code: 'const d = JSON.parse(localStorage.getItem("x"));\nbox.innerHTML = `<b>${d.name}</b>`;' },
  { filename: 'v2.0/index.html', code: '<!DOCTYPE html><html><head><meta http-equiv="Content-Security-Policy" content="default-src \'self\'"></head><body><script src="js/b.js"></script></body></html>' },
  { filename: 'v2.0/js/b.js', code: 'const d = JSON.parse(localStorage.getItem("x"));\nbox.innerHTML = `<b>${escapeHTML(d.name)}</b>`;' }
];
const ver = scanFiles(VERSIONED);
const oldF = ver.findings.find(f => f.filename === 'v1.0.0/js/a.js' && f.kind === 'html_from_data');
checkMap('舊版本資料夾的發現降為參考並說明原因', !!oldF && oldF.tier === 3 && oldF.context === 'old-version' && oldF.originalTier === 2);
checkMap('最新版本資料夾不受影響', !ver.findings.some(f => f.filename.indexOf('v2.0/') === 0 && f.context === 'old-version'));
const verHtml = findingRenderer(ver.findings, ver.languageCaveat, ver.notices, ver.projectMap);
checkMap('參考的摘要寫出可以略過的原因', /舊版本資料夾/.test(verHtml));

// 檔案情境(需要檔名,直接用 scanCode 檢查層級)
// 看起來像真的金鑰:拆開組合,避免本檔案在「掃描本專案自己」時被當成外洩
const REALISH_KEY = 'sk-proj-' + 'Xa7Qm2Lp9Rt4Vn8Kc3Zw6Hy1Bd5Fg0Js';
function checkTier(label, code, filename, kind, expectedTier) {
  const f = scanCode(code, { filename }).findings.find(x => x.kind === kind);
  const got = f ? f.tier : null;
  const ok = got === expectedTier;
  if (!ok) failCount++;
  console.log(`${ok ? '✅' : '❌'} [${kind} 應為 ${expectedTier === null ? '不回報' : 'tier' + expectedTier}${got !== expectedTier ? ',實際 ' + got : ''}] ${label}`);
}
checkTier('明顯的假金鑰(abcdef…1234567890)→ 參考', `const k = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890";`, 'app.js', 'plain_key', 3);
checkTier('交錯的假金鑰(a1B2c3D4…)→ 參考', `const k = "sk-proj-a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0";`, 'app.js', 'plain_key', 3);
checkTier('看起來真的金鑰 → 需要處理', `const k = "${REALISH_KEY}";`, 'app.js', 'plain_key', 1);
checkTier('測試檔裡看起來真的金鑰 → 仍然需要處理', `const k = "${REALISH_KEY}";`, 'tests/api.test.js', 'plain_key', 1);
checkTier('測試檔裡的 eval → 參考', `eval(input);`, 'src/__tests__/parse.test.js', 'insecure_eval', 3);
checkTier('一般檔案的 eval → 需要處理', `eval(input);`, 'src/parse.js', 'insecure_eval', 1);
checkTier('.js 檔裡的 HTML 字串不檢查 CSP', "const tpl = '<html><head></head><body></body></html>';", 'src/template.js', 'no_csp_html', null);
checkTier('.html 檔仍檢查 CSP', '<!DOCTYPE html><html><head></head><body></body></html>', 'public/index.html', 'no_csp_html', 1);
{
  const n = scanCode('const PYTHON_IMPORT = /^import os$/m;\n// def foo(): 範例\nimport os', { filename: 'modules/language-detector.js' }).notices;
  const ok = !n.some(x => x.id === 'language');
  if (!ok) failCount++;
  console.log(`${ok ? '✅' : '❌'} [notice:language 不應出現] .js 檔不提示 Python 特徵`);
}
{
  const f = scanCode('function a(){ return eval(x) + eval(y); }').findings.filter(x => x.kind === 'insecure_eval');
  const ok = f.length === 1;
  if (!ok) failCount++;
  console.log(`${ok ? '✅' : '❌'} [去重複] 同一行同一種問題只回報一次(實際 ${f.length} 筆)`);
}

// ── 第十五輪:整站生效的 CSP,其他網頁不重複報「完全沒有 CSP」 ──
console.log();
console.log('── 第十五輪:多檔案的 CSP 情境 ──');
{
  const PAGE = '<!DOCTYPE html><html><head><title>t</title></head><body><p>hi</p></body></html>';
  const cspNoHtml = f => scanFiles(f).findings.filter(x => x.kind === 'no_csp_html');
  const check = (label, files, want) => {
    const got = cspNoHtml(files).map(x => x.tier + (x.context ? '/' + x.context : '')).sort();
    const ok = JSON.stringify(got) === JSON.stringify(want);
    if (!ok) failCount++;
    console.log(`${ok ? '✅' : '❌'} ${label}(實際 ${JSON.stringify(got)})`);
  };
  const header = "module.exports={async headers(){return [{source:'/(.*)',headers:[{key:'Content-Security-Policy',value:\"default-src 'self'\"}]}]}}";

  check('[整站CSP] 沒有任何 CSP → 兩頁都是「需要處理」', [
    { filename: 'a.html', code: PAGE }, { filename: 'b.html', code: PAGE }
  ], ['1', '1']);

  check('[整站CSP] 框架設定檔有標頭 CSP → 兩頁都降為「參考」', [
    { filename: 'a.html', code: PAGE }, { filename: 'b.html', code: PAGE }, { filename: 'next.config.js', code: header }
  ], ['3/site-csp', '3/site-csp']);

  check('[整站CSP] nginx 設定檔也算整站生效', [
    { filename: 'a.html', code: PAGE }, { filename: 'nginx.conf', code: 'add_header Content-Security-Policy "default-src \'self\'";' }
  ], ['3/site-csp']);

  check('[整站CSP] helmet 設定也算整站生效', [
    { filename: 'a.html', code: PAGE },
    { filename: 'server.js', code: "app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: [\"'self'\"], scriptSrc: [\"'self'\"] } } }))" }
  ], ['3/site-csp']);

  check('[整站CSP] 別頁的 <meta> 只管自己那頁,不連帶降級', [
    { filename: 'a.html', code: PAGE },
    { filename: 'b.html', code: '<!DOCTYPE html><html><head><meta http-equiv="Content-Security-Policy" content="default-src \'self\'; object-src \'none\'; base-uri \'none\'"></head></html>' }
  ], ['1']);

  check('[整站CSP] 只回報不阻擋的標頭不算有防線', [
    { filename: 'a.html', code: PAGE },
    { filename: 'server.js', code: "res.setHeader('Content-Security-Policy-Report-Only', \"default-src 'self'\")" }
  ], ['1']);

  {
    // 單檔案貼上時不套用(沒有別的檔案可以佐證)
    const one = scanCode(PAGE, { filename: 'a.html' }).findings.filter(x => x.kind === 'no_csp_html');
    const ok = one.length === 1 && one[0].tier === 1 && !one[0].context;
    if (!ok) failCount++;
    console.log(`${ok ? '✅' : '❌'} [整站CSP] 單獨貼一頁 HTML 時仍是「需要處理」`);
  }
}

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
