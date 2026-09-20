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
