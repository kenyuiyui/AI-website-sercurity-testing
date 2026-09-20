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
  { filename: 'tmp_home.html', code: '<!DOCTYPE html><html><head></head><body></body></html>' },
  { filename: 'vite.config.ts', code: "import path from 'node:path'\nexport default { resolve: { alias: { '@': path.resolve(__dirname, './src') } } }" }
];
const vr = scanFiles(VITE_PROJECT);
const st = (r, p) => (r.projectMap.nodes.find(n => n.path === p) || {}).status;
checkMap('入口追得到的檔案標為使用中(含 @ 別名、動態 import)', ['index.html', 'src/main.ts', 'src/App.vue', 'src/components/Nav.vue', 'src/views/Home.vue'].every(p => st(vr, p) === 'used'));
checkMap('追不到的檔案標為疑似沒用到', st(vr, 'src/components/Old.vue') === 'unused' && st(vr, 'tmp_home.html') === 'unused');
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
checkMap('畫面顯示檔案地圖與疑似沒用到的數量', /rs-tree/.test(findingRenderer(vr.findings, vr.languageCaveat, vr.notices, vr.projectMap)) && /3 個疑似沒在使用/.test(findingRenderer(vr.findings, vr.languageCaveat, vr.notices, vr.projectMap)));

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
