# 規則邊界修正 — 交接文件

這份文件整理四個已驗證存在、待修正的規則邊界，供接手的人（AI 或工程師）直接動手，不需要重新調查。每一項都附：問題重現方式、精確的程式碼位置、建議修法、以及修完後怎麼驗證。

**背景**：這四項是在拿真實資安事件改寫案例、以及 [SecurityEval](https://github.com/s2e-lab/SecurityEval) 學術資料集（MIT 授權，逐字取用）驗證工具時發現的。詳細案例與原始驗證紀錄見 `eval/reference_cases/README.md` 與該資料夾內對應的 `*-known-gap.txt` 檔案。

**通用原則**：
- 四項彼此獨立，互不依賴，可以任選順序或只做其中幾項。
- 每項都是「新增一條規則」，不需要重寫現有邏輯，改動範圍小。
- 兩個版本要同步：`demo_split/modules/<檔名>.js`（拆分版）與 `reference/index.html` 內對應的同一段程式碼（單檔版，用註解 `// ── 模組: <檔名>.js ──` 標記邊界，可搜尋定位）。**忘記同步是最容易出的錯**，修完後兩邊都要跑一次驗證。
- 改完規則後，把 `eval/reference_cases/` 裡對應的 `*-known-gap.txt` 案例移回 `eval/cases/`（因為它們現在應該會命中了），並更新 `eval/reference_cases/README.md` 的邊界清單（移除已修正的項目）。
- 跑 `eval/run_scaled_eval.js` 確認整體命中率統計沒有意外下降（新規則不該讓任何既有案例從命中變漏判）。

---

## 1. M3 hash-detector — 不涵蓋 `hashlib.new('md5')` 兩段式建構

**規模：小**

### 問題重現

```js
const { hashDetector } = require('./demo_split/modules/hash-detector.js');
const code = `
import hashlib

def storePassword(userName, Password):
    hasher = hashlib.new('md5')
    hasher.update(Password)
    hashed_password = hasher.digest()
    return updateUserLogin(userName, hashed_password)
`;
console.log(hashDetector(code)); // 目前回傳 []，應該要偵測到弱雜湊
```

對照案例：`eval/reference_cases/securityeval-cwe759-hashlib-new-known-gap.txt`（逐字取自 SecurityEval `CWE-759_mitre_1`）。

### 精確位置

`demo_split/modules/hash-detector.js`，`HASH_RULES` 陣列（第 13-16 行）：

```js
const HASH_RULES = [
  { name: 'MD5 用於密碼儲存（疑似）', re: /md5\s*\(\s*(password|pwd|pass)/gi },
  { name: 'SHA1 用於密碼儲存（疑似）', re: /sha1\s*\(\s*(password|pwd|pass)/gi },
];
```

只認 `md5(password...)` 這種函式呼叫時直接把密碼參數傳入的單行形態，不認 `hashlib.new('md5')` 建構後再用 `.update(password...)` 分兩段餵入的形態。

### 建議修法

新增規則，偵測 `hashlib.new('md5')` / `hashlib.new('sha1')` 後、一定字元範圍內（例如 200 字元）出現 `.update(...)` 且參數名含 password/pwd/pass：

```js
const HASH_NEW_MD5_PATTERN = /hashlib\.new\(\s*['"]md5['"]\s*\)[\s\S]{0,200}?\.update\s*\(\s*(password|pwd|pass)/gi;
const HASH_NEW_SHA1_PATTERN = /hashlib\.new\(\s*['"]sha1['"]\s*\)[\s\S]{0,200}?\.update\s*\(\s*(password|pwd|pass)/gi;
```

加進 `HASH_RULES` 陣列即可，`hashDetector` 主邏輯完全不用動。

### 驗證

```bash
cd eval
node -e "
const { runScan } = require('./eval-orchestrator');
const raw = require('fs').readFileSync('reference_cases/securityeval-cwe759-hashlib-new-known-gap.txt', 'utf-8');
const code = raw.slice(raw.indexOf('===CODE===') + 10).trim();
console.log(runScan(code).findings.map(f => f.kind));
"
```
應該要看到 `weak_hash`。

修法建議段落給的正則也已測過不會誤傷非密碼用途（例如檔案校驗）：

```js
const pySafeCode = `
def get_checksum(file_data):
    hasher = hashlib.new('md5')
    hasher.update(file_data)
    return hasher.hexdigest()
`;
console.log('Python hashlib.new用於檔案校驗,非密碼(應false):', HASH_NEW_MD5_PATTERN.test(pySafeCode));
```

**注意誤判風險**：`hashlib.new('md5')` 也常用於非密碼場景（例如檔案完整性校驗，`eval/cases/legacy-tn-006.txt` 就是這類安全案例）。新規則要求 `.update()` 的參數名含 password/pwd/pass 才觸發，跟既有規則的判斷邏輯一致，理論上不會誤傷檔案校驗場景，但修完後務必連同 `eval/cases/legacy-tn-*.txt` 全部案例一起跑 `run_fp_eval.js` 或 `run_scaled_eval.js`，確認誤判率沒有上升。

---

## 2. M10 insecure-deserialize-detector — 不涵蓋 Python `exec()` 含格式化字串

**規模：小～中**

### 問題重現

```js
const { insecureDeserializeDetector } = require('./demo_split/modules/insecure-deserialize-detector.js');
const code = `
from flask import Flask, request
app = Flask(__name__)

@app.route('/')
def index():
    module = request.args.get("module")
    exec("import urllib%s as urllib" % module)
    return "Module imported"
`;
console.log(insecureDeserializeDetector(code)); // 目前回傳 []，應該要偵測到 code injection
```

對照案例：`eval/reference_cases/securityeval-cwe094-sonar1-known-gap.txt`（逐字取自 SecurityEval `CWE-094_sonar_1`）。

### 精確位置

`demo_split/modules/insecure-deserialize-detector.js`，`INSECURE_DESERIALIZE_RULES` 陣列（第 18-24 行）：

```js
const INSECURE_DESERIALIZE_RULES = [
  { name: 'eval() 執行動態內容（疑似不安全反序列化/程式碼注入）', re: /\beval\s*\(/g, kind: 'insecure_eval' },
  { name: 'Python pickle.loads() 反序列化不可信資料', re: /\bpickle\.loads?\s*\(/g, kind: 'insecure_pickle' },
  { name: 'Python yaml.load() 未使用安全模式（應改用 yaml.safe_load 或指定 SafeLoader）', re: /\byaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)/g, kind: 'insecure_yaml_load' },
  { name: 'Node.js exec()/execSync() 執行動態組成的指令（疑似命令注入）', re: /\b(exec|execSync)\s*\(\s*[a-zA-Z_$][\w$]*/g, kind: 'insecure_exec' },
  { name: 'Function 建構子動態執行程式碼字串（等同 eval 的風險）', re: /new\s+Function\s*\(/g, kind: 'insecure_function_constructor' },
];
```

現有的 `insecure_exec` 規則是 Node.js 的 `exec/execSync`，且要求後面接**變數名**（不是字串），刻意排除固定字串常值（避免誤報 `execSync("ls -la")`）。但 Python 的 `exec("...")` 語意完全不同——它執行的是**程式碼字串**本身，不是 shell 指令。目前完全沒有規則涵蓋 Python `exec()`。

### 建議修法

新增一條**獨立**的 Python `exec()` 規則（不要跟 Node `exec/execSync` 那條混在一起，語意不同），偵測 `exec(` 傳入的字串含 `%` 格式化或字串拼接（`+`）或 f-string 插值：

```js
// Python exec() 執行由字串格式化/拼接組成的內容(區別於Node.js的exec/execSync,
// Python exec()直接執行程式碼字串,語意上更接近eval而非shell指令執行)
const PYTHON_EXEC_DYNAMIC_PATTERN = /\bexec\s*\(\s*(f?["'][^"']*%[sd][^"']*["']\s*%|["'][^"']*["']\s*\+|f["'])/g;
```

加進 `INSECURE_DESERIALIZE_RULES` 陣列，`kind` 建議用新的 `insecure_python_exec`（不要跟既有的 `insecure_exec` 共用，因為那個 kind 目前語意綁定 Node.js，React/前端頁面渲染結果會用不同文字說明兩者，混用會讓使用者看到誤導的說明文字）。**這個新 kind 需要同步加進 `eval/case-loader.js` 的 `VALID_KINDS` 集合**，否則新案例會在 `loadCases` 階段報錯。

### 驗證

同上，用 `securityeval-cwe094-sonar1-known-gap.txt` 測試，應該要看到新的 `insecure_python_exec`。

修法建議段落給的 `PYTHON_EXEC_DYNAMIC_PATTERN` 已用以下組合測過：

```js
const code1 = `exec("import urllib%s as urllib" % module)`;
console.log('正案例-%格式化(應true):', PYTHON_EXEC_DYNAMIC_PATTERN.test(code1));

const code2 = `exec("print(1)")`;
console.log('安全固定字串(應false):', PYTHON_EXEC_DYNAMIC_PATTERN.test(code2));

const code3 = `exec("x = 1; y = 2" + extra_code)`;
console.log('拼接版本(應true):', PYTHON_EXEC_DYNAMIC_PATTERN.test(code3));

const code4 = `execSync("ls -la")`;
console.log('Node.js execSync固定字串,不該被新規則誤判(應false):', PYTHON_EXEC_DYNAMIC_PATTERN.test(code4));
```

**注意誤判風險**：務必確認 `exec("print('hello')")` 這種固定字串常值、不含格式化語法的呼叫**不會**被新規則觸發（正則要求出現 `%` 格式化或拼接語法，理論上安全，但建議額外手動寫一個這樣的安全案例丟進 `eval/cases/` 驗證一次）。

---

## 3. M9 sql-injection-detector — 不涵蓋 Python `%` 格式化字串

**規模：中**

### 問題重現

```js
const { sqlInjectionDetector } = require('./demo_split/modules/sql-injection-detector.js');
const code = `
def show_user(username):
    cursor = get_connection().cursor()
    cursor.execute("SELECT * FROM users WHERE username = '%s'" % username)
    return cursor.fetchone()
`;
console.log(sqlInjectionDetector(code)); // 目前回傳 []，應該要偵測到 SQL injection
```

對照案例：`eval/reference_cases/securityeval-cwe089-percent-format-known-gap.txt`（逐字取自 SecurityEval `CWE-089_codeql_1`，另有 `CWE-089_author_1` 的 `DELETE` 版本同樣問題，未單獨建檔，屬同一類邊界）。

### 精確位置

`demo_split/modules/sql-injection-detector.js`，第 52-70 行：

```js
const SQL_KEYWORD_PATTERN = '(SELECT|INSERT|UPDATE|DELETE)';
const SQL_SECOND_KEYWORD_PATTERN = '(FROM|INTO|WHERE|SET|VALUES)';

const CONCAT_PATTERN = new RegExp(
  `\\b${SQL_KEYWORD_PATTERN}\\b[\\s\\S]{0,60}?\\b${SQL_SECOND_KEYWORD_PATTERN}\\b[\\s\\S]{0,60}?["'\`]\\s*\\+|\\+\\s*["'\`][\\s\\S]{0,40}?\\b${SQL_KEYWORD_PATTERN}\\b[\\s\\S]{0,60}?\\b${SQL_SECOND_KEYWORD_PATTERN}\\b`,
  'i'
);

const TEMPLATE_INTERP_PATTERN = new RegExp(
  `\`[^\`]*\\b${SQL_KEYWORD_PATTERN}\\b[^\`]*\\$\\{[^}]+\\}[^\`]*\``,
  'i'
);

const FSTRING_PATTERN = new RegExp(
  `f["'][^"']*\\b${SQL_KEYWORD_PATTERN}\\b[^"']*\\{[^}]+\\}[^"']*["']`,
  'i'
);

const SQL_INJECTION_RULES = [
  { name: 'SQL 查詢使用字串拼接組成（疑似 SQL Injection）', re: CONCAT_PATTERN },
  { name: 'SQL 查詢使用模板字面值插值組成（疑似 SQL Injection）', re: TEMPLATE_INTERP_PATTERN },
  { name: 'SQL 查詢使用 Python f-string 插值組成（疑似 SQL Injection）', re: FSTRING_PATTERN },
];
```

只涵蓋字串拼接（`+`）、JS 模板插值（`` `...${}...` ``）、Python f-string（`f"...{}..."`），不涵蓋 Python 的 `%` 格式化語法（`"...%s..." % var`，等同 C 的 printf 風格）。

### 建議修法

新增一條規則，比照 `CONCAT_PATTERN` 的設計邏輯（用長度限制的寬鬆匹配取代嚴格引號邊界，因為 SQL 字串內部經常自帶單引號，例如 `WHERE username = '%s'`，嚴格引號邊界會提早截斷比對而漏判——這正是 `CONCAT_PATTERN` 當初「修正紀錄」解決過的同一類問題），改成偵測 `%` 格式化：

```js
// Python % 格式化字串組成SQL(printf風格,例如 "...%s..." % var)
// 要求兩個SQL關鍵字都出現、且引號結尾後緊接%格式化運算子,避免誤判一般字串格式化
// (例如 "%d items found" % count)或「只是提到SQL關鍵字的普通文字」
// (例如 log.info("User %s logged in with SELECT permission" % username))
const PERCENT_FORMAT_PATTERN = new RegExp(
  `\\b${SQL_KEYWORD_PATTERN}\\b[\\s\\S]{0,60}?\\b${SQL_SECOND_KEYWORD_PATTERN}\\b[\\s\\S]{0,80}?["']\\s*%\\s*\\w`,
  'i'
);
```

**這個版本已實測驗證過**（見下方「驗證」段落的測試組合），能正確處理：真正的 SQL `%s` 格式化（含 `SELECT`/`DELETE` 等不同關鍵字）判定為 true；一般字串格式化（如 `"%d items found" % count`）與「只提到 SQL 關鍵字但非真正語句」的情況，都正確判定為 false。**不要用更簡單的寫法**（例如只判斷「引號後接 % 加變數」而不要求兩個 SQL 關鍵字同時出現），那樣會把日誌訊息格式化這類常見寫法大量誤判。

加進 `SQL_INJECTION_RULES` 陣列，主邏輯 `sqlInjectionDetector` 完全不用動（架構已經是「陣列裡加規則就好」）。

### 驗證

用 `securityeval-cwe089-percent-format-known-gap.txt` 測試，應該要看到 `possible_sql_injection`。

修法建議段落給的 `PERCENT_FORMAT_PATTERN` 已用以下組合測過，接手時可以直接照抄這組測試：

```js
const code1 = `cursor.execute("SELECT * FROM users WHERE username = '%s'" % username)`;
console.log('正確SQL案例(應true):', PERCENT_FORMAT_PATTERN.test(code1));

const code2 = `print("%d items found" % count)`;
console.log('一般格式化(應false):', PERCENT_FORMAT_PATTERN.test(code2));

const code3 = `cursor.execute("DELETE FROM users WHERE username = '%s'" % username)`;
console.log('DELETE版本(應true):', PERCENT_FORMAT_PATTERN.test(code3));

const code4 = `log.info("User %s logged in with SELECT permission" % username)`;
console.log('提到SQL關鍵字但非真正SQL語句(應false):', PERCENT_FORMAT_PATTERN.test(code4));
```

**注意誤判風險（這項風險相對高，修的時候要仔細測）**：`%` 格式化在 Python 裡是非常常見的一般字串操作，不只用在 SQL（例如 `"%d items found" % count`、日誌訊息格式化等）。新規則要求**同時**出現 SQL 關鍵字（`SELECT/INSERT/UPDATE/DELETE`）和第二關鍵字（`FROM/INTO/WHERE/SET/VALUES`）才觸發，理論上能篩掉大部分無關的字串格式化，但因為 `%` 格式化語法本身太泛用，修完後**務必**額外寫幾個「用 `%` 格式化、但不是 SQL」的安全案例丟進 `eval/cases/`（例如一般的 log 訊息格式化、字串模板等）跑 `run_fp_eval.js`，確認沒有引入新的誤判。

---

## 4. M6 idor-detector — 正則保底版不涵蓋 Express 路由掛載式寫法

**規模：中（範圍比原先評估小——AST 版本已經沒問題，只需要補正則保底版）**

### 重要澄清

之前評估這項時，**只測過正則保底版**（模擬 CDN 離線情境），誤以為 M6 完全不支援 Express callback 寫法。後來用 AST 版重測，發現 **AST 版本其實已經正確偵測**：

```bash
cd eval
node -e "
global.acorn = require('acorn');
const { runScan } = require('./eval-orchestrator');
const raw = require('fs').readFileSync('reference_cases/incident-moltbook-2026.txt', 'utf-8');
const code = raw.slice(raw.indexOf('===CODE===') + 10).trim();
console.log(runScan(code).findings.map(f => f.kind)); // ['possible_idor'] ✅ AST版已命中
"
```

`incident-base44-2025.txt` 同樣，AST 版也命中。**真正的問題只在正則保底版**（`idorDetectorRegex`），這是 acorn CDN 載入失敗、離線環境、或企業網路限制時的降級路徑。

⚠️ **驗證正則保底版時的陷阱**：`resolveAcorn()` 是用 `typeof globalThis.acorn !== 'undefined'` 判斷 acorn 是否可用。如果在同一個 Node 進程裡任何時候 `require('acorn')` 並賦值給 `global.acorn` 過，之後即使不再主動使用，這個進程裡的判斷依然會誤以為 acorn 可用，跑出來的其實是 AST 版結果，不是真正的正則保底版。**驗證正則保底版必須用全新的、從未 `require('acorn')` 的 Node 進程執行**，例如另存成獨立的 `.js` 檔案再 `node xxx.js` 執行，不要在同一個互動式 session 或同一段程式碼裡先跑過 AST 版測試又跑正則版測試。

### 問題重現（正則保底版）

```js
const { idorDetector } = require('./demo_split/modules/idor-detector.js'); // 不載入acorn,強制走正則版
const code = `
app.get('/api/users/:userId/token', requireAuth, async (req, res) => {
  const record = await db.tokens.findOne({ userId: req.params.userId });
  res.json({ token: record.authToken, email: record.email });
});
`;
console.log(idorDetector(code)); // 正則版回傳 []，AST版能抓到
```

對照案例：`eval/reference_cases/incident-moltbook-2026.txt`、`incident-base44-2025.txt`（依真實事件改寫，非逐字蒐集，見檔案內 SOURCE 說明）。

### 精確位置

`demo_split/modules/idor-detector.js`，第 53-55 行：

```js
const IDOR_PATTERN = /(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s+\w+\s*\([^)]*\b(id|userId|req|[a-zA-Z_$][a-zA-Z0-9_$]*Id)\b[^)]*\)(?:\s*:\s*[\w.<>\[\]| ]+)?\s*{([^}]{0,300})}/g;
const DB_CALL_PATTERN = /\.(find|get|query|select|delete|update)\s*\(/i;
const AUTH_CHECK_PATTERN = /\b(owner|user\.id|session|auth|permission|role)\b/i;
```

只認 `function xxx(id) {...}` 這種具名函式宣告，或（依既有修正紀錄）指派給變數的箭頭函式如 `const deleteOrder = async (req, res) => {...}`，不認**直接作為參數傳給另一個函式呼叫**的箭頭函式，例如 `app.get(path, (req, res) => {...})`——這種寫法箭頭函式沒有被賦值給一個具名變數，是 Express/Koa 等框架路由註冊的標準寫法。

### 建議修法

新增一條正則，比照 `IDOR_PATTERN` 的判斷邏輯（找函式主體 → 檢查 DB call → 檢查 auth check），但改成匹配「作為函式呼叫參數的箭頭函式」這個更廣的模式：

```js
// Express/Koa等框架的路由掛載寫法: app.METHOD(path, ...middlewares, (req,res)=>{...})
// 箭頭函式直接作為呼叫參數傳入,沒有被賦值給具名變數,IDOR_PATTERN(鎖定具名function
// 宣告)抓不到這種形態。這裡改成寬鬆匹配「任意函式呼叫的最後一個參數是箭頭函式,
// 且箭頭函式參數名符合req/res慣例」,不嚴格要求是app.get/post等特定方法名,
// 因為框架寫法多樣(router.get、fastify.get等),鎖定方法名反而容易漏判。
const ROUTE_CALLBACK_PATTERN = /\((?:req|request)\s*,\s*(?:res|response)\s*\)\s*=>\s*{([^}]{0,300})}/g;
```

加進 `idorDetectorRegex` 函式內，比照現有邏輯跑一次 `DB_CALL_PATTERN` / `AUTH_CHECK_PATTERN` 判斷（可以抽成共用函式，兩條規則共用同一套「有 DB call 且無 auth check 就標記」的判斷邏輯，避免重複程式碼）。

**注意**：這條新正則沒有要求函式參數名一定要是 `id`/`userId`/`xxxId`（因為 Express 路由 callback 的固定簽名就是 `(req, res)`，實際查詢用的 ID 通常在 `req.params.xxx` 裡，不是函式參數本身），這跟 `IDOR_PATTERN` 的設計前提不同，需要用獨立的規則、獨立的判斷條件，不要嘗試把兩條正則合併成一條（會讓正則更難懂、更難維護，兩條規則保持獨立、各自簡單，比較符合這個專案目前所有模組的一貫寫法）。

### 驗證

⚠️ 依上方「驗證陷阱」提醒，請另存成獨立檔案執行，不要在同一段互動式指令裡混跑 AST 版與正則版測試：

```bash
cd eval
cat > /tmp/verify_m6_regex.js << 'SCRIPT'
// 全新進程,不 require('acorn'),確保測的是真正的正則保底版
const { runScan } = require('/絕對路徑/eval/eval-orchestrator');
['incident-moltbook-2026.txt', 'incident-base44-2025.txt'].forEach(f => {
  const raw = require('fs').readFileSync('/絕對路徑/eval/reference_cases/' + f, 'utf-8');
  const code = raw.slice(raw.indexOf('===CODE===') + 10).trim();
  console.log(f, ':', runScan(code).findings.map(x => x.kind));
});
SCRIPT
node /tmp/verify_m6_regex.js
```
修正前，兩個都應該印出 `[]`（漏判）；修正後，兩個都應該要看到 `possible_idor`。

**注意誤判風險**：這條新規則比 `IDOR_PATTERN` 寬鬆（不要求特定參數命名），誤判風險相對較高。修完後務必把全部既有的 `eval/cases/legacy-tn-*.txt`（29 個安全案例）和新增的 `securityeval-*` 案例都跑一次 `run_scaled_eval.js`，特別留意有沒有安全的 Express 路由（例如 `eval/cases/legacy-tn-011.txt`、`legacy-tn-012.txt`，這兩個是正確做了擁有權比較檢查的 IDOR 防護案例）被新規則誤傷。

---

## 完成後的收尾清單

- [ ] 四項改動都同步套用到 `demo_split/modules/*.js` 與 `reference/index.html` 對應段落
- [ ] 每項改動都有對應的正向測試（`reference_cases/*-known-gap.txt` 現在應該命中）
- [ ] 每項改動都測過負向案例（不該誤傷的安全寫法），特別是 M9 和 M6 這兩項風險較高的
- [ ] 已修正的 `*-known-gap.txt` 案例從 `eval/reference_cases/` 移回 `eval/cases/`（連同 `EXPECTED` 欄位內容不用改，本來就是正確的期望值）
- [ ] 更新 `eval/reference_cases/README.md`，移除已修正項目，只留下還沒修的邊界
- [ ] 跑 `eval/run_scaled_eval.js`（正則版與 AST 版都跑）確認整體命中率上升、誤判率沒有上升
- [ ] 若新增了 `insecure_python_exec` 這個新 kind，記得同步更新 `eval/case-loader.js` 的 `VALID_KINDS` 集合、`eval/CASE_FORMAT.md` 的合法清單、以及 `finding-renderer.js`（M8）裡對應的畫面呈現文字（新 kind 需要有自己的說明文字，不能直接沿用 `insecure_exec` 的文字，因為語意不同）
