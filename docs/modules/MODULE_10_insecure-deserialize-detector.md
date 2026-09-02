# M10 — insecure-deserialize-detector

## 你的任務
偵測程式碼中呼叫已知不安全的反序列化/動態執行函式（`eval()`、Python `pickle.loads()`、未加安全模式的 `yaml.load()`、動態組成的 `exec()`/`execSync()`、`new Function()`）。

**你不需要看過這個專案的任何其他模組。這份文件是你需要的全部背景。**

## 設計思路：跟 M3（弱雜湊）同一個套路

這個模組的可靠度定位很高，**固定為 tier 1**（高信心度發現），跟 M1（金鑰）、M3（弱雜湊）同一等級，不是像 IDOR 那樣的「疑似、建議複查」。原因是：判斷邏輯是「有沒有呼叫這個已知危險的函式」，這是固定字面樣式比對，跟弱雜湊偵測（`md5(password)`）本質上是同一種做法，只是換一批危險函式清單。

## 函式簽名

```js
function insecureDeserializeDetector(code) {
  // code: string
  // 回傳: Finding[]
}
```

## 規則庫

```js
const INSECURE_DESERIALIZE_RULES = [
  { name: 'eval() 執行動態內容（疑似不安全反序列化/程式碼注入）', re: /\beval\s*\(/g, kind: 'insecure_eval' },
  { name: 'Python pickle.loads() 反序列化不可信資料', re: /\bpickle\.loads?\s*\(/g, kind: 'insecure_pickle' },
  { name: 'Python yaml.load() 未使用安全模式（應改用 yaml.safe_load 或指定 SafeLoader）', re: /\byaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)/g, kind: 'insecure_yaml_load' },
  { name: 'Node.js exec()/execSync() 執行動態組成的指令（疑似命令注入）', re: /\b(exec|execSync)\s*\(\s*[a-zA-Z_$][\w$]*/g, kind: 'insecure_exec' },
  { name: 'Function 建構子動態執行程式碼字串（等同 eval 的風險）', re: /new\s+Function\s*\(/g, kind: 'insecure_function_constructor' },
];
```

每種規則命中，產生：

```js
{
  tier: 1,
  category: '不安全的反序列化/動態執行',
  name: '（依命中的規則而定）',
  kind: '（見上表對應的 kind 值）',
  evidence: '（比對到的原始字串片段，超過60字元截斷加省略號）'
}
```

## 關鍵設計細節：`exec`/`execSync` 為何要求「參數是識別字開頭」

```js
/\b(exec|execSync)\s*\(\s*[a-zA-Z_$][\w$]*/g
```

正則要求括號後緊接著的是**識別字**（變數名），而不是任何內容。這是刻意的設計，用來排除「固定字串常值」的呼叫（例如 `execSync("ls -la")`——括號後面接的是引號 `"`，不是識別字，不會命中）。

**理由**：`execSync("ls -la")` 這種固定寫死的指令，技術上沒有命令注入風險（沒有變數可以被外部操控）。但如果變數是用拼接方式組成字串再傳入（例如 `execSync("ls " + userInput)`），這種寫法**表面上第一個字元是引號**，同樣不會被目前的規則抓到——這是已知限制，因為要判斷「字串常值裡有沒有拼接變數」需要更複雜的分析（跟 M9 SQL Injection 的拼接偵測邏輯類似），目前 M10 沒有做這一層。

## 明確不在你職責範圍內的東西

- 判斷傳入這些危險函式的資料是否真的來自不可信來源 → 做不到，只要呼叫了就會標記，即使實際上處理的是安全的固定值
- `execSync("ls " + userInput)` 這種「字串常值開頭但內部有拼接」的命令注入 → 目前規則沒涵蓋，屬已知限制

## 測試要求

1. **True positive**：每一種規則都至少一個能命中的範例（`eval()`、`pickle.loads()`、`yaml.load()` 未加 safe、`exec()`/`execSync()` 搭配變數、`new Function()`）
2. **True negative**：`yaml.load()` 有加 `Loader=yaml.SafeLoader` 不應命中、`yaml.safe_load()`（方法名不同）不應命中、`JSON.parse()` 不應命中、`execSync("ls -la")`（固定字串常值）不應命中
3. **tier 正確性**：一律 tier 1
4. **evidence 長度合理**：不應過長，超過 60 字元要截斷
5. **空輸入**：`code = ''` 回傳空陣列

## 對照基準

`eval/samples.js` 案例 #8（`eval()` 處理動態配置）是這個模組的真實世界驗證案例。
