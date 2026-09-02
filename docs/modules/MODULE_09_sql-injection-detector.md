# M9 — sql-injection-detector

## 你的任務
偵測資料庫查詢語句是否用「字串拼接」的方式組成（相對於安全的「參數化查詢」寫法）。這是繼 M1-M8 之後新增的第 9 個模組，判斷邏輯的可靠度定位跟 M6（IDOR）相近——都是「可從語法特徵直接判斷的模式」，但仍歸類為 tier 2（建議複查），因為無法判斷拼接進去的變數是否真的來自不可信來源。

**你不需要看過這個專案的任何其他模組。這份文件是你需要的全部背景。**

## 為什麼加這個模組

2026 年 GenAI Code Security Report 等公開報告顯示，SQL Injection 是 AI 產出程式碼常見的資安問題類別之一。原始的《AI 產出程式碼資安檢查器》報告在最初的能力對照表裡把它列為「可以，且相對可靠」（跟 IDOR 同一個技術難度分類），但當時沒有實際做——這個模組是補上這個缺口。

## 函式簽名

```js
function sqlInjectionDetector(code) {
  // code: string
  // 回傳: Finding[]
}
```

## 核心邏輯：三種拼接模式

```js
const SQL_KEYWORD_PATTERN = '(SELECT|INSERT|UPDATE|DELETE)';

// 模式1: 字串拼接 — SQL關鍵字附近(同一行,120字元內)出現字串結尾接+號,
// 或+號後方接SQL關鍵字字串
const CONCAT_PATTERN = new RegExp(
  `\\b${SQL_KEYWORD_PATTERN}\\b[\\s\\S]{0,120}?["'\`]\\s*\\+|\\+\\s*["'\`][\\s\\S]{0,40}?\\b${SQL_KEYWORD_PATTERN}\\b`,
  'i'
);

// 模式2: JS模板字面值插值 — `...SQL...${...}...`
const TEMPLATE_INTERP_PATTERN = new RegExp(
  `\`[^\`]*\\b${SQL_KEYWORD_PATTERN}\\b[^\`]*\\$\\{[^}]+\\}[^\`]*\``,
  'i'
);

// 模式3: Python f-string — f"...SQL...{...}..."
const FSTRING_PATTERN = new RegExp(
  `f["'][^"']*\\b${SQL_KEYWORD_PATTERN}\\b[^"']*\\{[^}]+\\}[^"']*["']`,
  'i'
);
```

逐行掃描（不是整段程式碼一次比對），每一行分別套用三種規則，命中即產生 Finding：

```js
{
  tier: 2,
  category: '建議人工複查',
  name: '（依命中的規則而定，見模組內三種名稱）',
  kind: 'possible_sql_injection',
  evidence: '偵測到 SQL 查詢字串疑似透過拼接方式組成，而非使用參數化查詢（如 ? 佔位符或 ORM 方法），建議改用參數化查詢避免 SQL Injection'
}
```

## ⚠️ 重要：`CONCAT_PATTERN` 的設計取捨（來自真實案例踩坑的教訓，已發生過兩輪修正）

**不要用「排除引號字元的字元類別」（如 `[^"'`]`）去界定 SQL 字串的邊界。** 這是這個模組最初版本犯過的錯，且是拿真實案例測試才發現的：

SQL 查詢字串本身經常包含單引號（例如 `"SELECT * FROM users WHERE username='" + username + "'"`），如果正則用 `[^"'`]` 排除引號字元來界定字串邊界，遇到字串內部自己的單引號就會提早截斷比對，導致**這個最常見的真實寫法反而被漏判**。

第一次修正改用「限制比對長度的寬鬆匹配」（`[\s\S]{0,120}?`）取代嚴格的引號邊界匹配，犧牲一點點理論上的精確度，換取不漏判真實世界最常見的樣式。

**但這次修正留下了一個副作用，是後續拿誤判率測試（邊界值案例）才發現的**：判斷條件放寬成「SQL 關鍵字附近有拼接即算數」之後，一句只是**提到** SQL 關鍵字的普通說明文字（例如 `"Use SELECT statements carefully" + userNote`），也會被誤判為疑似 SQL Injection——因為它確實符合「SELECT 附近有拼接」，卻根本不是一句 SQL 語句。

第二次修正：要求 SQL 關鍵字後方（60字元內）還要出現對應的第二關鍵字（`FROM`/`INTO`/`WHERE`/`SET`/`VALUES`），兩者都出現才判定為真正的 SQL 語句結構，而不只是「提到 SQL 關鍵字的普通文字」。目前的 `CONCAT_PATTERN` 已經是這個雙關鍵字版本。

**這裡最重要的教訓，修改這個模組時務必記住**：修正一個漏判問題（讓判斷更寬鬆）很可能同時引入新的誤判空間；修正一個誤判問題（讓判斷更嚴格）也可能意外造成新的漏判。**改動 `CONCAT_PATTERN` 之後，必須同時跑 `test/sql-injection-detector.test.js`（功能測試）、`eval/run_eval.js`（true positive 真實案例，確認命中率沒下降）、`eval/run_fp_eval.js`（false positive 誤判率，確認沒有新誤判）三份測試，缺一不可**——只跑功能測試會漏掉這種「規則邊界的連鎖效應」，這正是這個模組已經發生過一次的真實教訓。

## 明確不在你職責範圍內的東西

- 判斷拼接進去的變數是否經過消毒（sanitize）處理 → 做不到，只要偵測到拼接模式就會標記
- DDL 語句（CREATE/DROP 等）→ 目前只涵蓋 SELECT/INSERT/UPDATE/DELETE
- 跨行拼接（例如用 `.concat()` 方法、或分成多行變數再組合）→ 目前逐行比對，看不到跨行的拼接關係
- 若 SQL 語句的第二關鍵字（FROM/WHERE 等）距離 SQL 關鍵字超過 60 字元（例如選取極多欄位的 SELECT），可能導致漏判 → 這是為了限制正則掃描範圍、避免效能問題與跨語句誤配對而做的取捨，已知限制

## 測試要求

1. **True positive**：JS 字串拼接（含字串內部自帶引號的情境，這是曾經漏判過的案例，務必保留這條測試）、模板字面值插值、Python f-string、Python 字串拼接、長欄位清單的 SELECT、UPDATE...SET 語句
2. **True negative**：`?` 佔位符參數化查詢、`%s` 佔位符參數化查詢、ORM 方法呼叫（如 `User.findOne(...)`）、**SQL 關鍵字出現在一般說明文字裡（不構成完整語句，這是曾經誤判過的案例，務必保留這條測試）**都不應被偵測到
3. **tier/kind 正確性**：一律 tier 2、kind 為 `possible_sql_injection`
4. **空輸入**：`code = ''` 回傳空陣列
5. **改動 CONCAT_PATTERN 時，三份測試都要跑**：`test/sql-injection-detector.test.js`、`eval/run_eval.js`、`eval/run_fp_eval.js`，見上方「設計取捨」段落的完整說明

## 對照基準

`eval/samples.js` 案例 #4、#5 是這個模組的真實世界驗證案例，`eval/EVAL_REPORT.md` 記錄了發現漏判與修正的完整過程。
