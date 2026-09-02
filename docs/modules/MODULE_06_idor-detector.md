# M6 — idor-detector

## 你的任務
偵測程式碼中疑似缺少「擁有權驗證」的函式——也就是只檢查「有沒有登入」，卻沒檢查「這筆資料是不是真的屬於這個使用者」的模式（Broken Access Control / IDOR）。

**你不需要看過這個專案的任何其他模組。這份文件是你需要的全部背景。**

## ✅ 現況：已完成「正則保底 + AST(Acorn) 疊加分析」架構

這是本專案目前唯一採用「雙層分析」設計的模組。

## 這是本專案中最需要謹慎的模組（先讀完這段）

IDOR 需要理解程式邏輯意圖才能判斷，是所有模組裡誤判率天生最高的一種。**永遠固定為 tier 2**，不可調成 tier 1。輸出的 evidence 與呈現文字都必須清楚表達「這只是模式比對，不是確診」——無論是正則版還是 AST 版，都只是**語法層級**的模式比對，不是真正理解程式邏輯意圖。AST 能看懂「這裡有一個 if 判斷式」，但看不懂「這個判斷式是不是真的在驗證擁有權」（例如 `if (Math.random() > 0.5)` 在語法上一樣是個 if，AST 不會知道它跟權限完全無關）。這個限制不會因為換成 AST 而消失，做測試或跟人解釋時要記得講清楚。

## 函式簽名（這個介面是長期契約，內部實作改變不影響它）

```js
function idorDetector(code) {
  // code: string
  // 回傳: Finding[]
}
```

**這個函式簽名——輸入一個 code 字串、輸出 Finding[]——不受內部實作影響。這是刻意設計，讓外部呼叫端（orchestrator）完全不需要因為內部邏輯改變而修改任何東西。**

## 架構：正則保底 + AST 疊加

```
idorDetector(code)
   │
   ├─ 1. 一定先跑 idorDetectorRegex(code)  ← 保底,零依賴,任何環境都能動
   │
   ├─ 2. resolveAcorn() 檢查全域是否存在可用的 acorn 物件
   │        (瀏覽器端由 HTML 的 <script src="...acorn CDN..."> 載入後掛在 window.acorn)
   │
   ├─ 3a. 找不到 acorn(CDN載入失敗/離線/未引入)
   │        → 直接回傳正則版結果,靜默退化,不報錯、不影響其他功能
   │
   └─ 3b. 找到 acorn → 跑 idorDetectorAst(code, acornRef)
            ├─ 解析失敗(語法錯誤,例如貼上的其實是 Python)→ ok:false → 退回正則版結果
            └─ 解析成功 → 回傳 AST 版結果,取代正則版結果(不是疊加兩份,避免重複回報)
```

**為什麼要這樣設計，而不是直接全面換成 AST：**
- 正則版是保底，任何情況下都能動，不會因為 CDN 掛掉或使用者離線就讓這項檢測完全失效
- AST 版是加值，載入失敗就優雅降級，使用者不會看到任何錯誤訊息
- 兩者共用同一個對外函式簽名，orchestrator 跟其他 7 個模組完全不需要知道這個模組內部在做什麼

## 正則版（保底邏輯）

```js
const IDOR_PATTERN = /function\s+\w+\s*\([^)]*\b(id|userId|req)\b[^)]*\)\s*{([^}]{0,300})}/g;
const DB_CALL_PATTERN = /\.(find|get|query|select|delete|update)\s*\(/i;
const AUTH_CHECK_PATTERN = /\b(owner|user\.id|session|auth|permission|role)\b/i;
```

判斷邏輯：函式參數包含 `id`/`userId`/`req`，函式體（最多抓 300 字元內）裡有資料庫呼叫關鍵字，但**沒有**任何權限比對關鍵字 → 判定為疑似缺漏。

**已知限制（誠實記錄，這正是需要 AST 版的理由）：**
- 只涵蓋 `function xxx(){}` 宣告語法，**不支援箭頭函式**（`const f = (req,res)=>{...}`）、不支援 class method
- 函式體只抓前 300 字元，長函式後半部不會被分析到
- 只看關鍵字是否「出現」，不理解實際邏輯關係——**例如 `// TODO: check owner` 這種註解裡出現 `owner` 字樣，會被誤判為「有做權限檢查」而放過**

## AST 版（Acorn 疊加分析）

用 Acorn 把程式碼解析成語法樹，遞迴收集三種函式節點型態：`FunctionDeclaration`（具名函式）、`FunctionExpression`（函式表達式）、`ArrowFunctionExpression`（箭頭函式）。對每個函式節點：

1. 檢查參數列表裡是否有 `id`/`userId`/`req`（比對 `Identifier` 節點的 `name`，不是字串比對）
2. 在函式體子樹裡找是否存在「資料庫呼叫」節點（`CallExpression`，`callee` 是 `xxx.find(...)` 這類 `MemberExpression`，且方法名稱屬於白名單）
3. 在函式體子樹裡找是否存在「權限比對相關」節點（`Identifier` 名稱屬於 `owner`/`session`/`auth`/`permission`/`role`，或 `MemberExpression` 的屬性名稱符合、或為 `.user`）

有資料庫呼叫、且**完全沒有**權限比對節點 → 判定為疑似缺漏。

**這解決了正則版的兩個已知限制：**
- **箭頭函式現在能被正確偵測到**——因為 AST 直接辨識 `ArrowFunctionExpression` 這個節點類型，不需要靠字面上「有沒有出現 `function` 這個字」
- **註解陷阱不再誤判**——因為判斷邏輯是走訪語法樹上的節點類型（`Identifier`/`MemberExpression`），註解在 AST 裡根本不是可執行程式碼的一部分，不會被當成「有做權限檢查」

## visualData：供 M8 視覺化展示使用的選用欄位

AST 版偵測到疑似 IDOR 時，除了標準的 Finding 欄位，還會額外附加一個 `visualData` 物件，讓 M8（finding-renderer）可以畫出「合法使用者 vs 攻擊者」的對比展示，而不是只有一段純文字說明：

```js
{
  tier: 2, category: '...', name: '...', kind: 'possible_idor', evidence: '...',
  visualData: {
    functionName: 'getOrder',       // 函式名稱,箭頭函式賦值寫法時會是 null(節點本身沒有名稱)
    idParamName: 'orderId',         // 用於查詢的參數名,優先取 id/userId 語意明確的,找不到則取第一個參數
    dbCall: { object: 'db', method: 'find' }  // 資料庫呼叫的物件與方法名,找不到是 null
  }
}
```

**這個欄位只有 AST 版會填，正則版完全沒有**（正則沒有能力解析出結構化的變數名，只能做整段字串比對）。呼叫端（M8）必須把 `visualData` 當成可能不存在、也可能部分欄位是 `null` 的選用資料，永遠要有 fallback 邏輯，不能假設它一定存在或欄位齊全。

萃取邏輯見 `extractDbCallInfo`（找資料庫呼叫的物件/方法名）與 `extractIdParamName`（找查詢用的識別碼參數名），兩者都是遞迴走訪 AST 子樹，拿不到就回傳 `null`，不強行猜測。

## Acorn 從哪裡來、載入方式

由呼叫端（`reference/index.html`）在 `<head>` 用 CDN 載入：

```html
<script src="https://cdn.jsdelivr.net/npm/acorn@8.11.3/dist/acorn.min.js" defer></script>
```

- 用 `defer` 是為了不阻塞頁面渲染。因為 `resolveAcorn()` 只會在使用者**點擊掃描按鈕時**才被呼叫（不是頁面剛載入時），所以即使 `defer` 腳本執行時機晚於主邏輯 `<script>` 的同步執行，實際使用時序上沒有問題——等使用者按下掃描按鈕，`defer` 腳本早已執行完畢
- 只在使用者瀏覽器本機執行語法解析，**不會把貼上的程式碼傳送到任何伺服器**，這點在 HTML 的註解裡也有說明，避免使用者誤解「載入外部函式庫」等於「資料外送」

`resolveAcorn()` 依序檢查 `window.acorn` 與 `globalThis.acorn`，找不到就回傳 `null`（不拋例外）。

## 明確不在你職責範圍內的東西

- 判斷函式是否真的有邏輯漏洞（本模組只能做語法層級的模式比對，AST 也一樣做不到真正的語意理解，見上方「先讀完這段」）
- 其他語言的 IDOR 偵測（Acorn 只認得 JavaScript/TypeScript，其他語言的程式碼丟進去解析會失敗，此時 `idorDetectorAst` 會回傳 `ok:false`，自動退回正則版結果——正則版本身也只是字面樣式比對，對其他語言的涵蓋同樣有限，這是已知邊界，不是這次要解決的問題）

## 測試要求

測試分三層，`test/idor-detector.test.js` 已包含完整範例：

1. **正則版本身**（`idorDetectorRegex`）：True positive、True negative、多函式只回報有問題的那個、箭頭函式偵測不到（記錄已知限制）、空輸入
2. **AST 版本身**（`idorDetectorAst`，需要傳入 acorn 物件）：具名函式仍被偵測到、**箭頭函式應被偵測到**（核心驗證項目）、function expression 賦值寫法、有權限檢查不誤判、**註解陷阱不應讓 AST 版誤判為安全**（核心驗證項目，用來對比正則版會誤放過）、非法 JS（如 Python）應優雅回傳 `ok:false` 而非拋例外
3. **對外介面整合測試**（`idorDetector`）：
   - `resolveAcorn()` 找不到 acorn 時（未安裝/CDN失敗情境），應完全等同正則版行為
   - `globalThis.acorn` 存在時，應改用 AST 版且涵蓋範圍變廣
   - 有 acorn 但輸入非法 JS 時，應優雅退回正則版結果，不拋例外

測試環境本身需要 `acorn` 這個 npm 套件才能測試 AST 相關邏輯（見專案根目錄 `package.json`），但**若沒有安裝，測試會自動偵測不到 acorn，改以「Acorn 不可用時的退化行為」驗證，不會讓整組測試失敗**——這正是在模擬瀏覽器端 CDN 載入失敗的真實情境。這是本專案唯一一個測試依賴外部套件的模組，其餘 7 個模組完全零依賴。

## 對照基準

- 正則版邏輯對照 `reference/index__1_.html`（原始未拆分版本）搜尋 `idorPattern`
- 完整雙層架構的實際運作對照 `reference/index.html`（現行正式版本），該檔案 `<head>` 有 Acorn CDN 載入的完整說明註解
