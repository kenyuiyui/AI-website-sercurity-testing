# CLAUDE.md — 給 AI 協作者的專案說明

純前端、零後端的靜態資安檢查工具：使用者貼上程式碼、拖入檔案或貼 GitHub 網址，瀏覽器內用正則／AST 比對 AI 產出程式碼常見的資安問題。GitHub Pages 直接發布 repo 根目錄。介面與文案一律繁體中文，主要使用者是**不懂程式的人**（行銷、營運、學生），用字以他們看得懂為準。

## 協作方式（重要）

- 專案擁有者的電腦**沒有 Node.js，也不使用 Claude CLI**。Claude 只透過讀寫指定資料夾協作；**commit / push 一律由擁有者手動進行**，Claude 不做 git 操作。
- 修改流程：在雲端工作區複製一份 → 修改 → 跑 `npm run verify`（含畫面驗收時需 playwright 與 Chromium）→ **全部通過才寫回資料夾**。
- 寫回時保留 CRLF 換行（擁有者是 Windows 環境）。
- 動手前先重新列出並讀取資料夾，不要依賴舊的副本。

## 改東西前先知道

- 行為快照（`eval/findings-snapshot.json`）記錄每個驗證樣本的掃描結果。規則改動是刻意的 → 檢查 verify 印出的差異合理後，`npm run verify -- --update`。**不要為了讓測試通過而更新快照。**
- **不要手改 `referencesingle/index.html`**，它由 `npm run build:single` 產生（含 CSP 雜湊，手改會讓腳本被瀏覽器擋下）。
- **改了任何 `assets/`、`modules/`、`vendor/` 的 JS/CSS 後執行 `npm run build:single`**：它會先更新 `index.html` 裡的檔案指紋（`?v=…`）與頁尾版本號，再產生單檔版。指紋過期 verify 會失敗。不要手改 `?v=` 或版本號。
- 修正紀錄寫在 `docs/CHANGELOG.md`；程式碼旁只留一行 `為什麼:…(背景見 docs/CHANGELOG.md)`。
- 報告數字（README「準確度驗證」、`eval/EVAL_REPORT.md`）只在跑過 `npm run eval` / `eval:ast` 後依實際輸出更新。

## 架構

```
index.html                    結構 + CSP + <script> 載入順序;不放 CSS/邏輯/行內腳本
assets/style.css              全部樣式,色彩只用 :root 變數(深色預設,html[data-theme=light] 淺色)
assets/fonts/                 JetBrains Mono latin woff2(OFL)
assets/theme-init.js          首次繪製前套用主題(CSP 不允許行內腳本,所以獨立成檔)
assets/github-import.js       公開 GitHub 專案匯入(api.github.com 取清單、raw.githubusercontent.com 取內容)
assets/app.js                 畫面層:事件、讀檔、結果互動、匯出。不寫偵測規則
vendor/                       acorn、acorn-jsx 本地打包版(瀏覽器全域 acorn / acornJsx),授權見 THIRD_PARTY_LICENSES.md
modules/*.js                  偵測模組(瀏覽器全域腳本 + Node module.exports 雙用)
modules/source-mask.js        分辨程式碼／字串／註解／正則;「執行程式碼」類規則只對真正的程式碼報警
modules/scan-orchestrator.js  掃描流程唯一來源:scanCode(code, {filename}) / scanFiles(files);另含檔案情境規則(測試檔、假金鑰、副檔名、去重複)
modules/finding-renderer.js   結果 HTML(依問題類型分組)、白話標題(PLAIN_TITLES)、結論與步驟(buildVerdict)、報告(buildReportMarkdown)
scripts/stamp-version.js      index.html 本地 CSS/JS 網址加內容指紋 ?v=…、寫入頁尾版本號(避免 GitHub Pages 快取造成新舊版混用)
scripts/build-single.js       index.html → referencesingle/index.html(內嵌 css/js/字型,改寫 CSP 為 sha256)
scripts/verify.js             一鍵驗證;snapshot.js / check-report.js / ui-smoke.js 為其子步驟
eval/load-ast.js              讓 Node 使用 vendor/ 內與網頁相同的 acorn(require 它 = AST 版)
eval/                         驗證案例與報告(見 eval/CASE_FORMAT.md)
docs/USER_TEST_KIT.md         真人測試任務腳本(擁有者執行,結果回饋給 Claude)
```

資料流：`app.js` → `scanCode` / `scanFiles`（依序跑各偵測模組、補行號、產生 notices）→ `findingRenderer(findings, caveat, notices)` → `#results`。`eval/eval-orchestrator.js` 呼叫同一個 `scanCode`，所以驗證結果＝上線行為。

## 隱私與 CSP（不可退步）

- 貼上／拖入／匯入的內容只在瀏覽器記憶體處理。不可新增任何網路請求、分析追蹤、外部 CDN／字型，或儲存使用者程式碼。
- `index.html` 的 CSP：`default-src 'none'`，腳本／樣式／字型只允許 `'self'`，`connect-src` 只允許 GitHub 匯入的兩個網域。放寬任何一項都要先問擁有者。
- 不可加行內 `<script>`、`style="…"` 屬性或 `on*=` 事件屬性（CSP 會擋）；樣式用 class，事件用 `addEventListener`。
- 所有插入 HTML 的文字經過 `escapeHtml`（renderer）或以 `.value` / `textContent` 賦值（app.js）。
- 內嵌進單檔版的 JS 不可含 `</script` 或 `<!--`（build 會報錯）。

## Finding 契約

```js
{
  tier: 1 | 2 | 3,        // 畫面顯示為 需要處理 / 請你確認 / 參考
  category, name,         // name 是技術名稱,顯示為小字副標;主標題用 PLAIN_TITLES
  kind: 'snake_case',     // 對應 FINDING_GUIDE(說明+修正指令)、PLAIN_TITLES(白話標題+一句話處理)、VALID_KINDS
  evidence: string,       // 技術細節;金鑰必須先 maskMatch() 遮罩
  index?: number,         // 選填:在原始碼中的字元位置
  match?: string,         // 選填:原始片段,供定位與去重複。可能含未遮罩金鑰 → 絕不可輸出到畫面或報告
  visualData?: object,    // 選填:畫面示意用
  // 以下由 scan-orchestrator 補上
  line?, start?, end?, filename?,
  context?: 'placeholder' | 'test' | 'test-real-secret',  // 依檔案情境調整過層級時的原因
  originalTier?
}
```

notices（本次檢查的限制）：`{ id, level: 'warn' | 'info', text }`，由 `scan-orchestrator.buildNotices` 產生，畫面放在結果最上方。

## 常見任務

**規則是否該看字串？** 金鑰、SQL 規則要看字串內容；「呼叫某個危險函式」類規則必須用 `resolveCodeMask` 只看真正的程式碼（見 M3、M10 寫法），否則說明文字、測試資料都會誤報。

**整專案回歸**：`scripts/self-scan.js` 掃描本專案自己，verify 要求「需要處理 = 0」。本專案的測試或說明需要放「看起來像真的」金鑰時，請拆開組合（`'sk-proj-' + '…'`），否則會被正確地判為外洩。

**新增一條規則（既有模組）**：改 `modules/<模組>.js` → 在 `eval/run_rule_regression.js` 加「應命中／不應命中」各至少一例 → `npm run verify`，確認快照差異只有預期的樣本 → `--update`。

**新增 kind**：模組產生 Finding → `finding-renderer.js` 的 `FINDING_GUIDE`（plain + handoff）與 `PLAIN_TITLES`（title + action）→ `eval/case-loader.js` 的 `VALID_KINDS`。verify 會檢查這三處。

**新增偵測模組**：
1. `modules/<name>.js`，檔尾照其他模組加 `module.exports`
2. `modules/scan-orchestrator.js`：Node 清單與 `getSingleFileDetectors()` 各加一行
3. `index.html`：在 `scan-orchestrator.js` 之前加 `<script src="modules/<name>.js">`
4. README 模組對照表、「查得到什麼」分頁（`index.html` Tab 2）與 README「能查什麼」同步

**改畫面**：HTML 在 `index.html`、樣式在 `assets/style.css`、互動在 `assets/app.js`、結果卡片／摘要／報告在 `finding-renderer.js`。驗收標準在 `scripts/ui-smoke.js`：1280×720 與 390×844 首屏不捲動就看得到輸入框和「看範例」、零非預期對外請求、無 JS／CSP 錯誤。深淺兩種主題都要看。

**更新 vendor 函式庫**：雲端 `npm i acorn@x acorn-jsx@y esbuild`，acorn 用 esbuild 壓縮；acorn-jsx 以 `--alias:acorn=<shim: module.exports = globalThis.acorn>` 打包成 IIFE 設定 `globalThis.acornJsx`。更新 `vendor/THIRD_PARTY_LICENSES.md` 版本號。

**新增驗證案例**：`eval/cases/*.txt`，格式見 `eval/CASE_FORMAT.md`；真實事件改寫的放 `eval/reference_cases/`（不計入統計）。

## 指令（在雲端工作區或 CI 執行）

| 指令 | 用途 |
|---|---|
| `npm run verify` | 改完必跑，全綠才寫回 |
| `npm run build:single` | 更新檔案指紋與版本號，並重新產生單檔版 |
| `npm run eval` / `eval:ast` / `eval:fp` | 準確度統計（更新報告數字時用） |
| `npm run test:ui` | 畫面驗收（需 playwright；可用 `CHROMIUM_PATH` 指定瀏覽器） |

本專案沒有 npm 相依套件；`npm install` 不需要執行。
