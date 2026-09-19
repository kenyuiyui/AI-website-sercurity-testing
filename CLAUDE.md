# CLAUDE.md — 給 AI 協作者的專案說明

純前端、零後端的靜態資安檢查工具:使用者貼上（或拖入）程式碼，瀏覽器內用正則／AST 比對常見的 AI 產出資安問題。GitHub Pages 直接發布 repo 根目錄。介面與文案一律繁體中文。

## 改東西前先知道

- **改完一律跑 `npm run verify`**，全綠才算完成。它會跑規則回歸、行為快照、單檔版同步檢查。
- 行為快照（`eval/findings-snapshot.json`）記錄每個驗證樣本的掃描結果。規則改動是刻意的 → 檢查 verify 印出的差異合理後，`npm run verify -- --update`。**不要為了讓測試通過而更新快照。**
- **不要手改 `referencesingle/index.html`**，它由 `npm run build:single` 產生。
- 修正紀錄寫在 `docs/CHANGELOG.md`；程式碼旁只留一行 `為什麼:…(背景見 docs/CHANGELOG.md)`。
- 報告數字（README「準確度驗證」、`eval/EVAL_REPORT.md`）只在跑過 `npm run eval` / `eval:ast` 後依實際輸出更新。

## 架構

```
index.html                  結構(HTML)+ <script> 載入順序;不放 CSS/邏輯
assets/style.css            全部樣式,色彩只用 :root 變數(深色預設,html[data-theme=light] 淺色)
assets/app.js               畫面層:事件、讀檔、結果互動。不寫偵測規則
modules/*.js                偵測模組(瀏覽器全域腳本 + Node module.exports 雙用)
modules/scan-orchestrator.js 掃描流程唯一來源:scanCode(code) / scanFiles(files)
modules/finding-renderer.js 唯一產生結果 HTML 的地方(M8)
scripts/build-single.js     index.html → referencesingle/index.html(內嵌本機 css/js)
scripts/verify.js           一鍵驗證;snapshot.js / ui-smoke.js 為其子步驟
eval/                       驗證案例與報告(見 eval/CASE_FORMAT.md)
```

資料流：`app.js` → `scanCode` / `scanFiles`（依序跑各偵測模組、補行號、組語言提示）→ `findingRenderer(findings, caveat)` → `#results`。`eval/eval-orchestrator.js` 呼叫同一個 `scanCode`，所以驗證結果＝上線行為。

## Finding 契約

```js
{
  tier: 1 | 2 | 3,        // 1=發現(高信心) 2=建議複查 3=資訊提示
  category, name,         // 顯示用標題
  kind: 'snake_case',     // 對應 FINDING_GUIDE 說明文字與 VALID_KINDS
  evidence: string,       // 技術細節;金鑰必須先 maskMatch() 遮罩
  index?: number,         // 選填:在原始碼中的字元位置
  match?: string,         // 選填:原始片段,供定位用。可能含未遮罩金鑰 → 絕不可輸出到畫面
  visualData?: object,    // 選填:畫面示意用
  // 以下由 scan-orchestrator 補上
  line?, start?, end?, filename?
}
```

## 常見任務

**新增一條規則（既有模組）**：改 `modules/<模組>.js` → 在 `eval/run_rule_regression.js` 加「應命中／不應命中」各至少一例 → `npm run verify`，確認快照差異只有預期的樣本 → `--update`。

**新增 kind**：模組產生 Finding → `finding-renderer.js` 的 `FINDING_GUIDE` 加 `plain` + `handoff` → `eval/case-loader.js` 的 `VALID_KINDS` 加上。verify 會檢查這兩處。

**新增偵測模組**：
1. `modules/<name>.js`，檔尾照其他模組加 `module.exports`
2. `modules/scan-orchestrator.js`：Node 清單與 `getSingleFileDetectors()` 各加一行
3. `index.html`：在 `scan-orchestrator.js` 之前加 `<script src="modules/<name>.js">`
4. README 模組對照表、「查得到什麼」分頁（`index.html` Tab 2）與 README「能查什麼」同步

**改畫面**：HTML 在 `index.html`、樣式在 `assets/style.css`、互動在 `assets/app.js`、結果卡片結構在 `finding-renderer.js`。深淺兩種主題與手機寬度（390px）都要看。

**新增驗證案例**：`eval/cases/*.txt`，格式見 `eval/CASE_FORMAT.md`；真實事件改寫的放 `eval/reference_cases/`（不計入統計）。

## 安全與隱私底線

- 貼上／拖入的內容只在瀏覽器記憶體處理，不可新增任何網路請求、分析追蹤或儲存使用者程式碼的行為。
- 所有插入 HTML 的文字經過 `escapeHtml`（renderer）或以 `.value` / `textContent` 賦值（app.js）。
- 外部依賴只有 Acorn 與 acorn-jsx（CDN，選用）；載入失敗必須靜默退回正則版。

## 指令

| 指令 | 用途 |
|---|---|
| `npm install` | 第一次執行，安裝 acorn（AST 版測試用） |
| `npm run verify` | 改完必跑 |
| `npm run build:single` | 重新產生單檔版 |
| `npm run eval` / `eval:ast` / `eval:fp` | 準確度統計（更新報告數字時用） |
| `npm run test:ui` | 畫面冒煙測試（需 `npm i -D playwright`） |

本機預覽：`python -m http.server 8000` 後開 `http://localhost:8000`；或直接雙擊 `referencesingle/index.html`。
