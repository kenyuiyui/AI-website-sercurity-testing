# 看見 AI 網頁的程式過錯

> 錯與過，不該是我的鍋——貼上程式碼，掃描常見的 AI 產出資安問題。

純前端、零安裝的靜態資安檢查工具，專為「用 AI 生成程式碼、不熟悉資安」的人設計。貼上程式碼、拖入檔案或貼上 GitHub 網址，幾秒內看到白話的問題說明與處理步驟。程式碼只在你的瀏覽器裡處理，頁面以 CSP 禁止背景外傳。

**Live Demo：** https://kenyuiyui.github.io/AI-website-sercurity-testing/

---

## 這是什麼

用 AI 工具（v0、Lovable、Bolt、Cursor 等）生成程式碼時，容易在無形中留下漏洞——明文金鑰、缺少權限驗證、不安全的雜湊等。這個工具讓你部署前貼上程式碼快速自查一輪。

**不取代正式資安審查**，只抓最常見的低垂果實，並誠實標示「這裡需要你自己判斷」和「這件事做不到」。

- **適合**：不熟資安術語的個人開發者、學生、行銷/營運人員自查
- **不適合**：需要正式稽核／CI/CD 整合／多人協作的團隊 → 用 Gitleaks、TruffleHog、SonarQube 等專業工具

---

## 快速開始

**直接使用：** 打開 https://kenyuiyui.github.io/AI-website-sercurity-testing/ 即可，不需要安裝任何東西。

**離線使用：** 下載 `referencesingle/index.html`，雙擊開啟（所有程式、字型都已內嵌，斷網也能用）。

**本機預覽拆分版：** 需要一個本機網頁伺服器（例如 `python -m http.server 8000` 後開 `http://localhost:8000`）；直接雙擊 `index.html` 會被瀏覽器的 `file://` 限制擋住。

部署到 GitHub Pages：repo 根目錄就是發布內容（`index.html` + `assets/` + `vendor/` + `modules/`），Pages 發布來源設為 `main` 分支根目錄即可。

---

## 檔案結構

```
.
├── index.html                # 拆分版主頁(GitHub Pages 發布的就是這份):HTML 結構、CSP、載入順序
├── assets/
│   ├── style.css              # 全部樣式
│   ├── fonts/                 # JetBrains Mono 字型(本站提供,不連外部字型服務)
│   ├── theme-init.js          # 首次繪製前套用深淺色主題
│   ├── github-import.js       # 從公開 GitHub 專案匯入檔案
│   └── app.js                 # 畫面層(輸入、讀檔、結果互動、匯出報告)
├── vendor/                   # acorn / acorn-jsx 本地版本與第三方授權
├── modules/                  # M1~M12 偵測模組 + scan-orchestrator(掃描流程唯一來源)
├── referencesingle/
│   └── index.html            # 單檔版(由 scripts/build-single.js 產生，請勿手改)
├── scripts/                  # build-single(產生單檔版)、verify(一鍵驗證)與其子步驟
├── eval/                     # 準確度驗證報告、測試案例、行為快照
├── docs/
│   ├── CHANGELOG.md           # 變更與規則修正紀錄
│   └── USER_TEST_KIT.md       # 真人測試任務腳本與觀察紀錄表
├── CLAUDE.md                  # 給 AI 協作者的專案說明(架構、契約、常見任務)
└── package.json               # 驗證用指令(無任何相依套件)
```

### 修改與驗證

**你的電腦不需要安裝 Node.js。** 驗證在兩個地方跑：

- **Claude 修改時**：在雲端工作區跑 `npm run verify`，全部通過才寫回資料夾
- **push 到 GitHub 後**（若已放入 `.github/workflows/verify.yml`）：GitHub 自動跑同一套驗證，在 commit 旁顯示通過或失敗

`verify` 包含：模組清單一致、每種問題都有白話說明、規則回歸測試、所有樣本的行為快照比對、匯出報告不含金鑰與原始碼、GitHub 匯入解析、單檔版同步，以及（有 playwright 時）瀏覽器畫面驗收。規則是刻意調整、快照差異也確認合理時，才用 `npm run verify -- --update` 更新快照。

單檔版是由拆分版產生的，**只改 `index.html`、`assets/`、`vendor/`、`modules/`**，改完重新產生 `referencesingle/index.html`（`npm run build:single`）。

模組對照表：M1 key-detector（明文金鑰）／M2 jwt-analyzer（JWT/Supabase）／M3 hash-detector（弱雜湊）／M4 secret-heuristics（自訂密鑰啟發式）／M5 csp-detector（CSP 缺失）／M6 idor-detector（IDOR）／M7 language-detector／M8 finding-renderer（結果呈現、報告）／M9 sql-injection-detector／M10 insecure-deserialize-detector／M11 field-masking-consistency-detector（多檔案模式）／M12 rate-limit-coverage-detector；scan-orchestrator 負責依序呼叫並合併結果。

---

## 能查什麼、不能查什麼

**「工具沒標記」不代表「沒問題」。**

### 查得到

- 已知格式的明文 API 金鑰（OpenAI／Anthropic／Gemini／Line／AWS），並依上下文分辨 Firebase 設定這類「本來就可公開」的值
- HTML／框架設定檔是否有 CSP
- 密碼是否用 MD5／SHA1 這類弱雜湊（含 Python `hashlib.new('md5')` 再 `.update(password)` 的兩段式寫法）
- Supabase／JWT 金鑰，區分 `anon`（可公開）與 `service_role`（絕不可公開）
- SQL Injection（字串拼接、模板插值、f-string、Python `%` 格式化）
- 不安全的反序列化／動態執行（eval／exec／pickle／yaml.load，含 Python `exec()` 格式化字串注入）
- 疑似缺少擁有權驗證（IDOR），含 Express 路由 `app.get(path, (req, res) => {...})` 寫法
- 多檔案模式：同一敏感欄位在不同檔案的遮罩不一致、路由缺少速率限制

### 做不到 / 僅供保守提示

- 字串拆分組合而成的金鑰
- 協定層級漏洞、需動態執行才能確認的邏輯漏洞
- IDOR——只是模式比對，主要針對 JS／Express，AST 解析失敗時降級為涵蓋率較低的正則版
- 疑似自訂密鑰、疑似內部端點 URL、環境變數明文 fallback——無固定格式，誤判率較高
- 打包壓縮過的程式碼（例如「檢視網頁原始碼」取得的）：金鑰檢查仍有效，權限、SQL 這類邏輯檢查幾乎無法判斷
- 私人 GitHub 專案無法直接匯入（請下載後用拖放或開啟檔案）；工具不會主動讀取你電腦裡的檔案
- 後端是否真的驗證了前端送出的密鑰／權杖——這是後端邏輯，工具只看得到你貼的這份程式碼
- 雲端 IAM 權限設定完全不在範圍內

---

## 對照 OWASP Top 10:2025

只列有涵蓋到的項目，其餘 5 項（A03 供應鏈、A06 不安全設計、A08 軟體完整性、A09 日誌告警、A10 例外處理）完全不涉及——這些需要看依賴清單、架構、CI/CD 或錯誤處理邏輯，超出「掃單一檔案片段」的能力範圍。

| 分類 | 涵蓋程度 | 對應模組 |
|---|---|---|
| A01 – Broken Access Control | ✅ 完整 | M6 idor-detector |
| A05 – Injection | ✅ 完整 | M9 sql-injection-detector、M10 insecure-deserialize-detector |
| A02 – Security Misconfiguration | 🟡 部分（僅 CSP 缺失） | M5 csp-detector |
| A04 – Cryptographic Failures | 🟡 部分（僅弱雜湊） | M3 hash-detector |
| A07 – Authentication Failures | 🟡 部分（僅 JWT／Supabase 角色判斷） | M2 jwt-analyzer |

框架外的自訂規則：M1／M4（金鑰偵測）、M11（欄位遮罩一致性）、M12（速率限制涵蓋率）。

---

## 常見問題 FAQ

### Firebase 的 apiKey 會被當成金鑰外洩嗎？

不會。`AIzaSy` 開頭的字串同時可能是 Firebase 設定值（設計上可公開）或 Gemini／Google API 金鑰（外洩要立刻撤銷）。工具會看上下文判斷：

- 以 `apiKey` 屬性寫在 Firebase 設定裡（附近有 `authDomain`、`projectId`、`firebaseapp.com`、`initializeApp(` 等特徵）→ 「請你確認」：本身可公開，但要確認 Firebase Security Rules
- 其他情況（例如 `GEMINI_API_KEY = "AIzaSy..."`、傳給 Gemini SDK）→ 「需要處理」：當成外洩金鑰

同一個值只會回報一次。這是依上下文的推斷，極少數寫法仍可能判斷錯誤，看到時可對照上面兩點確認。

### 為什麼有些結果標成「參考」？

整個專案一起檢查時，測試檔、範例資料、說明文件裡常有刻意寫的漏洞範例或假金鑰。工具會：

- **測試／範例檔**（目錄或檔名含 test、spec、fixture、sample、mock、e2e 等）裡的發現 → 「參考」，並註明原因
- **明顯的假金鑰**（含 test／example 字樣、`abcdefgh`、`12345678` 這類連續字元）→ 「參考」
- **看起來是真的金鑰，即使在測試檔裡也維持「需要處理」**——公開專案的測試檔外洩一樣是外洩
- 說明文字、註解、字串裡「提到」`eval()`、`pickle.loads()` 等函式，不會被當成真的呼叫

### 貼上「檢視網頁原始碼」的內容，結果可靠嗎？

一半可靠。從已上線網站拿到的通常是打包壓縮過的程式碼：**金鑰外洩的檢查仍然有效**（金鑰字串壓縮後不變），但權限、SQL 這類要看懂程式邏輯的檢查幾乎無法判斷。工具偵測到壓縮程式碼時會在結果最上方明確提醒。想完整檢查，請用 GitHub 匯入或原始檔。

### 掃到別人網站（例如公開網頁）的原始碼，跳出金鑰警示，代表那個網站真的外洩了嗎？

大機率是，但仍需人工核對：
- 看到 tier 1「明文金鑰」且不是 Firebase／Supabase `anon` 這類「設計上就該公開」的類型，通常代表真的外洩，建議透過負責任揭露管道通知該網站維護者，而不是自行使用或散布。
- CSP 缺失提示只代表**這段 HTML 原始碼裡沒看到 CSP meta 標籤**，不代表該網站真的沒有 CSP——許多正式站台會在 CDN／反向代理層級（如 Cloudflare）用 HTTP header 設定 CSP，工具看不到伺服器回應的 header，只能看到你貼上的原始碼文字。

### 工具說「疑似 Line Bot Access Token」，但我不確定是不是真的

這條規則本身誤判率較高，工具訊息裡也誠實承認：判斷邏輯只是「這串字元夠長、字元集合符合 base64」，沒有 LINE 官方公開的固定格式可比對，一段 base64 編碼的圖片雜湊、簽章值都可能被誤標。需要你自行核對變數名稱與使用情境。

---

## 準確度驗證

用貼近真實世界的案例做了驗證，數字要一起看，不能只看 AST 版：

| 驗證方向 | 案例數 | 正則保底版 | AST 完整版 |
|---|---|---|---|
| 真實案例命中率 | 20 個（真實蒐集，含 SecurityEval 學術資料集；共 21 個應偵測項目） | 95.2%（20/21） | 100%（21/21） |
| 誤判率 | 29 個（含邊界值測試） | 0% | 0% |

語法分析函式庫（Acorn、acorn-jsx）現在放在本站 `vendor/`，網頁上一律使用 AST 完整版。正則保底版仍是程式碼含 TypeScript 型別語法、語法分析無法解析時的退路；它唯一的漏判是 `legacy-tp-002`：函式裡出現 `session` 字樣就會被當成「已檢查權限」，分辨不出只是登入檢查、而非擁有權檢查，這是正則能力的天花板。

```bash
npm run eval         # 正則保底版
npm run eval:ast     # AST 完整版(使用 vendor/ 內與網頁相同的檔案)
```

`eval-orchestrator.js` 與上線版呼叫同一個 `modules/scan-orchestrator.js`，驗證結果就是上線行為。新增驗證案例只需在 `eval/cases/` 新增 `.txt` 檔案，格式見 `eval/CASE_FORMAT.md`。`eval/reference_cases/` 是依真實事件改寫的參考案例，刻意不計入統計（避免改寫帶入預期偏誤），細節見該資料夾 README。

樣本規模仍有限（相較 Gitleaks、TruffleHog 等工具的數千至數萬案例），歡迎提交真實案例協助擴充。

---

## 使用小技巧

- **GitHub 專案**：把專案網址貼到最上面的欄位按「匯入」，自動抓取程式碼檔案並檢查（限公開專案；可貼子資料夾網址如 `…/tree/main/src` 縮小範圍）
- **本機檔案**：拖進程式碼框，或按「開啟檔案」；一次拖入多個檔案會自動切換成多檔案模式
- `Ctrl+Enter`（Mac：`⌘ Enter`）直接檢查
- 結果最上方有一句話結論與處理步驟；每筆結果標有行號，點一下會在輸入框選取那一段
- 「複製全部修正指令」：整理成一段，直接貼給 AI 修改
- 「匯出報告」：可複製、下載 .md 或（手機）分享，報告**不含原始程式碼，金鑰只顯示前後幾碼**
- 分頁可直接分享連結：`#boundary`（查得到什麼）、`#privacy`（隱私說明）、`#howto`（怎麼拿到程式碼）

---

## 技術細節

- **純前端，零依賴後端**：程式碼只在瀏覽器記憶體處理，不上傳、不儲存。
- **CSP 自我保護**：頁面設定 `default-src 'none'`，只允許載入本站檔案；對外連線只允許 GitHub 匯入用的 `api.github.com` 與 `raw.githubusercontent.com`（只讀取）。單檔版以 sha256 雜湊放行內嵌的程式與樣式。
- **零外部資源**：字型（JetBrains Mono，OFL）與語法分析函式庫（Acorn、acorn-jsx，MIT）都放在本站，授權見 `vendor/THIRD_PARTY_LICENSES.md`。
- **正則保底 + AST 疊加**：M6 用 Acorn 做語法樹分析，搭配 acorn-jsx 支援 JSX；純 TypeScript 語法（`interface`、泛型等）仍無法解析，會退回正則版並在結果中提示。
- **多檔案模式**：額外比對「同一個敏感欄位在不同檔案的輸出是否遮罩不一致」（M11）。
- **GitHub 匯入**：每次匯入呼叫 2 次 GitHub API（未登入每小時上限 60 次，約 30 次匯入），檔案內容從 raw.githubusercontent.com 下載；一次最多 60 個檔案，優先挑 API、設定、資料庫相關路徑。

---

## 授權

[MIT License](LICENSE)

## 作者

kenyuiyui ｜ [GitHub 專案頁面](https://github.com/kenyuiyui/AI-website-sercurity-testing)
