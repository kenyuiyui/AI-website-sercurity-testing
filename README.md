# 看見 AI 網頁的程式過錯

> 錯與過，不該是我的鍋——貼上程式碼，掃描常見的 AI 產出資安問題。

純前端、零安裝的靜態資安檢查工具，專為「用 AI 生成程式碼、不熟悉資安」的人設計。貼上程式碼，幾秒內看到常見問題提示。

**Live Demo：** https://kenyuiyui.github.io/AI-website-sercurity-testing/

---

## 這是什麼

用 AI 工具（v0、Lovable、Bolt、Cursor 等）生成程式碼時，容易在無形中留下漏洞——明文金鑰、缺少權限驗證、不安全的雜湊等。這個工具讓你部署前貼上程式碼快速自查一輪。

**不取代正式資安審查**，只抓最常見的低垂果實，並誠實標示「這裡需要你自己判斷」和「這件事做不到」。

- **適合**：不熟資安術語的個人開發者、學生、行銷/營運人員自查
- **不適合**：需要正式稽核／CI/CD 整合／多人協作的團隊 → 用 Gitleaks、TruffleHog、SonarQube 等專業工具

---

## 快速開始

```bash
git clone https://github.com/kenyuiyui/AI-website-sercurity-testing.git
cd AI-website-sercurity-testing/demo_split
python3 -m http.server 8000   # 然後開 http://localhost:8000
```

或直接下載 `demo_split/` 整個資料夾（含 `index.html` 與 `modules/`），瀏覽器開啟即可用。

> ⚠️ 若直接雙擊開啟 `index.html` 沒反應，是瀏覽器對 `file://` 頁面限制了 `<script src>` 載入，改用上面的本機伺服器方式。

部署到 GitHub Pages：把 `demo_split/` 內的 `index.html` 與 `modules/` 放到 repo 根目錄（或設定 Pages 發布目錄指向 `demo_split/`）。

---

## 檔案結構

```
.
├── demo_split/              # 拆分版(推薦)
│   ├── index.html
│   └── modules/              # M1~M12,各自獨立的偵測模組
├── reference/                # 單檔打包版(邏輯內嵌，下載即用)
├── eval/                     # 準確度驗證報告與測試案例
│   ├── CASE_FORMAT.md         # 新增案例前先看這份
│   ├── run_scaled_eval.js     # 規模化驗證,算信賴區間
│   ├── cases/                 # 持續擴充的驗證案例
│   └── reference_cases/       # 真實事件改寫案例(不計入統計)
└── README.md
```

模組對照表：M1 key-detector（明文金鑰）／M2 jwt-analyzer（JWT/Supabase）／M3 hash-detector（弱雜湊）／M4 secret-heuristics（自訂密鑰啟發式）／M5 csp-detector（CSP 缺失）／M6 idor-detector（IDOR）／M7 language-detector／M8 finding-renderer（結果呈現）／M9 sql-injection-detector／M10 insecure-deserialize-detector／M11 field-masking-consistency-detector（多檔案模式）／M12 rate-limit-coverage-detector。

---

## 能查什麼、不能查什麼

**「工具沒標記」不代表「沒問題」。**

### 查得到

- 已知格式的明文 API 金鑰（OpenAI／Anthropic／Gemini／Firebase／Line／AWS）
- HTML／框架設定檔是否有 CSP
- 密碼是否用 MD5／SHA1 這類弱雜湊
- Supabase／JWT 金鑰，區分 `anon`（可公開）與 `service_role`（絕不可公開）
- SQL Injection（字串拼接、模板插值、f-string、Python `%` 格式化）
- 不安全的反序列化／動態執行（eval／exec／pickle／yaml.load，含 Python `exec()` 格式化字串注入）

### 做不到 / 僅供保守提示

- 字串拆分組合而成的金鑰
- 協定層級漏洞、需動態執行才能確認的邏輯漏洞
- IDOR——只是模式比對，主要針對 JS／Express，AST 解析失敗時降級為涵蓋率較低的正則版
- 疑似自訂密鑰、疑似內部端點 URL、環境變數明文 fallback——無固定格式，誤判率較高
- `.env` 需直接貼上文字內容，工具不會讀取你的檔案系統
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

### 為什麼同一組 Firebase 金鑰，工具同時說它「外洩高風險」又說「本身非機密」？

**這是已知的規則重疊問題，不是操作錯誤。**

M1(key-detector) 判斷 Google／Gemini API Key 的規則是「符合 `AIzaSy` 開頭 39 字元格式就標記」，這是純字串比對，不看上下文；但 Firebase 的 `apiKey`（本來就設計成可公開的專案識別碼）剛好也是 `AIzaSy` 開頭的同一種 Google 平台格式。結果同一串字元會被**兩條規則各判一次**：

- M1 判成「Google / Gemini API Key 明文外洩」→ tier 1，高風險說法
- Firebase 專屬規則判成「Firebase 設定值，本身非機密」→ tier 2，低風險說法

兩個結論同時出現在一次掃描結果裡，容易讓人誤以為自己的 Gemini 金鑰外洩了，但其實那組字串是 Firebase apiKey。

**怎麼判斷是哪一種：**
1. 看這串字元出現的上下文——如果前後文是 `"apiKey": "AIzaSy..."` 且旁邊有 `authDomain`、`projectId`、`storageBucket` 這些欄位，就是 **Firebase 設定值**，本身公開沒關係，只要 Firebase Security Rules 設對就好。
2. 如果是單獨一行、變數名像 `GEMINI_API_KEY`、`GOOGLE_API_KEY`，或用在呼叫 `generativelanguage.googleapis.com` 這類 API 端點，才是**真正的 Gemini API Key**，外洩需要立刻到 Google Cloud Console 撤銷重發。

工具目前**不會自動排除這種重疊**，需要你自己核對上下文。這也是為什麼「查得到，且相對可靠」清單只承諾抓得到格式，判讀責任仍在使用者。

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
| 真實案例命中率 | 20 個（真實蒐集，含 SecurityEval 學術資料集） | 95.2% | 100% |
| 誤判率 | 29 個（含邊界值測試） | 0% | 0% |

正則保底版是「使用者瀏覽器連不上 Acorn CDN 時（企業網路限制、離線、CDN 故障）一定做得到」的水準；AST 版是條件允許時的最佳水準。

```bash
cd eval
node run_scaled_eval.js                                                    # 正則保底版
node -e "global.acorn=require('acorn');require('./run_scaled_eval.js');"   # AST 完整版
```

`eval-orchestrator.js` 直接從 `../demo_split/modules` 讀取偵測邏輯，跟上線版本完全同源。新增驗證案例只需在 `eval/cases/` 新增 `.txt` 檔案，格式見 `eval/CASE_FORMAT.md`。`eval/reference_cases/` 是依真實事件改寫的參考案例，刻意不計入統計（避免改寫帶入預期偏誤），細節見該資料夾 README。

樣本規模仍有限（相較 Gitleaks、TruffleHog 等工具的數千至數萬案例），歡迎提交真實案例協助擴充。

---

## 技術細節

- **純前端，零依賴後端**：程式碼只在瀏覽器記憶體處理，不上傳、不儲存。
- **正則保底 + AST 疊加**：M6 用 [Acorn](https://github.com/acornjs/acorn) 做語法樹分析，CDN 載入失敗會靜默降級為正則版，不中斷其他功能。
- **JSX 支援**：搭配 [acorn-jsx](https://github.com/acornjs/acorn-jsx)；純 TypeScript 語法（`interface`、泛型等）仍不支援，會退回正則版並顯示提示。
- **多檔案模式**：支援同時貼上多個檔案，額外比對「同一個敏感欄位在不同檔案的輸出是否遮罩不一致」（M11）。

---

## 授權

[MIT License](LICENSE)

## 作者

kenyuiyui ｜ [GitHub 專案頁面](https://github.com/kenyuiyui/AI-website-sercurity-testing)
