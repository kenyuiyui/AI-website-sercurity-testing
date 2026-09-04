# 看見 AI 網頁的程式過錯

> 錯與過，不該是我的鍋——貼上程式碼，掃描常見的 AI 產出資安問題。

一個純前端、零安裝的靜態資安檢查工具，專為「用 AI 生成網頁/程式碼、但不熟悉資安」的人設計。貼上程式碼，幾秒內看到常見的資安問題提示，不用裝 CLI、不用學 pre-commit hook。

**Live Demo：** https://kenyuiyui.github.io/AI-website-sercurity-testing/

---

## 這個工具在做什麼

用 AI 工具（v0、Lovable、Bolt、Cursor 等）生成網頁或應用程式時，容易在無形中留下資安漏洞——明文寫死的 API 金鑰、缺少的權限驗證、不安全的雜湊演算法等。這個工具讓你在部署前，把程式碼貼上來快速自我檢查一輪。

**核心原則：誠實告知能力邊界。** 這個工具不會、也不能取代正式的資安審查，它的目的是幫你抓出最常見、最容易被忽略的低垂果實，並且清楚告訴你「這裡看起來可疑，需要你自己判斷」和「這件事本工具做不到」分別是什麼。

### 適合誰用

- 用 AI 生成程式碼、不熟悉資安術語的學生、行銷／營運人員
- 想在上線前隨手自查一輪的個人開發者
- 團隊內部快速自查（非正式合規流程）

### 不適合誰用

- 需要正式資安稽核、合規報告的團隊 → 請使用專業滲透測試或合規工具
- 需要 CI/CD 整合、多人協作、歷史紀錄追蹤的工程團隊 → 請搭配 Gitleaks、TruffleHog、SonarQube 等工具

---

## 快速開始

### 方法一：直接開啟單檔版（最快）

下載 `demo_split/index.html` 所在的整個資料夾（見下方「檔案結構」），或使用單檔打包版本，用瀏覽器直接開啟即可使用，不需要任何安裝或伺服器。

### 方法二：本機執行拆分版（推薦，方便開發／維護）

```bash
git clone https://github.com/kenyuiyui/AI-website-sercurity-testing.git
cd AI-website-sercurity-testing/demo_split

# 用任何靜態伺服器開啟即可,例如:
python3 -m http.server 8000
# 然後瀏覽器開啟 http://localhost:8000
```

> ⚠️ 部分瀏覽器對本機開啟的 `file://` 頁面會限制 `<script src="modules/...">` 的載入（CORS 限制）。若直接雙擊開啟 `index.html` 後掃描功能沒有反應，請改用上述本機伺服器方式開啟。

### 部署到 GitHub Pages

把 `demo_split/` 內的 `index.html` 與 `modules/` 資料夾整個放到 repo 根目錄（或設定 Pages 的發布目錄指向 `demo_split/`），兩者路徑結構必須保持一致，缺一不可。

---

## 檔案結構

```
.
├── demo_split/                  # 拆分版(推薦,模組各自獨立,方便開發維護)
│   ├── index.html
│   └── modules/
│       ├── key-detector.js                        # M1 明文金鑰偵測
│       ├── jwt-analyzer.js                         # M2 JWT / Supabase 金鑰分析
│       ├── hash-detector.js                        # M3 弱雜湊演算法偵測
│       ├── secret-heuristics.js                    # M4 自訂密鑰啟發式偵測
│       ├── csp-detector.js                         # M5 CSP 缺失偵測
│       ├── idor-detector.js                        # M6 疑似缺少擁有權驗證(IDOR)
│       ├── language-detector.js                    # M7 程式語言偵測
│       ├── finding-renderer.js                     # M8 結果畫面呈現
│       ├── sql-injection-detector.js               # M9 SQL Injection 偵測
│       ├── insecure-deserialize-detector.js        # M10 不安全反序列化偵測
│       ├── rate-limit-coverage-detector.js         # M12 速率限制涵蓋率偵測
│       └── field-masking-consistency-detector.js   # M11 跨檔案欄位遮罩一致性(多檔案模式專用)
├── reference/                   # 單檔打包版(所有邏輯內嵌在一個 html,下載即用)
├── eval/                        # 準確度驗證報告與測試案例
│   ├── EVAL_REPORT.md                # 真實案例命中率報告(快照)
│   ├── FALSE_POSITIVE_REPORT.md      # 誤判率驗證報告(快照)
│   ├── CASE_FORMAT.md                # 案例蒐集格式說明,新增案例前先看這份
│   ├── eval-orchestrator.js          # 驗證腳本用的協調層,直接讀取 demo_split/modules,與上線版本同源
│   ├── case-loader.js                # 讀取 cases/ 資料夾內的 .txt 案例檔案
│   ├── stats.js                      # Wilson score interval 信賴區間計算
│   ├── run_eval.js                   # 重新執行「真實案例命中率」驗證(舊版樣本集)
│   ├── run_fp_eval.js                # 重新執行「誤判率」驗證(舊版樣本集)
│   ├── run_scaled_eval.js            # 規模化驗證:讀取 cases/ 全部案例,算出信賴區間與達標進度
│   ├── samples.js
│   ├── false_positive_samples.js
│   ├── cases/                        # 持續擴充的驗證案例(.txt 格式,見 CASE_FORMAT.md)
│   └── reference_cases/              # 依真實事件改寫的參考案例(不計入統計,見該資料夾README)
└── README.md
```

---

## 能查什麼、不能查什麼

使用前建議先看這段，避免對掃描結果有錯誤期待。**「工具沒標記」不代表「沒問題」。**

### 查得到，且相對可靠

- 已知格式的明文 API 金鑰（OpenAI／Anthropic／Gemini／Firebase／Line／AWS）
- HTML 頁面是否設定 Content Security Policy（含 Next.js／Nuxt 等框架設定檔的初步比對）
- 密碼是否用 MD5／SHA1 這類不適合存密碼的雜湊函式
- Supabase／JWT 格式金鑰，並區分 `anon`（可公開）與 `service_role`（絕不可公開）兩種風險等級
- SQL Injection 常見的字串拼接／模板字串插值／Python `%` 格式化字串寫法
- 不安全的反序列化呼叫，含 Python `exec()` 由字串格式化／拼接組成內容的程式碼注入

### 做不到 / 僅供保守提示

- 字串拆分組合而成的金鑰
- 協定層級漏洞、需要動態執行才能確認的邏輯漏洞
- 疑似缺少擁有權驗證（IDOR）——只是模式比對，主要針對 JavaScript／Express 語法，AST 解析失敗時會靜默降級為涵蓋率較低的正則版
- 疑似自訂密鑰變數、疑似內部服務端點 URL、環境變數明文 fallback——沒有固定格式可比對，誤判率高於已知金鑰格式
- `.env` 檔案需直接貼上文字內容才會被掃描到，工具不會、也無法自動讀取你的檔案系統
- 後端是否真的驗證了前端送出的密鑰／權杖——這屬於後端邏輯，工具只看得到你貼上的這份程式碼
- 雲端 IAM 權限設定（如 AWS IAM policy JSON）完全不在涵蓋範圍內

---

## 對照 OWASP Top 10:2025

這個工具鎖定的是「AI 生成程式碼最常見的幾類漏洞」，不是全面的資安稽核，以下如實列出目前規則集對照 [OWASP Top 10:2025](https://owasp.org/Top10/2025/)（2025 年 11 月發布的最新版）能做到的部分。**只列有涵蓋到的項目，其餘 5 項（A03 Software Supply Chain Failures、A06 Insecure Design、A08 Software or Data Integrity Failures、A09 Logging and Alerting Failures、A10 Mishandling of Exceptional Conditions）本工具完全不涉及**——這些問題本質上需要看依賴清單、架構設計、CI/CD 流程或錯誤處理邏輯，超出「掃描單一檔案程式碼片段」這種工具的能力範圍，不是規則沒寫齊，而是設計定位本來就不含這些。

### 完整涵蓋

| 分類 | 對應模組 | 說明 |
|---|---|---|
| **A01 – Broken Access Control** | M6 idor-detector | 偵測疑似缺少擁有權驗證的函式（IDOR），正則保底版 + AST 疊加分析雙軌並行 |
| **A05 – Injection** | M9 sql-injection-detector、M10 insecure-deserialize-detector | SQL Injection（字串拼接、模板插值、f-string、Python % 格式化）＋ 程式碼注入（eval／exec／pickle／yaml.load／Function 建構子） |

### 部分涵蓋

| 分類 | 對應模組 | 涵蓋範圍 |
|---|---|---|
| **A02 – Security Misconfiguration** | M5 csp-detector | 只涵蓋「HTML 頁面／框架設定檔缺少 CSP」這一個子項，不涵蓋其他設定缺失（如預設密碼、不必要功能未關閉、雲端服務配置錯誤等） |
| **A04 – Cryptographic Failures** | M3 hash-detector | 只涵蓋「MD5／SHA1 用於密碼儲存」這一種弱雜湊模式，不涵蓋其他密碼學失敗（加密演算法選型、TLS 設定、金鑰長度不足等） |
| **A07 – Authentication Failures** | M2 jwt-analyzer | 只涵蓋 JWT／Supabase 角色判斷（`anon`／`service_role`、格式異常），不涵蓋 session 管理、密碼強度政策、MFA 等更廣的身分驗證範圍 |

### 框架外的自訂規則

以下模組性質上與資安相關，但不直接對應 OWASP Top 10:2025 任一分類：

- **M1 key-detector／M4 secret-heuristics**：硬編碼 API 金鑰／密鑰偵測，性質貼近 A02（配置管理）與 A04（金鑰管理）的交界
- **M12 rate-limit-coverage-detector**：路由缺速率限制偵測
- **M11 field-masking-consistency-detector**：跨檔案欄位遮罩一致性檢查

---

## 準確度驗證

不是只做單元測試，額外用貼近真實世界的案例做了兩份驗證報告：

| 驗證方向 | 案例數 | 結果 |
|---|---|---|
| 真實案例命中率（`eval/EVAL_REPORT.md`） | 10 個案例（依公開資安報告改寫） | 正則保底版 77.8%／AST 完整版 100% |
| 誤判率（`eval/FALSE_POSITIVE_REPORT.md`） | 29 個案例（含 JS／Python，含邊界值測試） | 0% 誤判 |

**這兩個數字要一起看，不能只看 100% 那個。** 使用者的瀏覽器不一定能連上 Acorn（IDOR AST 分析用的外部函式庫）的 CDN——企業網路限制、離線環境、CDN 故障都可能發生。77.8% 才是工具「保底一定做得到」的水準，100% 是「條件允許時的最佳水準」。詳細方法論與案例設計原則見對應報告檔案。

### 自己重新跑一次驗證

```bash
cd eval
npm install acorn   # 只有測 AST 版才需要,正則保底版不需要裝任何東西

# 真實案例命中率
node run_eval.js                                              # 正則保底版
node -e "global.acorn=require('acorn');require('./run_eval.js');"   # AST 完整版

# 誤判率
node run_fp_eval.js                                            # 正則保底版
node -e "global.acorn=require('acorn');require('./run_fp_eval.js');" # AST 完整版
```

`eval-orchestrator.js` 直接從 `../demo_split/modules` 讀取偵測邏輯，跟 `demo_split/index.html` 實際上線的程式碼完全同源，不是另外一份可能對不上的複製品。

`EVAL_REPORT.md` 與 `FALSE_POSITIVE_REPORT.md` 是一次性的快照報告，反映的是撰寫當下的樣本狀態。

### 案例規模化：往統計上站得住腳的準確率前進

10 個和 29 個案例的樣本規模，用 Wilson score interval 計算 95% 信賴區間，命中率的實際不確定範圍是 ±24 個百分點——這麼寬的區間沒有太多實用意義。要讓「準確率」這幾個字有統計上的意義，同時避免案例本身帶有設計者的預期偏誤，案例需要來自真實蒐集（而非另外發想編寫）且數量要足夠。

`eval/cases/` 資料夾與 `run_scaled_eval.js` 提供一套持續擴充驗證樣本的框架：

```bash
cd eval
node run_scaled_eval.js                                                    # 正則保底版
node -e "global.acorn=require('acorn');require('./run_scaled_eval.js');"   # AST 完整版
```

新增案例只需要在 `eval/cases/` 底下新增一個 `.txt` 檔案，不用碰任何 JS 語法，格式與可用分類見 `eval/CASE_FORMAT.md`。每新增一個案例，重跑一次指令就能立即看到信賴區間收斂進度，以及距離 ±5 個百分點目標還需要多少樣本。

目前 `eval/cases/` 裡有 49 個計入統計的案例：38 個是既有樣本集轉換而來（`legacy-*.txt`，對應 `EVAL_REPORT.md` 與 `FALSE_POSITIVE_REPORT.md` 的原始案例），另外 11 個（`securityeval-*.txt`）逐字取自 [SecurityEval](https://github.com/s2e-lab/SecurityEval) 學術資料集（Siddiq & Santos, MSR4P&S'22, MIT 授權）——這是研究團隊人工蒐集、整理自 CodeQL/MITRE/SonarSource 等來源的真實漏洞範例，不是本專案發想編寫的。加入這批案例後，正則保底版的命中率信賴區間半寬從 ±24.2 個百分點收窄到 ±10.9 個百分點，AST 版收窄到 ±7.7 個百分點（已接近 ±5pt 目標）。

`eval/reference_cases/` 是另一批案例，依已公開發表的真實資安事件技術報告（CVE-2025-48757 / Lovable RLS、Moltbook、Base44 平台認證繞過等）改寫而成，**刻意不計入上述統計**——改寫仍帶有改寫者的預期偏誤，統計上跟真實蒐集不是同一件事。這批案例的用途是擴充問題模式的覆蓋面、記錄驗證過程中發現的規則邊界（例如 M6 正則保底版目前不涵蓋函式主體含超過一層巢狀大括號的 Express route callback），細節見 `eval/reference_cases/README.md`。

樣本規模仍相對有限（相較 Gitleaks、TruffleHog 等成熟工具的數千至數萬案例規模），這是目前最誠實能給出的資料，歡迎提交更多真實案例協助擴充測試集。

---

## 技術細節

- **純前端，零依賴後端。** 貼上的程式碼只在瀏覽器記憶體處理，不會上傳、不會儲存、不會送出到任何伺服器。
- **正則保底 + AST 疊加架構。** M6（IDOR 偵測）使用 [Acorn](https://github.com/acornjs/acorn) 做語法樹分析以提升精確度，透過 CDN 載入；若載入失敗（離線、CDN 故障等），會靜默降級為涵蓋率較窄的正則比對版本，不會中斷其他任何功能。
- **JSX／TypeScript 支援。** 搭配 [acorn-jsx](https://github.com/acornjs/acorn-jsx) 讓 IDOR 的 AST 分析也能處理 React 的 JSX 語法；純 TypeScript 專屬語法（`interface`、型別標註、泛型等）目前仍不支援，會依現有機制退回正則版並顯示提示。
- **多檔案模式。** 支援同時貼上多個檔案（例如前端／後端分開的專案），除了各自跑完整分析外，額外比對「同一個敏感欄位在不同檔案的輸出是否遮罩不一致」（M11）。
- **淺色／深色主題**，記住使用者選擇。

---

## 授權

本專案採用 [MIT License](LICENSE) 授權。

---

## 作者

kenyuiyui ｜ [GitHub 專案頁面](https://github.com/kenyuiyui/AI-website-sercurity-testing)
