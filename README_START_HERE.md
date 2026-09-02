# AI 產出程式碼資安檢查器 — 工程資料包

**這份資料包是給 AI（或任何接手的開發者）看的。目的：讓拿到這包東西的人，不需要問專案發起人任何背景問題，就能獨立完成指定的一個模組。**

---

## 0　拿到這包東西，你該做的第一件事

1. 讀完這份 README（決定你要做哪個模組）
2. 讀 `docs/ARCHITECTURE.md`（了解整體系統長相、資料怎麼流動）
3. 只讀你負責模組對應的那一份 `docs/modules/MODULE_xx_*.md`（不用讀別人的）
4. 打開 `src/modules/xx-xxx.js`，裡面已經有函式簽名、輸入輸出型別註解、TODO 標記
5. 打開 `test/xx-xxx.test.js`，裡面已經有測試樣板（true positive / true negative / 邊界案例）
6. 完成後只回傳你改動的那個檔案，不要動其他模組檔案

**如果你被要求「改某個功能」，先查 `docs/CHANGE_MAP.md`，那份文件會直接告訴你「這個需求對應哪個模組」，不用自己猜。**

---

## 1　這個專案在做什麼（30 秒版）

一個純前端、零後端的網頁工具。使用者貼上程式碼，工具用一組固定規則掃描明文金鑰、CSP 缺失、弱雜湊演算法、疑似缺少擁有權驗證（IDOR）等問題，分成「高信心度發現」與「建議人工複查」兩層呈現。不執行、不上傳、不儲存使用者貼上的內容。

現有 demo（`reference/index__1_.html`）已經是完整可動的單檔版本。這份資料包的目的，是把 demo 裡黏在一起的邏輯拆成 8 個獨立模組，讓每個模組可以：
- 個別交給不同 AI／不同時間點分別開發
- 個別寫測試、個別驗證，不會因為改 A 模組而不小心弄壞 B 模組
- 之後要換掉某個模組的內部實作（例如 IDOR 偵測從正則換成 AST），只動一個檔案

---

## 2　8 個模組總覽（誰負責什麼）

| 模組代號 | 檔案 | 做什麼 | 難度 | 能否完全獨立開發 |
|---|---|---|---|---|
| M1 | `key-detector.js` | 已知格式金鑰比對（OpenAI/Anthropic/Google/AWS/Line） | 低 | ✅ 完全獨立 |
| M2 | `jwt-analyzer.js` | JWT 格式判讀＋角色分層（Supabase anon/service_role） | 中 | ✅ 完全獨立 |
| M3 | `hash-detector.js` | 弱雜湊演算法偵測（MD5/SHA1 存密碼） | 低 | ✅ 完全獨立 |
| M4 | `secret-heuristics.js` | 第二層猜測式規則：自訂密鑰變數、內部端點 URL、env fallback、.env 格式內容 | 中 | ⚠️ 依賴 M1 的輸出（見下方相依說明） |
| M5 | `csp-detector.js` | CSP 缺失偵測（HTML／框架設定檔） | 中 | ✅ 完全獨立 |
| M6 | `idor-detector.js` | 疑似缺少擁有權驗證 | 高（✅已完成:正則保底+AST疊加分析） | ✅ 完全獨立（唯一依賴外部函式庫Acorn，但透過CDN載入+自動降級處理，不影響其他模組） |
| M7 | `language-detector.js` | 判斷貼上內容的語言，回傳規則涵蓋範圍提示 | 低 | ✅ 完全獨立 |
| M8 | `finding-renderer.js` | 把所有模組的結果轉成畫面（分層排版、複製按鈕、guide 文案） | 中 | ✅ 完全獨立（只依賴標準 Finding 格式，不依賴其他模組內部邏輯） |
| M9 | `sql-injection-detector.js` | 疑似 SQL Injection（字串拼接組成查詢） | 中（正則,與M6同技術難度分類） | ✅ 完全獨立 |
| M10 | `insecure-deserialize-detector.js` | 不安全反序列化/動態執行（eval、pickle.loads、yaml.load未加safe等） | 低（固定字面樣式比對,與M3同套路） | ✅ 完全獨立 |

**能「完全獨立」的意思：只要你知道輸入格式和輸出格式（見下方「資料契約」），不需要看過任何其他模組的原始碼，就能把這個模組寫完、測完。**

---

## 3　資料契約（所有模組共用，這是最重要的一段）

### 輸入
所有偵測模組（M1-M7）的輸入都一樣：一個字串 `code`，也就是使用者貼上的原始程式碼文字。不會是別的型別，不會是已經處理過的資料結構。

### 輸出：Finding 物件
偵測模組（M1-M6）輸出 `Finding[]`（陣列，可以是空陣列）。每個 Finding 長這樣：

```js
{
  tier: 1,                  // 1 = 高信心度發現, 2 = 建議人工複查
  category: '明文金鑰',      // 顯示用的分類名稱
  name: 'OpenAI API Key',   // 這個具體規則的名稱
  kind: 'plain_key',        // 機器可讀的種類代碼,對應 M8 的 FINDING_GUIDE 文案庫
  evidence: 'sk-p...3456 [MASKED]'  // 佐證文字(已遮罩,不可含完整明文密鑰)
}
```

`kind` 的值必須是 M8（`finding-renderer.js`）的 `FINDING_GUIDE` 字典裡已存在的 key，否則畫面上只會顯示技術證據、不會有白話說明。新增一種 `kind` 時，兩邊都要記得更新（見 `docs/CHANGE_MAP.md`）。

### M7 的例外輸出
`language-detector.js` 不輸出 Finding[]，輸出 `string | null`（一段提示文字，或沒有提示時回傳 null）。

### M8 的輸入
`finding-renderer.js` 吃兩個東西：`Finding[]`（所有模組結果合併後的陣列）與 M7 產生的 caveat 字串。輸出 HTML 字串。

### 環境相容匯出（重要，影響你怎麼把模組檔案用在哪裡）

每個模組檔案結尾都是這樣：

```js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { keyDetector, maskMatch, KEY_RULES };
}
```

這代表同一份檔案可以直接用在兩個地方，不需要修改：
- **Node.js 測試環境**：`module` 這個全域物件存在，會走 `module.exports`，`require('./key-detector')` 正常運作
- **瀏覽器 `<script src="key-detector.js">` 載入**：`module` 不存在，這段判斷式會被跳過，`keyDetector` 等函式/常數直接以全域作用域的方式存在，可以被同一頁面上的其他 `<script>` 使用（這正是 `reference/demo_split/index.html` 的載入方式）

**如果你要新增一個模組，或修改某個模組的匯出內容**（例如新增一個要對外公開的函式），結尾都要維持這個包裝格式，不要直接寫 `module.exports = {...}`，否則這個檔案在瀏覽器環境會直接報錯、整個頁面掛掉。

---

## 4　模組相依關係（唯一一條相依,務必注意)

```
M1 (key-detector) ──輸出結果──▶ M4 (secret-heuristics)
                                  用來避免同一段字串被 M1 和 M4 各報一次
```

M4 的函式簽名因此是：

```js
secretHeuristics(code, existingFindings)   // existingFindings 是 M1 輸出的 Finding[]
```

**如果你只負責 M4：** 測試時不需要真的先跑 M1，直接手工造一組假的 `existingFindings` 陣列餵給函式即可（`test/secret-heuristics.test.js` 裡已經有範例）。

**除此之外，M1/M2/M3/M5/M6/M7/M8 之間完全沒有相依，誰先誰後開發都不影響誰。**

---

## 5　協調層（誰把 8 個模組串起來）

有一個不在 8 個模組編號內的檔案：`src/scan-orchestrator.js`。這是唯一知道「所有模組都存在」的地方，負責依序呼叫 M1～M7、合併結果、交給 M8 渲染。

**這個檔案原則上不開放給執行單一模組任務的 AI 修改**，除非任務明確是「新增一個模組」或「調整模組執行順序」。單一模組的任務，只碰自己的模組檔案跟自己的測試檔案。

---

## 6　哪些能完全獨立交給 AI 做，哪些不行

### ✅ 可以直接丟給任何一個 AI 單獨做的
- M1、M2、M3、M5、M6、M7、M8：只要給它對應的 `docs/modules/MODULE_xx_*.md` + 該模組的骨架檔 + 測試骨架檔，AI 不需要任何額外背景就能完成。
- 新增一條新規則到某個既有模組（例如「新增一種金鑰格式到 M1」）：屬於該模組的內部任務，同樣可完全獨立處理。

### ⚠️ 需要額外上下文，不建議單獨丟給不知情的 AI
- M4：因為有相依，必須連同「M1 輸出格式範例」一起給。資料包裡已經準備好了（見 `docs/modules/MODULE_04_secret-heuristics.md` 裡的相依說明）。
- M8：雖然介面獨立，但因為 `FINDING_GUIDE` 文案庫要跟所有模組的 `kind` 值對齊，新增/修改任何模組的 `kind` 時，M8 需要同步收到通知（見第 7 節）。
- `scan-orchestrator.js`：需要知道全部 8 個模組的存在，不適合單獨外包。

### ❌ 不應該交給 AI 自主決定的
- 是否要放寬/收緊某條規則的誤判率門檻（例如 IDOR 判定的寬鬆程度）——這是產品判斷，AI 可以提供選項分析，但最終決定要回到你手上。

---

## 7　「今天要改一個東西」時，你該怎麼做

看 `docs/CHANGE_MAP.md`。那份文件是一張需求 → 模組的對照表，例如：

- 「金鑰誤判了」→ M1 或 M4
- 「CSP 判斷邏輯要改」→ M5
- 「IDOR 準確度要提升，換成 AST」→ M6（介面不變，只換內部實作）
- 「畫面上的文案要改」→ M8
- 「要多支援一種語言的規則」→ 視規則類型可能橫跨 M1/M4/M6，並更新 M7 的語言提示邏輯

找到對應模組後，把該模組的 `docs/modules/MODULE_xx_*.md` + 對應的 `.js` + `.test.js` 三個檔案丟給任一個 AI，說明「這是要新增/修改的行為」，該 AI 不需要看整包東西就能完成任務。

---

## 7.5　目前進度狀態

**✅ 已完成：階段二（法律／免責聲明檢查），對應 `roadmap/ROADMAP.md` 的四個項目**：

1. **免責聲明可見度**：上輪把「能力邊界說明」收進 `<details>` 收合區塊後，重新評估發現這會降低使用者注意度。解法：**收合狀態保留**（維持版面乾淨），但在首屏新增一個不可收合的 `.scope-notice` 提醒（`reference/index.html` 的 `<header class="hero">` 內），明確寫「沒有標記出問題，不代表這段程式碼安全——請點下方了解範圍」，用琥珀色左側色條強調但不搶版面焦點
2. **使用授權範圍聲明**：同一個 `.scope-notice` 區塊裡新增「本工具僅供掃描你自己有權查看的程式碼，請勿用於未經授權的他人系統」，呼應先前討論過的「不能拿去測別人網站」的法律邊界
3. **資料隱私聲明**：確認「內容不外送」原本就在首屏最上方、不受收合影響，維持現狀不動；頁尾原有的「不執行、不上傳、不儲存」聲明也保留
4. **開源授權**：新增 `LICENSE` 檔案（MIT License），頁尾新增作者署名與 GitHub 連結（`https://github.com/kenyuiyui`）

- 這次改動**只動 HTML/CSS 與文字內容**，沒有動任何 JS 邏輯（語法檢查確認 script 區塊長度與修改前完全一致）
- 單檔版與拆分版皆已同步更新，用真實檔案系統載入方式驗證過新增元素正確顯示且掃描功能不受影響
- 全部 133 個單元測試不受影響，依然全數通過
- `roadmap/ROADMAP.md` 階段二的四個項目皆已完成，階段三（部署準備）與階段四（上線後維運）尚未開始

**✅ 已完成：誤判率驗證第二輪擴充（17→29案例），發現並修正第二個真實誤判，揭露一個重要的規則設計教訓**：

- 依官方文件查證後新增 12 個案例：Python/Django/Flask 真實慣用寫法補強（fp-18~fp-23，涵蓋 M1/M4/M6/M9/M10 共5個模組的 Python 情境）、邊界值測試（fp-24~fp-29，第一輪完全沒涵蓋的類別）
- **發現並修正誤判**：`M9 sql-injection-detector` 把一般說明文字裡剛好提到 SQL 關鍵字的句子（如 `"Use SELECT statements carefully" + userNote`）誤判為疑似 SQL Injection。原因：第一輪為了解決「SQL字串內含引號導致漏判」而把判斷條件放寬成「關鍵字附近有拼接即算數」，卻沒有同步要求這真的構成一句 SQL 語句。已修正為要求 SQL 關鍵字後方要有對應的第二關鍵字（FROM/WHERE/SET等）才判定，用真實案例集與既有測試集驗證過不會造成新漏判
- **這次修正揭露一個重要教訓**：解決漏判問題可能意外放寬條件、留下新的誤判空間；反之亦然。已在 `docs/modules/MODULE_09_sql-injection-detector.md` 與 `docs/CHANGE_MAP.md` 明確記錄——往後修改任何模組的判斷邏輯，必須同時跑功能測試（`test/*.test.js`）、真實案例命中率（`eval/run_eval.js`）、誤判率（`eval/run_fp_eval.js`）三份測試，缺一不可，只跑功能測試會漏掉這種規則邊界的連鎖效應
- 修正後：誤判率 0/29 = 0.0%（正則版與AST版一致），真實案例命中率維持不變（77.8% / 100%）
- `test/sql-injection-detector.test.js` 新增3條對應測試（15條），全部模組測試：**133/133 通過**

**✅ 已完成：誤判率驗證（False Positive Evaluation）第一輪，這是階段一的核心工作，並修正一個真實誤判**：

- 新增 `eval/false_positive_samples.js`（17個安全案例，涵蓋 M1/M2/M3/M4/M5/M6/M9/M10 共8個模組）與 `eval/run_fp_eval.js` 評測腳本，`eval/FALSE_POSITIVE_REPORT.md` 記錄完整過程與數據
- **發現並修正**：`M4 secret-heuristics` 的環境變數 fallback 規則會把純數字的合理設定值（如 `process.env.DB_PORT || "5432"`，PostgreSQL預設連接埠）誤判為疑似密鑰。密鑰不可能是純數字，這是可以安全排除的類別，已在 `ENV_FALLBACK_PLACEHOLDER` 加上排除規則
- 修正後：正則保底版與AST版誤判率皆為 **0/17 = 0.0%**（修正前為 1/17 = 5.9%）
- **誠實記錄樣本限制**：17個案例不足以代表「真實世界誤判率是0%」，這份報告本身在文件裡明確寫了下一步該怎麼擴充（尤其 Python 案例偏少、缺乏邊界值測試）
- `test/secret-heuristics.test.js` 新增對應測試（13條），全數通過
- 全部模組測試：**130/130 通過**
- 這是專案 `roadmap/ROADMAP.md` 規劃裡「階段一：誤判率驗證」的第一輪成果，報告裡列出的下一步（擴充案例、補Python、補邊界值）尚未進行

**✅ 已完成：版面精簡（輸入畫面與掃描結果卡片）**：

- **輸入畫面**：拿掉頂部 6 個功能標籤（pill）、大幅縮短說明段落（原本是完整能力範圍描述，改成一句話）、「這個工具做得到與做不到的事」整個區塊（可以/做不到兩欄清單 + 誠實聲明）收進 `<details>`，預設收合，需要的人自己點開看，不再佔用首屏空間
- **掃描結果卡片**：釐清一個誤判——「複製指令」的完整文字內容原本就是預設隱藏的（`display: none`，透過 `.rc-handoff.expanded` 才顯示），這部分不需要改。真正每次掃描都固定攤開、占版面的是**「本工具無法檢測」這段長文字**（不管有沒有發現都會顯示），已改成 `<details>`/`<summary>` 收合，預設收合，跟「技術細節」「攻擊示範」視覺語言一致（用同一套展開箭頭樣式）
- 這次改動**只動 HTML 結構、CSS 樣式與收合狀態**，沒有修改任何偵測邏輯、規則、文案內容——用真實檔案系統載入方式驗證過，發現卡片的實際內容（白話說明、技術細節、視覺化展示、複製指令文字）逐字比對完全一致，只有外層標籤從 `<div>` 換成 `<details>`
- 单檔內嵌版與拆分版都已同步更新，全部 129 個單元測試依然通過（這次改動主要在展示層/HTML，多數測試檢查的是資料結構與文字內容，不受影響）

**✅ 已完成：一般機密金鑰新增「這組金鑰能做的事」視覺化，並修正 Firebase apiKey 的誤分類問題**（M1 重構 + M8 `buildKeyCapabilityHtml`）：

- **Firebase apiKey 誤分類修正（查證公開文件後發現的問題）**：原本 Firebase 的 `apiKey` 跟 OpenAI/AWS 等真正機密金鑰共用同一套 tier1「明文金鑰外洩」邏輯與「需撤銷重新產生」的修復指令。查證後確認這是不準確的——Firebase 官方文件明確說明 `apiKey` 設計上就是要公開在前端的識別碼，不是機密，真正該檢查的是 Security Rules。已將 Firebase 抽出成獨立的 `firebaseConfigDetector`，改為 tier2「建議人工複查」的提醒性質（`kind: 'firebase_config_exposed'`），文案改成引導使用者去確認 Security Rules，不再要求撤銷重新產生金鑰（那樣做對安全性毫無幫助）
- **一般金鑰能力清單視覺化**：`plain_key`（OpenAI/Anthropic/Google-Gemini/Line Bot/AWS）點擊「查看這組金鑰能做的事」，顯示該廠商金鑰的權限範圍清單。內容依查證過的官方文件撰寫，**刻意不列金額或費用估計**（避免無法驗證的具體數字宣稱），AWS 因為權限完全取決於綁定的 IAM policy，用條件式措辭處理，不給固定清單
- 這是三種視覺化裡「fallback 程度最徹底」的一個——M1 純正則沒有 AST，天生無法從程式碼萃取任何結構化資訊，內容 100% 來自工具內建知識庫查表（`KEY_CAPABILITY_KB`），查無對應廠商時回傳空字串、不硬湊內容
- `test/key-detector.test.js` 新增 Firebase 獨立性測試（4條）與 `visualData.vendor` 測試（3條，共16條）、`test/finding-renderer.test.js` 新增 `buildKeyCapabilityHtml` 測試（7條，含「不應包含具體金額數字」的驗證，共27條），全數通過
- 全部模組測試：**129/129 通過**

**✅ 已完成：Supabase JWT 金鑰新增「金鑰影響範圍」視覺化展示**（M2 `visualData` 欄位 + M8 `buildKeyImpactHtml`）：

- `supabase_service_role`（tier1）：點擊「查看這組金鑰能做的事」，顯示這組金鑰能繞過 RLS、讀寫刪除任意資料等權限清單，強調破壞力是全域性的
- `supabase_anon`（tier2）：點擊「查看這組金鑰的安全性取決於什麼」，顯示「已設定 RLS」vs「未設定」的雙欄條件對比，強調這組金鑰本身沒問題、安全性完全取決於後端設定
- M2 新增 `decodeJwtPayload` 函式，保留完整 JWT payload（原本只挑 `role` 欄位），讓 `visualData.projectRef` 可以顯示真實的 Supabase 專案代碼（來自 payload 的 `ref` 欄位），沒有就 fallback 成通用說法
- `jwt_unknown_role`（角色判斷不出來）刻意不附加 `visualData`，不觸發任何視覺化——連角色都不確定時不該猜測該顯示哪種內容
- 這是繼 M6 IDOR 之後第二個做視覺化展示的問題類型，`buildAttackDemoHtml`（IDOR用）與 `buildKeyImpactHtml`（JWT用）各自獨立成函式，`buildCardBody` 依序呼叫、不適用就回傳空字串，不合併成單一巨大函式
- `test/jwt-analyzer.test.js` 新增 4 條 `visualData` 測試（9條）、`test/finding-renderer.test.js` 新增 7 條 `buildKeyImpactHtml` 測試（20條，含 XSS 防護），全數通過
- 全部模組測試：**115/115 通過**

**✅ 已完成：IDOR 發現新增「攻擊示範」視覺化展示**（M6 `visualData` 欄位 + M8 `buildAttackDemoHtml`）：

- 過去 IDOR 的呈現方式只有一段白話文字說明，現在點擊「查看攻擊示範」可以看到「合法使用者 vs 攻擊者」的請求/結果對比卡片，一眼看懂「換一個數字就能看到別人資料」這件事，不用先讀懂文字描述
- **分層 fallback 設計**：M6 的 AST 版偵測到 IDOR 時，會額外萃取函式名、查詢參數名、資料庫呼叫的物件/方法名，附加在 `visualData` 欄位；M8 有這些真實資料就顯示真實變數名，沒有（正則保底版、或 AST 版部分欄位抓不到）就退化成通用抽象示意，兩種情況畫面結構一致，不會開天窗
- 正則保底版（沒有 Acorn 可用時）完全沒有 `visualData`，一律走抽象示意版本——這是誠實的設計：正則沒有能力解析出結構化的變數名
- 視覺配色沿用既有的 `--amber`（危險）/`--green`（安全）色彩系統，不引入新色系，跟畫面其他地方視覺語言一致
- 互動方式跟既有「技術細節」區塊一致：`<details>`/`<summary>` 原生摺疊，預設收合、點擊才展開
- `test/idor-detector.test.js` 新增 4 條 `visualData` 測試（24條）、`test/finding-renderer.test.js` 新增 6 條 `buildAttackDemoHtml` 測試（13條，含 XSS 防護測試），全數通過
- **目前只有 IDOR 一種問題類型有這個視覺化**，其他 9 種仍是純文字呈現。M8 文件裡有記錄「未來要擴充到其他 kind 時該注意什麼」

**✅ 已完成：拿真實世界案例做評測，新增 M9(SQL Injection)、M10(不安全反序列化) 兩個模組，並修正評測過程中發現的 3 個真實 bug。**

這是繼「模組拆分」之後的第二個重大里程碑，過程記錄在 `eval/EVAL_REPORT.md`，摘要如下：

1. **背景**：查證 2026 年 Veracode GenAI Code Security Report、Georgia Tech Vibe Security Radar 等公開報告，確認 AI 產出程式碼最常見的問題類型，比對工具現有涵蓋範圍，評估後決定新增 SQL Injection（技術難度與 M6/IDOR 同級，可靠度高）與不安全反序列化（技術難度與 M3/弱雜湊同級）兩個模組；輸入驗證缺失併入既有 IDOR 邏輯範疇不獨立新增、供應鏈幻覺套件與 Prompt Injection 評估後決定不做（超出靜態分析能力邊界或維護成本過高）。

2. **新增 M9、M10**：各自完整的正則規則、測試、文件，架構完全比照現有 8 個模組的模式。

3. **拿 10 個真實世界代表性案例實測**（`eval/samples.js`，依公開報告改寫，非逐字複製真實外洩程式碼），計算命中率：
   - acorn 不可用（正則保底，CDN失敗/離線的真實情境）：**7/9 = 77.8%**
   - acorn 可用（AST完整分析）：**9/9 = 100%**

4. **這次評測直接測出 3 個單元測試沒抓到的真實 bug**，全部已修正：
   - **M9 SQL Injection 正則版**：字串內部自帶引號（如 `"...username='" + username`）會讓字串邊界比對提早截斷，導致最常見的拼接寫法反而被漏判。改用寬鬆長度匹配取代嚴格引號邊界匹配。
   - **M6 IDOR 正則版**：不支援 `export async function` 這種現代常見的 ES Module 寫法，正則加上選擇性的 `export`/`async` 前綴支援。
   - **M6 IDOR AST 版（最關鍵的修正）**：原本「函式體內出現 owner/session/auth 等字樣就視為已檢查」的判斷方式，會把「只檢查有沒有登入」（如 `if(!req.session.userId)`）誤判為「已做擁有權檢查」，這正是 IDOR 漏洞最典型也最危險的樣式（仿 Lovable 真實外洩事件模式）。改用「是否存在擁有權比較運算（===/!==/==/!=，且至少一邊牽涉權限相關識別字）」的判斷邏輯，正確區分「登入檢查」與「擁有權檢查」。

5. **修正後跑了完整回歸測試**（含原有 94 個單元測試 + 19 組 demo 端對端案例），確認沒有引入新的誤判，才將修正併入正式版本。

- `test/sql-injection-detector.test.js`（12條）、`test/insecure-deserialize-detector.test.js`（12條）：新增測試，全數通過
- `test/idor-detector.test.js` 從 16 條擴充到 20 條，新增「export語法涵蓋」與「擁有權比較邏輯」修正的對應測試
- 全部模組測試總數：**94/94 通過**

**✅ 已完成：8 個模組已實際拆分進 `reference/index.html`，行為與原始 demo（`reference/index__1_.html`）逐項比對驗證一致（19 組回歸測試案例，涵蓋金鑰/JWT角色分層/雜湊/IDOR/CSP/XSS防護/.env格式偵測/畫面互動，語意輸出完全相同）。**

**✅ 已完成：M4 的 `.env` 格式掃描 TODO 已補完**（`src/modules/secret-heuristics.js` 的 `scanEnvFormatLines`），邏輯與原始 demo 完全對齊。`test/secret-heuristics.test.js` 新增 4 條對應測試，全數通過。

**✅ 已完成：M6 IDOR 偵測已升級為「正則保底 + AST(Acorn) 疊加分析」架構**（`src/modules/idor-detector.js`）：
- 正則版永遠先跑，是零依賴的保底邏輯
- 若頁面成功從 CDN 載入 Acorn（`reference/index.html` 的 `<head>` 已加入 `<script src="...acorn CDN...">`），額外用 AST 語法樹分析取代正則結果，解決了正則版兩個已知限制：**箭頭函式完全抓不到**、**註解裡的關鍵字會被誤判為已檢查**
- Acorn 載入失敗（離線、CDN不通）時**靜默退化**為純正則版，不報錯、不影響其他任何功能
- 函式簽名 `idorDetector(code) → Finding[]` 未變，其他 7 個模組完全不受影響
- `test/idor-detector.test.js` 重寫為三層測試（正則版/AST版/整合介面），16 條測試全數通過，**這是資料包內唯一一個測試需要外部 npm 套件（`acorn`）的模組**，見根目錄 `package.json`；沒安裝該套件時測試會優雅跳過 AST 相關案例，不影響保底邏輯的驗證

**✅ 已完成：8 個模組已拆成獨立 `.js` 檔案，透過 `<script src>` 載入**（`reference/demo_split/`）：
- `src/modules/` 底下的 8 個檔案結尾都改成環境相容匯出：`if (typeof module !== 'undefined' && module.exports) { module.exports = {...}; }` — Node 測試環境走 `module.exports`，瀏覽器環境（沒有 `module` 這個全域物件）會跳過這段，函式/常數直接以全域作用域宣告的方式被使用，同一份檔案兩邊都能用，不需要維護兩份
- 拆分版是**兩份 demo 並行交付**，不是取代單檔版：
  - `reference/index.html`（單檔內嵌版，跟之前一樣，開了就能用，只需一個檔案）
  - `reference/demo_split/`（拆分版：`index.html` + `modules/` 資料夾共 9 個檔案，部署時要整個資料夾一起上傳，缺一個模組檔案就會壞掉）
- 兩份的執行邏輯完全相同，只是「程式碼放在一個檔案裡」還是「拆成多個檔案由瀏覽器分別載入」的差異
- 驗證方式：用真實檔案系統路徑（非字串模擬）跑 JSDOM，讓拆分版真的去讀取 `modules/*.js`，確認 19 組回歸案例 + 8 組 AST 雙層架構案例 + 互動層案例，跟單檔版逐一比對語意輸出完全一致

- `reference/index__1_.html` — 原始未拆分版本（舊基準，保留供對照）
- `reference/index.html` — 單檔內嵌正式版，8 模組拼裝而成，M4/M6 均已完成
- `reference/demo_split/` — 拆分版正式版，`index.html` 透過 `<script src="modules/xxx.js">` 載入 8 個獨立檔案
- 這次拆分**沒有**動到任何偵測邏輯、規則、文案——純粹是「檔案怎麼組織」的改變，兩份 reference 的執行結果完全一致

**下一步可做的事（尚未開始）：**
- 「攻擊示範/影響範圍」視覺化目前涵蓋 IDOR、Supabase JWT、一般金鑰外洩三種，其餘 7 種問題類型（弱雜湊、CSP缺失、自訂密鑰變數、SQL Injection、不安全反序列化等）仍是純文字呈現，可視情況評估是否需要擴充
- `KEY_CAPABILITY_KB`（M8）目前只涵蓋 M1 的 5 種金鑰廠商，若 M1 未來新增金鑰規則（例如其他雲端服務的 API Key），記得同步在知識庫補上對應條目，否則視覺化會安靜地不顯示任何內容
- `eval/samples.js` 目前只有 10 個案例，樣本數偏少，且沒有涵蓋 Firebase 誤分類這類「規則本身判斷準確度」的案例，可考慮補充；也可持續累積更多真實世界變化型擴充（見 `eval/EVAL_REPORT.md` 建議）
- `eval/false_positive_samples.js` 誤判率測試集目前只有 17 個案例，偏重 JavaScript/Node.js，Python 案例偏少，且完全沒有涵蓋邊界值測試（例如剛好卡在長度門檻邊緣的字串），見 `eval/FALSE_POSITIVE_REPORT.md` 的下一步建議
- M6 的 AST 判斷規則本身還有調整空間（例如資料庫方法名稱白名單、權限關鍵字白名單都可以再擴充），這屬於規則調校，不是架構問題

## 8　資料夾結構

```
pkg/
├── README_START_HERE.md          ← 你在這裡
├── LICENSE                        ← MIT授權(含作者署名 kenyuiyui)
├── docs/
│   ├── ARCHITECTURE.md           ← 整體系統設計、資料流圖
│   ├── CHANGE_MAP.md             ← 需求 → 模組對照表(臨時改動查這份)
│   └── modules/
│       ├── MODULE_01_key-detector.md
│       ├── MODULE_02_jwt-analyzer.md
│       ├── MODULE_03_hash-detector.md
│       ├── MODULE_04_secret-heuristics.md
│       ├── MODULE_05_csp-detector.md
│       ├── MODULE_06_idor-detector.md
│       ├── MODULE_07_language-detector.md
│       ├── MODULE_08_finding-renderer.md
│       ├── MODULE_09_sql-injection-detector.md
│       └── MODULE_10_insecure-deserialize-detector.md
├── eval/
│   ├── EVAL_REPORT.md              ← 真實案例評測報告(命中率數據、發現的bug、修正過程)
│   ├── samples.js                  ← 10個真實世界代表性案例(依公開資安報告改寫)
│   ├── run_eval.js                 ← 評測腳本,計算命中率
│   ├── FALSE_POSITIVE_REPORT.md    ← 誤判率驗證報告(安全程式碼會不會被誤報)
│   ├── false_positive_samples.js   ← 17個安全案例(涵蓋8個模組,測試規則判斷邊界)
│   └── run_fp_eval.js              ← 誤判率評測腳本
├── roadmap/
│   └── ROADMAP.md                  ← 上架前的完整專案規劃(四階段:誤判率驗證/法律文案/部署/上線後維運)
├── src/
│   ├── scan-orchestrator.js      ← 協調層,串起全部模組(不輕易外包修改)
│   └── modules/
│       ├── key-detector.js
│       ├── jwt-analyzer.js
│       ├── hash-detector.js
│       ├── secret-heuristics.js
│       ├── csp-detector.js
│       ├── idor-detector.js
│       ├── language-detector.js
│       ├── finding-renderer.js
│       ├── sql-injection-detector.js
│       └── insecure-deserialize-detector.js
├── test/
│   ├── key-detector.test.js
│   ├── jwt-analyzer.test.js
│   ├── hash-detector.test.js
│   ├── secret-heuristics.test.js
│   ├── csp-detector.test.js
│   ├── idor-detector.test.js
│   ├── language-detector.test.js
│   ├── finding-renderer.test.js
│   ├── sql-injection-detector.test.js
│   └── insecure-deserialize-detector.test.js
└── reference/
    ├── index.html                ← 【正式版-單檔內嵌】8模組已拼裝進單一HTML,開了就能用
    ├── demo_split/                ← 【正式版-拆分版】與上者行為完全一致,改為多檔案載入
    │   ├── index.html             ← 只剩畫面結構+互動邏輯,透過<script src>載入下方8個模組
    │   └── modules/                ← 與 src/modules/ 內容相同的8個檔案,瀏覽器端使用
    │       ├── key-detector.js
    │       ├── jwt-analyzer.js
    │       ├── hash-detector.js
    │       ├── secret-heuristics.js
    │       ├── csp-detector.js
    │       ├── idor-detector.js
    │       ├── language-detector.js
    │       └── finding-renderer.js
    └── index__1_.html            ← 原始未拆分版本(舊基準,保留供對照)
```
