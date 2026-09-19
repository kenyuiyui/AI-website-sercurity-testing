# 變更與修正紀錄

程式碼裡只留一行「為什麼」;完整背景(發現經過、當初的錯誤寫法、驗證方式)集中在這裡。
新增紀錄時:程式碼旁寫一行 `為什麼:…(背景見 docs/CHANGELOG.md)`,細節寫在本檔對應模組底下。

## 2026-09 第二輪：可信度、隱私、門檻

- **Firebase 誤報修正**：`AIzaSy` 金鑰只有「以 apiKey 屬性寫在 Firebase 設定裡（附近有 authDomain／projectId／firebaseapp.com／initializeApp 等特徵）」才判為 `firebase_config_exposed`（tier2），否則仍為 Gemini／Google 金鑰外洩（tier1）。同一個值不再被兩條規則各報一次。舊的 Firebase 規則只認 JSON 雙引號寫法，JS 物件寫法反而漏掉、被當成外洩。
- **自訂密鑰去重複修正**：M4 原本拿「已遮罩的 evidence」比對金鑰前 8 碼，遮罩後只剩前 4 碼，所以去重複從未生效（每個明文金鑰都會多一筆「自訂密鑰」）。改用模組回傳的原始片段 `match` 比對。
- **壓縮程式碼提示**：實測壓縮後的金鑰檢查仍然有效，失效的只有權限／SQL 等邏輯檢查。偵測到壓縮程式碼時在結果最上方明確說明，不再只給「沒有比對到問題」的假安心。
- **答非所問的提示**：「權限檢查退回簡易版」只在程式碼含資料庫查詢時才顯示（原本普通 HTML 也會出現）。語言與降級提示改為 notices，顯示在結果最上方而非收合區塊裡。
- **零外部連線＋CSP**：acorn、acorn-jsx、字型改放本站（`vendor/`、`assets/fonts/`），移除 jsdelivr、esm.sh、Google Fonts。頁面加上 `default-src 'none'` 的 CSP，對外只允許 GitHub 匯入的兩個網域；單檔版以 sha256 雜湊放行內嵌內容。語法分析不再依賴 CDN，網頁上一律使用 AST 版。
- **白話結果**：層級改稱「需要處理／請你確認／參考」；每種 kind 有白話標題（技術名稱改為副標）；結果最上方有一句話結論、「先別慌」說明與 2～3 個行動步驟。
- **匯出報告**：Markdown 報告可複製、下載或分享；不含原始程式碼，金鑰只輸出遮罩後字串。verify 會對所有樣本檢查報告不含偵測原文與程式碼行。
- **GitHub 公開專案匯入**：貼網址即抓取檔案（最多 60 個，優先 API／設定／資料庫相關路徑），私人專案與流量限制有明確說明。
- **首屏精簡**：標語縮成一行，GitHub 匯入與輸入框直接在首屏；「看範例」會自動檢查。驗收標準寫進 `scripts/ui-smoke.js`。
- **測試環境**：Node 驗證改用 `vendor/` 內與網頁相同的 acorn（`eval/load-ast.js`），專案不再需要任何 npm 套件。

## 2026-09 架構整理

- 掃描流程抽成 `modules/scan-orchestrator.js`,瀏覽器(`assets/app.js`)與驗證腳本(`eval/eval-orchestrator.js`)共用,原本三處重複的流程合一。
- `index.html` 拆出 `assets/style.css` 與 `assets/app.js`;單檔版改由 `scripts/build-single.js` 內嵌所有本機 `<link>`/`<script src>`。
- 偵測模組的 Finding 可帶 `index`(字元位置)或 `match`(原始片段),由 scan-orchestrator 換算成 `line`/`start`/`end`,畫面顯示行號。`match` 只供定位,不可輸出到畫面。
- 畫面:摘要列可跳轉、自動捲到結果、Ctrl/⌘+Enter 掃描、一鍵複製指令與「複製全部修正指令」、拖放／開啟本機檔案、手機版固定掃描列、分頁支援 `#boundary` `#howto` 連結、補上 tier3 樣式。
- 範例改為正則保底版也能同時展示「發現」與「建議複查」兩層。

## 外部依賴(原 index.html 註解;第二輪後已改為本站 vendor/,以下為當時背景)

- **Acorn**(jsdelivr):M6 IDOR 的語法樹分析。唯一必要的外部函式庫,只影響 IDOR 精確度;載入失敗時 `idor-detector.js` 靜默退回正則版,其他功能不受影響。只在瀏覽器本機解析,不外送程式碼。
- **acorn-jsx**(esm.sh):Acorn 原生不認 JSX,而 Lovable/v0/Bolt 的主要產出就是 React 元件。acorn-jsx 沒有瀏覽器 UMD 版,因此透過 esm.sh 轉成 ES module 載入並掛到 `window.acornJsx`。失敗時同樣退回正則版。
  - 已知限制:acorn-jsx 不處理 TypeScript 專屬語法(interface、型別標註、泛型、as),含這些語法的 .tsx 仍會退回正則版並顯示提示——這是刻意的邊界。
  - 部署後請在瀏覽器 Console 輸入 `window.acornJsx` 確認有載入(Node 測試環境無法驗證這點)。

## 模組修正紀錄

### M11 field-masking-consistency-detector.js

- **多檔案模式(M11)由 scan-orchestrator.scanFiles 呼叫。**

  修補紀錄(2026):原本這個模組雖然邏輯完整,但完全沒被打包進demo HTML,
  UI也沒有多檔案輸入介面可以觸發它。這次補上多檔案模式後,一併打包進來。

### M6 idor-detector.js

- **允許 TS 回傳型別標註 `): Order {`,否則正則版整條漏判。**

  修正紀錄(2026,真實AI產出程式碼實測發現的漏判):
  原本 \)\s*{ 要求右括號後緊接大括號,但TypeScript常見的函式回傳型別標註
  (例如 function getOrder(id: number): Order { ... })在右括號跟大括號中間
  插入了 ": Order" 這段文字,導致整個正則完全匹配失敗、直接漏判。這不只
  影響AST版失敗後的降級情境——任何貼上帶回傳型別標註的TS函式,連正則保底版
  都抓不到。加上 (?:\s*:\s*[\w.<>\[\]| ]+)? 這段選擇性分組,允許右括號後、
  大括號前存在型別標註,但不解析型別內容本身(只是跳過,不影響其他判斷)。

- **參數名除 id/userId/req 外也認駝峰 xxxId(大寫 Id,避開 valid/grid)。**

  修正紀錄2(2026,真實Lovable專案[filla-app]實測發現的嚴重漏判):
  原本只認完全等於 id/userId/req 這三個精確名稱,但真實程式碼裡最常見的
  參數命名其實是 xxxId 駝峰形式(如 propertyId、taskId、orderId、assetId)——
  這在真實案例中比裸 id 更常見。原本的 \b(id|userId|req)\b 是單字邊界完全
  匹配,propertyId 裡的 "Id" 前面緊接 property(字母),不構成獨立單字邊界,
  完全匹配不到,導致這類函式全部被漏判。加上 [a-zA-Z_$][a-zA-Z0-9_$]*Id 這
  個分支涵蓋駝峰 xxxId 命名,要求 Id 是大寫開頭(符合JS駝峰慣例),避免誤傷
  valid/avoid/grid/solid 這類字尾剛好是小寫id、但語意無關的單字。

- **Express/Koa 路由 callback 寫法;主體用大括號配對取出,不能用 [^}] 截斷。**

  修正紀錄(2026,reference_cases/incident-moltbook-2026、incident-base44-2025 發現):
  IDOR_PATTERN 只認具名 function 宣告,Express/Koa 路由最常見的「callback 直接當參數」
  寫法 app.get(path, async (req, res) => {...}) 與 app.get(path, function (req, res) {...})
  完全抓不到(AST 版沒有這個問題,只影響 acorn 無法載入時的保底路徑)。
  這條規則只比對 callback 的開頭,不要求參數名是 id/xxxId——路由 callback 的簽名固定是
  (req, res),實際查詢用的 ID 在 req.params 裡。也順帶涵蓋指派給變數的箭頭函式
  (const deleteOrder = async (req, res) => {...})。
  函式主體改用大括號配對取出(extractBraceBody),不沿用 IDOR_PATTERN 的 [^}]{0,300}:
  路由 callback 幾乎一定含 { appId } 解構或 findOne({...}) 這類物件字面值,
  [^}] 會在第一個 } 就截斷主體,導致後面的 DB 呼叫看不到而漏判。

- **必須是「擁有權比較」才算已檢查;只檢查有沒有登入(session)不算。**

  修正紀錄(來自真實案例實測發現的問題):原本的 isAuthRelatedNode 只判斷
  「有沒有出現」owner/session/auth 等權限相關字樣,但這樣會把「只檢查有沒有登入」
  (例如 if(!req.session.userId){...},只確認使用者存在,不比較資料擁有者)
  誤判為「已做擁有權檢查」而放過,這正是 IDOR 漏洞最典型也最危險的樣式——
  有登入檢查、卻沒有擁有權檢查。

- **Acorn 原生不認 JSX,需 acorn-jsx 外掛,否則 React 程式碼一律退回正則版。**

  修正紀錄(2026,真實AI產出程式碼實測發現的問題):
  Acorn 是純 JavaScript parser,原生完全不認識 JSX(<div>...</div> 這類語法)。
  實測發現:貼上任何一段含 JSX 的 React 元件(.tsx/.jsx,這正是 Lovable/v0/Bolt
  這類工具最主要的產出格式),AST 解析必定失敗,靜默退回正則版,IDOR 涵蓋率
  從100%(AST版)掉回77.8%(正則版),且這個降級對使用者完全不可見。

- **回傳 astUsed,讓畫面提示「這次 IDOR 用的是較弱的正則版」。**

  修正紀錄(2026,真實AI產出程式碼實測發現的問題):
  idorDetector(code) 原本在AST解析失敗時靜默退回正則版,呼叫端完全無法得知
  「這次分析比較弱」這件事。既然JSX/TS的AST解析失敗是已知會發生的常態情況
  (不是例外狀況),不應該讓使用者在完全不知情下拿到涵蓋率較低的結果。
  新增這個函式,額外回傳 astUsed(布林值):AST版是否真的被採用。
  scan-orchestrator 部分(見本檔案下方組裝掃描流程的<script>)會用這個
  資訊組出提示文字,顯示在畫面上「本工具無法檢測」區塊,取代原本完全
  靜默的行為。

### M2 jwt-analyzer.js

- **依賴 M1 的 maskMatch():瀏覽器靠載入順序,Node 直接 require。**

  修正紀錄(2026,拆分成獨立檔案後才暴露的問題):
  本模組的 evidence 文字組裝依賴 M1(key-detector)的 maskMatch() 遮罩函式。
  單檔版把全部模組寫在同一個 <script> 作用域內時,這個依賴不會出錯,但拆成
  獨立檔案後,若載入順序不含 key-detector.js,或本檔案被單獨抽出使用,
  會在瀏覽器與 Node.js 兩種環境下都直接噴 ReferenceError。
  因此不再宣稱「不依賴任何其他模組」,改為明確處理跨模組依賴:
  瀏覽器端要求 index.html 必須在 jwt-analyzer.js 之前載入 key-detector.js
  (根目錄 index.html 的載入順序已符合這個要求);Node.js 環境則直接
  require key-detector.js 取得 maskMatch。
  輸入/輸出介面不變:輸入 code(string),輸出 Finding[]。

### M1 key-detector.js

- **Firebase apiKey 設計上可公開 → 獨立為 tier2 firebase_config_exposed,不當外洩處理。**

  修正紀錄(2026,查證公開文件後修正):
  Firebase 的 apiKey 原本跟 OpenAI/Anthropic/AWS 等金鑰混在同一份 KEY_RULES 裡,
  用同一個 tier1「明文金鑰外洩」的等級與文案處理。這是不準確的——Firebase 官方
  文件明確說明 apiKey 只是「識別這是哪個專案」的識別碼,不是機密憑證,設計上
  就是要出現在前端程式碼裡,外洩本身不構成風險。真正該檢查的是 Firebase
  Security Rules 有沒有正確設定,那才是實際控制資料存取的機制。
  因此 Firebase 從 KEY_RULES 抽出,獨立成 firebaseConfigDetector,
  產生 tier2、kind: 'firebase_config_exposed' 的提醒性質 Finding,
  不再套用「金鑰外洩、需撤銷重新產生」那套適用於真正機密金鑰的文案與流程。

- **Line Bot token 無固定格式 → tier2 猜測規則,並排除 JWT(交給 M2)。**

  修正紀錄2(2026,真實AI產出程式碼實測發現的誤判):
  Line Bot Access Token 原本跟 OpenAI/Anthropic/AWS 等金鑰混在同一份 KEY_RULES 裡,
  套用同一個 tier1「明文金鑰外洩」等級。這是不準確的——LINE 官方文件說明
  channel access token 是「不透明字串(opaque string)」,沒有公開的固定格式規則
  (不像 sk-proj-/AKIA 等有明確字首),原本的正則 /[A-Za-z0-9+/=]{100,}/ 只是「任意
  100字元以上的base64字元集合字串」,會誤判任何長JWT、base64編碼圖片、簽章值等
  完全不相關的內容。實測發現:貼上一組 Supabase JWT 金鑰,會被同時誤標成
  「Line Bot Access Token 外洩」(因為JWT本身也是100+字元的base64字元集合)。
  因此 Line Bot 比照 Firebase 的處理方式從 KEY_RULES 抽出,獨立成
  lineBotTokenDetector:(1) 明確排除三段式JWT格式(xxx.yyy.zzz,已由M2 JWT分析器
  專責處理,不應由這條規則重複標記或誤標成別的廠商),(2) 降為 tier2「建議複查」
  而非 tier1「高信心度發現」,文案上誠實反映「這條規則沒有可靠格式特徵可比對,
  誤判率高於其他已知格式金鑰」,避免使用者把這類低可靠度的比對結果當成確診。

- **排除 JWT 片段要檢查「前後緊鄰」是否有 .xxx 段,只看匹配片段本身會失效。**

  修正紀錄(2026,真實Lovable專案實測發現的問題):
  原本只用 JWT_SHAPE_PATTERN.test(matched) 檢查「匹配到的片段本身」是否為
  完整三段式JWT,但這個排除邏輯幾乎永遠失效——因為JWT的分隔符號 "." 不在
  LINE_BOT_TOKEN_RULE.re 的字元集合[A-Za-z0-9+/=]內,正則掃描遇到"."就會
  截斷,實際只抓到JWT三段中的其中一段(通常是payload),這段本身當然不符合
  "xxx.yyy.zzz"的完整格式,排除判斷因此形同虛設。實測發現:一組真實的
  Supabase anon JWT會同時被M1的supabase_anon規則正確標記,又被這裡誤標成
  Line Bot token,兩者互相矛盾,使用者會很困惑。
  修法:不檢查「匹配片段本身」,而是檢查「匹配片段的前後緊鄰處」是否存在
  JWT的其他兩段(用.分隔、同樣是base64-like字元的片段)——如果前面或後面
  緊接著 "." + 另一段長度合理的base64-like字元,代表這其實是嵌在一個更大
  JWT結構裡的其中一段,應該排除,交給M2(jwt-analyzer)處理整個JWT。

### M7 language-detector.js

- **Python import 規則必須排除 JS/TS 的 ES Module import,否則幾乎所有 TS 檔都誤判。**

  修正紀錄(2026,真實Lovable專案[filla-app]實測發現的嚴重誤判):
  原本 PYTHON_PATTERN 裡的 \bimport\s+\w+\b 這條子規則,目的是抓Python的
  裸import語句(如 import os),但寫法完全沒排除JavaScript/TypeScript的
  ES Module import語法。實測發現:任何一份標準的TS/JS檔案,只要有
  `import type { X } from "./y"`(TypeScript專屬語法)或
  `import React from "react"`(一般default import)這類再正常不過的寫法,
  都會被誤判成「含Python特徵」,對使用者顯示一段誤導性的警告文字,
  說這份程式碼的規則涵蓋範圍有限——而它明明就是規則主要針對的
  JavaScript/TypeScript語言本身。這是影響面極廣、幾乎必現的誤判
  (幾乎所有現代TS/JS檔案都有import語句),比其他已知限制嚴重得多。

### M9 sql-injection-detector.js

- **字串拼接用限長寬鬆匹配 [\s\S]{0,120}?,不能用引號邊界(SQL 內常含單引號)。**

  修正紀錄(來自真實案例實測發現的bug):
  初版 CONCAT_PATTERN 用「排除引號字元的字元類別」([^"'`]) 來界定字串邊界,
  目的是避免比對跨越多個不同字串。但這個做法有嚴重副作用: SQL 查詢字串
  內部經常自己就包含單引號(例如 "...username='" + username + "'..."),
  正則在字串開頭遇到內部的單引號就會提早截斷比對,導致真正的字串拼接
  反而被漏判。改用「限制比對長度的寬鬆匹配」([\s\S]{0,120}?)取代嚴格
  的引號邊界匹配,犧牲一點點精確度換取不漏判真實案例中最常見的寫法。
  (此問題是在拿真實世界案例實測時發現,原本的單元測試案例湊巧沒有
  觸發這個邊界,這正是「真實案例測試」相對於「手寫假案例測試」的價值所在)

- **SQL 關鍵字需搭配第二關鍵字(FROM/INTO/SET…)才算語句,避免一般文字誤判(fp-26)。**

  修正紀錄2(誤判率驗證發現的問題,見 eval/FALSE_POSITIVE_REPORT.md fp-26):
  修正1解決了漏判問題,但換來另一個副作用:CONCAT_PATTERN 只要求「SQL關鍵字
  附近有拼接」,沒有要求這真的是一句完整的SQL語句,導致一般文字說明裡剛好
  提到SQL關鍵字(例如 "Use SELECT statements carefully" + userNote 這種
  提示文字或註解),也會被誤判為疑似SQL Injection。
  修正:要求SQL關鍵字後方(60字元內)還要出現對應的第二關鍵字
  (SELECT/DELETE 對應 FROM,INSERT 對應 INTO,UPDATE 對應 SET,
  也接受 WHERE/VALUES 作為輔助判斷),兩者都出現才算是真正的SQL語句結構,
  而不只是「提到SQL關鍵字的普通文字」。用完整的既有測試集(true positive
  案例、eval/samples.js真實案例)驗證過,加上這個限制不會讓任何真實的
  SQL Injection案例漏判,只排除了「關鍵字單獨出現、不構成完整語句結構」
  的情況。
