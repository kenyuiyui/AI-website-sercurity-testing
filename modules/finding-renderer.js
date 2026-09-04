/**
 * M8 — finding-renderer
 * 詳細規格見 docs/modules/MODULE_08_finding-renderer.md
 *
 * 職責:把合併後的 Finding[] + 語言提示,轉成使用者看到的 HTML
 * 輸入: findings (Finding[]), languageCaveat (string|null)
 * 輸出: string (HTML)
 *
 * 這是唯一碰 DOM/輸出 HTML 的模組。
 * ⚠️ 安全要求:所有插入 HTML 的文字都必須經過 escapeHtml,避免 XSS。
 *    一個檢查別人程式碼安全性的工具,不能自己被貼上的內容打 XSS。
 */

// kind → { plain: 白話說明, handoff: 可複製給AI的協作指令模板 }
// 這個字典的 key 必須跟 M1-M6 會產生的所有 kind 值對齊,見規格文件對照表。
const FINDING_GUIDE = {
  plain_key: {
    plain: '這組金鑰目前寫死在程式碼裡，任何看得到這份程式碼的人（包含之後公開的原始碼、瀏覽器開發者工具）都能直接複製走並冒用。',
    handoff:
      '我的程式碼裡有一組 API 金鑰是直接寫死在原始碼中的明文字串（不是透過環境變數讀取）。請幫我：\n' +
      '1. 找出這組金鑰目前寫死的位置，改成從環境變數讀取（例如 process.env.對應名稱），不要保留任何明文的金鑰內容在程式碼裡。\n' +
      '2. 提醒我這組金鑰需要到原本申請金鑰的服務後台「撤銷並重新產生」一組新的，因為舊的這組已經外洩，光改程式碼不會讓舊金鑰失效。\n' +
      '3. 修改完成後，請你檢查整個專案裡還有沒有其他地方也用同樣方式寫死了金鑰。\n' +
      '完成後請告訴我：金鑰現在是從哪個環境變數名稱讀取的，以及我還需要去哪裡設定這個環境變數的值。'
  },
  firebase_config_exposed: {
    plain: '這組 Firebase 的 apiKey 出現在程式碼裡，這件事本身不是問題——Firebase 官方明確設計這組值就是要放在前端、公開給任何人看到的，它只是「識別這是哪個 Firebase 專案」的識別碼，不是密碼，光靠它本身無法讀取或修改你的任何資料。真正決定別人能不能存取你資料的，是 Firebase 的 Security Rules（安全規則）有沒有正確設定。如果 Security Rules 沒設定好，即使沒有這組 apiKey，資料一樣不安全；如果 Security Rules 設定正確，這組 apiKey 被任何人看到都沒關係。',
    handoff:
      '我的程式碼裡有 Firebase 的 apiKey 設定值，我知道這本身不是機密外洩（Firebase 官方設計它就是要公開的），但想確認我的 Security Rules 有沒有正確設定。請幫我：\n' +
      '1. 不需要撤銷或更換這組 apiKey，這不會提升安全性，因為它本身不是存取憑證。\n' +
      '2. 幫我檢查專案裡 Firestore／Realtime Database／Cloud Storage 的 Security Rules 設定檔（如果有的話），看看是不是預設的「完全開放」或「完全鎖死」狀態，而不是根據實際需求（例如「只有登入的使用者能讀寫自己的資料」）設定。\n' +
      '3. 如果找不到 Security Rules 設定檔，提醒我去 Firebase 主控台的 Firestore／Database 頁面裡的「規則」分頁確認目前的設定內容。\n' +
      '完成後請告訴我：目前的 Security Rules 大致是什麼邏輯，以及是否需要調整。'
  },
  supabase_service_role: {
    plain: '這是 Supabase 的最高權限金鑰，等於資料庫的管理員密碼，一旦外洩，任何人都能繞過你的權限設定直接讀寫或刪除全部資料。這是這次檢查中最嚴重的一級問題，建議優先處理。',
    handoff:
      '我的前端程式碼裡意外出現了一組 Supabase 的 service_role 金鑰（最高權限、可繞過 Row Level Security 的金鑰），這組金鑰絕對不該出現在前端。請幫我：\n' +
      '1. 找出這組金鑰目前出現的位置，完全移除，前端只能使用 anon 金鑰（一般匿名金鑰）。\n' +
      '2. 若專案中有需要用到高權限操作的功能，改成透過後端 API／Supabase Edge Function 處理，讓 service_role 金鑰只存在於伺服器端環境變數，絕不出現在會送到瀏覽器的程式碼中。\n' +
      '3. 提醒我到 Supabase 後台立即重新產生（rotate）這組 service_role 金鑰，因為舊的已經外洩，光改程式碼不會讓舊金鑰失效。\n' +
      '完成後請告訴我：現在前端使用的是哪一組金鑰，以及高權限操作實際是在哪個後端位置執行的。'
  },
  supabase_anon: {
    plain: '這組 Supabase 金鑰本身設計上是可以出現在前端的，不算外洩，但它的安全性完全取決於你有沒有正確設定「資料列層級安全性（RLS）」規則——如果沒設定，等於任何人都能透過這組公開金鑰直接讀寫你的資料庫。',
    handoff:
      '我的專案中有一組 Supabase 的 anon（匿名）金鑰出現在前端程式碼裡，這本身是官方允許的正常用法，但我需要確認資料庫的安全性有沒有正確設定。請幫我：\n' +
      '1. 說明什麼是 Row Level Security（RLS），以及為什麼只有 anon 金鑰本身不足以保護資料。\n' +
      '2. 如果我告訴你我的資料表結構與需求（誰可以讀/寫哪些資料），請幫我寫出對應的 RLS 政策（policy）設定。\n' +
      '3. 提醒我到 Supabase 後台的 Authentication／Table Editor 裡確認每一張表格是否都已啟用 RLS，而不是預設的「沒有限制」狀態。\n' +
      '完成後請告訴我：我的哪些資料表目前可能還沒有 RLS 保護，需要優先處理。'
  },
  jwt_unknown_role: {
    plain: '偵測到一段長得像身分驗證金鑰（JWT）的字串，但沒辦法判斷它的權限等級高不高，需要你自己確認一下這是什麼服務的金鑰、能做到什麼事。',
    handoff:
      '我的程式碼裡有一段 JWT 格式（eyJ 開頭）的字串，我不確定這是哪個服務的金鑰、權限有多高。請幫我：\n' +
      '1. 告訴我這段字串大概是哪一種服務常見的金鑰格式（如果看得出來的話）。\n' +
      '2. 說明如果這是一組高權限金鑰，出現在前端程式碼會有什麼風險。\n' +
      '3. 建議我應該做哪些下一步確認（例如去哪個服務後台核對這組金鑰的權限範圍）。'
  },
  line_bot_token_suspected: {
    plain: '偵測到一段長度足夠、字元組合看起來像 Line Bot 存取權杖的字串，但 LINE 官方對這組權杖沒有公開的固定格式規則，本工具只能靠「字串夠長、字元集合符合 base64」這種粗略特徵判斷，誤判率比其他有固定格式的金鑰高很多——例如一段 base64 編碼的圖片或簽章值也可能被誤標成這個。需要你自己確認這段字串實際上是不是 Line Bot 權杖。',
    handoff:
      '我的程式碼裡有一段字串被檢查出「疑似 Line Bot 存取權杖」，但這個規則沒有可靠的格式特徵可比對，誤判率較高。請幫我：\n' +
      '1. 先幫我確認這段字串實際上是不是 Line Bot 的 channel access token（而不是圖片編碼、簽章、或其他不相關的長字串）。\n' +
      '2. 如果確認是真的權杖，找出目前寫死的位置，改成從環境變數讀取，不要保留任何明文權杖在程式碼裡。\n' +
      '3. 如果確認是真的權杖，提醒我到 LINE Developers Console 重新產生一組新的權杖，因為舊的已經外洩。\n' +
      '完成後請告訴我：這段字串實際上是不是 Line Bot 權杖，以及如果是，現在是從哪個環境變數讀取的。'
  },
  weak_hash: {
    plain: '密碼目前是用一種已經被證實不安全的方式加密儲存（MD5 或 SHA1），這類方式可以被現成的工具快速破解還原成原始密碼，一旦資料庫外洩，使用者的密碼幾乎等於明文外流。',
    handoff:
      '我的程式碼裡用 MD5 或 SHA1 來雜湊儲存使用者密碼，這是已知不安全的做法。請幫我：\n' +
      '1. 找出目前用 MD5／SHA1 處理密碼的位置，改成使用 bcrypt 或 argon2 這類專門為密碼儲存設計的雜湊演算法。\n' +
      '2. 如果專案已經有既有使用者資料用舊方式儲存，請告訴我遷移既有密碼雜湊的建議做法（通常是下次使用者登入時，用舊方式驗證成功後，順便用新方式重新加密儲存）。\n' +
      '3. 修改完成後，幫我確認密碼的雜湊與驗證邏輯前後端呼叫的地方都已經同步更新。\n' +
      '完成後請告訴我：新的雜湊方式是什麼，以及既有使用者資料需不需要額外遷移。'
  },
  custom_secret_var: {
    plain: '有一個變數名稱看起來像是密碼或金鑰，而且直接被寫成明文字串，這通常代表這組密鑰之後會被不小心一起提交到版本控制系統（如 GitHub），造成外洩。',
    handoff:
      '我的程式碼裡有一個變數名稱看起來像密鑰／密碼，但被直接寫成明文字串，而不是透過環境變數讀取。請幫我：\n' +
      '1. 找出這個變數目前寫死明文的位置，改成從環境變數讀取。\n' +
      '2. 確認專案的 .gitignore 裡有沒有正確排除 .env 這類存放實際密鑰值的檔案，避免之後又不小心提交到版本控制。\n' +
      '3. 如果這個值已經被提交進 Git 歷史紀錄，提醒我這組值也需要視同外洩處理（更換一組新的），單純刪除檔案不會讓舊的 Git 紀錄消失。\n' +
      '完成後請告訴我：這個變數現在是從哪個環境變數名稱讀取的。'
  },
  endpoint_url: {
    plain: '程式碼裡寫死了一個內部服務的網址（例如自動化腳本或通知服務的專屬連結），這個網址本身通常不需要密碼就能被呼叫，一旦外流，任何人都可能利用這個網址觸發你的自動化流程或發送訊息。',
    handoff:
      '我的程式碼裡寫死了一個內部服務的端點網址（例如 Google Apps Script 部署網址或 Webhook 網址），這個網址如果外流，可能被任何人拿去呼叫。請幫我：\n' +
      '1. 評估這個網址目前有沒有做任何呼叫端的身分驗證（例如檢查一組只有我知道的密鑰參數），如果沒有，幫我加上。\n' +
      '2. 如果可以的話，把這個網址改成從環境變數讀取，而不是寫死在會公開的前端程式碼裡。\n' +
      '3. 提醒我這個網址本身要不要視同密鑰處理（例如重新部署產生一個新的網址）。\n' +
      '完成後請告訴我：這個端點現在有沒有身分驗證機制，以及網址是否還存在於前端程式碼中。'
  },
  env_fallback: {
    plain: '程式碼有使用環境變數的正確習慣，但同時又寫了一組明文的「備用密碼」——如果上線時忘記設定正式的環境變數，系統會悄悄改用這組所有人都看得到的備用密碼，而且不會有任何警告。',
    handoff:
      '我的程式碼在讀取環境變數時，帶了一組明文字串作為備用預設值（fallback），如果正式環境忘記設定對應的環境變數，就會直接使用這組所有人都看得到的明文值。請幫我：\n' +
      '1. 找出這個帶明文備用值的地方，移除明文備用值，改成如果環境變數沒有設定時，程式應該直接報錯並提醒開發者，而不是悄悄使用一組不安全的預設值。\n' +
      '2. 檢查專案裡還有沒有其他地方也用同樣的「環境變數 + 明文備用值」寫法。\n' +
      '3. 提醒我確認正式部署環境是否已經正確設定了這個環境變數。\n' +
      '完成後請告訴我：修改後如果忘記設定環境變數，程式現在會發生什麼事（應該是明確報錯，而不是繼續悄悄運作）。'
  },
  env_file_secret: {
    plain: '這份 .env 檔案內容裡有一組看起來像真實密鑰的值。.env 檔案原本設計上就不該被提交進版本控制，如果這份內容已經被上傳到 GitHub 之類的地方，這組密鑰已經算是外洩。',
    handoff:
      '我貼上的 .env 檔案內容裡被檢查出疑似含有真實的明文密鑰。請幫我：\n' +
      '1. 先不要在對話中重複這組密鑰的完整內容。\n' +
      '2. 告訴我確認這份 .env 檔案有沒有被提交進 Git 版本控制的方法（例如檢查 git log 裡有沒有這個檔案的紀錄）。\n' +
      '3. 如果已經被提交過，提醒我這組密鑰需要視同外洩處理：到對應服務後台撤銷並重新產生一組新的，不能只靠刪除檔案或修改 .gitignore 解決。\n' +
      '4. 幫我確認專案根目錄的 .gitignore 裡有沒有正確包含 .env 相關檔案，避免以後再次發生。\n' +
      '完成後請告訴我：這組密鑰是否需要重新產生，以及 .gitignore 現在有沒有正確排除這類檔案。'
  },
  no_csp_html: {
    plain: '這個頁面沒有設定「內容安全政策（CSP）」，這是瀏覽器提供的一道額外防線——如果頁面不小心被植入了惡意程式碼（例如透過某個有漏洞的第三方套件），CSP 能限制這段惡意程式碼能做的事；沒有這道防線，惡意程式碼能做的事就沒有額外限制。這不代表現在就有惡意程式碼，是「萬一發生時少一層保護」。',
    handoff:
      '我的網頁沒有設定 Content Security Policy（CSP），請幫我：\n' +
      '1. 先列出這個頁面實際載入了哪些外部資源（字型、CDN 上的 JS/CSS 函式庫、圖片來源、API 呼叫的網域等），我需要知道 CSP 規則要允許哪些來源，否則設定後頁面可能會壞掉。\n' +
      '2. 根據這份清單，幫我寫一組合理的 CSP meta 標籤（或框架設定檔中的 headers 設定），預設先擋掉其他一切不在清單內的來源。\n' +
      '3. 設定完成後，提醒我實際打開頁面測試看看有沒有東西因為 CSP 太嚴格而載入失敗（瀏覽器開發者工具的 Console 會顯示 CSP 相關的錯誤訊息）。\n' +
      '完成後請告訴我：CSP 規則允許了哪些來源，以及有沒有需要我實際測試確認的部分。'
  },
  no_csp_config: {
    plain: '這份設定檔（看起來像 Next.js／Nuxt 等框架的設定檔）裡沒有找到 CSP 相關設定。這類框架通常是在這裡集中設定安全性標頭，而不是寫在個別頁面裡，所以值得確認一下整個專案是不是真的完全沒有設定。',
    handoff:
      '我的專案設定檔裡似乎沒有設定 Content Security Policy，這是一個 Next.js／Nuxt 類型的框架專案。請幫我：\n' +
      '1. 先確認這個框架設定 CSP 的正確位置與寫法（例如 Next.js 是在 next.config.js 的 headers() 函式）。\n' +
      '2. 列出這個網站實際會用到的外部資源來源（字型、CDN、API 網域等），根據這份清單幫我寫出對應的 CSP 設定。\n' +
      '3. 設定完成後，提醒我要重新部署並實際測試頁面功能是否正常，避免 CSP 設定太嚴格導致網站部分功能失效。\n' +
      '完成後請告訴我：CSP 設定加在哪個檔案的哪個位置，以及允許了哪些來源。'
  },
  possible_idor: {
    plain: '這裡疑似出現一個很常見也很嚴重的問題：程式碼看起來只檢查「你有沒有登入」，卻沒有檢查「你要看的這筆資料是不是真的屬於你」。如果真的是這樣，等於只要是登入過的任何人，把網址或參數裡的編號換成別人的，就可能看到或修改別人的資料。這只是模式比對，不是確診，需要你自己對照程式邏輯確認一次。',
    handoff:
      '我的程式碼裡有一段函式，被檢查出「疑似缺少擁有權驗證」：它看起來會直接用參數（例如網址列的 id）去資料庫查詢或修改資料，但程式碼裡看不到「這筆資料是否真的屬於目前這個使用者」的檢查。請幫我：\n' +
      '1. 先幫我看這個函式，判斷它是不是真的有這個問題（有可能權限檢查寫在別的地方，這只是自動偵測的疑似結果，不一定準確）。\n' +
      '2. 如果確認有問題，請在讀取／修改／刪除資料之前，加上「確認這筆資料的擁有者就是目前登入的使用者」的檢查，如果不是就拒絕並回傳權限錯誤。\n' +
      '3. 提醒我用兩個不同的測試帳號實際操作一次，確認帳號 A 沒辦法透過修改網址參數看到或修改帳號 B 的資料。\n' +
      '完成後請告訴我：這個函式原本是否真的有這個問題，以及你加上了什麼樣的檢查。'
  },
  possible_sql_injection: {
    plain: '這裡的資料庫查詢語句疑似是用「字串拼接」的方式組成的——也就是把使用者輸入的內容直接接進 SQL 查詢字串裡，而不是用「參數化查詢」的安全寫法。如果使用者故意輸入特殊字元（例如在輸入框打入 SQL 語法片段），可能改變這段查詢原本的意圖，讀取、修改甚至刪除不該被存取的資料，這就是 SQL Injection（SQL 注入）。這只是模式比對，不保證每次都準確，需要你自己確認拼接進去的內容來源是否真的來自使用者輸入。',
    handoff:
      '我的程式碼裡有一段資料庫查詢，被檢查出疑似用字串拼接（或模板插值）的方式組成 SQL 查詢語句，而不是使用參數化查詢。請幫我：\n' +
      '1. 先確認這段查詢裡拼接進去的變數是否真的可能來自使用者輸入（例如表單、網址參數、API 請求內容），如果是，這就是需要優先處理的風險。\n' +
      '2. 把這段查詢改成使用參數化查詢（prepared statement），也就是 SQL 語句裡用 ? 或具名佔位符代表變數位置，把實際的值透過參數陣列傳入，而不是直接拼進字串。如果專案有使用 ORM（例如 Sequelize、Prisma、SQLAlchemy），優先改用 ORM 提供的查詢方法，而不是手寫 SQL 字串。\n' +
      '3. 檢查專案裡還有沒有其他地方也用同樣的字串拼接方式組資料庫查詢。\n' +
      '完成後請告訴我：改成參數化查詢後，原本拼接進去的變數現在是透過什麼方式傳遞的。'
  },
  insecure_eval: {
    plain: '程式碼裡呼叫了 eval()，這個函式會把傳進去的文字內容當成程式碼直接執行。如果這段文字內容包含了使用者輸入或來自外部的資料，等於讓使用者有機會執行任意程式碼，這是非常高風險的漏洞（可以想像成讓陌生人直接在你的電腦上打指令）。',
    handoff:
      '我的程式碼裡使用了 eval()，這個函式會把傳入的字串當成程式碼執行，存在高風險。請幫我：\n' +
      '1. 先確認傳入 eval() 的內容是否可能包含使用者輸入或外部資料，如果是，這是需要優先處理的高風險問題。\n' +
      '2. 找出這段程式碼原本想達成的目的（例如動態計算、動態存取物件屬性等），並改用不需要執行任意程式碼的安全替代方案（例如用 JSON.parse 處理資料、用物件的中括號語法動態存取屬性，而不是組字串再執行）。\n' +
      '3. 檢查專案裡還有沒有其他地方使用 eval() 或 new Function()，這兩者風險等級相同。\n' +
      '完成後請告訴我：原本 eval() 的用途是什麼，以及你改用了什麼替代方案。'
  },
  insecure_pickle: {
    plain: 'Python 的 pickle.loads() 被用來還原（反序列化）資料，但 pickle 格式本身設計上就不安全——如果還原的內容來自不可信的來源（例如使用者上傳的檔案、網路請求的內容），惡意的 pickle 資料可以讓程式在還原的當下就直接執行任意程式碼，不需要額外的漏洞就能被攻擊。',
    handoff:
      '我的 Python 程式碼裡使用了 pickle.loads()（或 pickle.load()）來反序列化資料，這個函式如果處理不可信來源的資料會有高風險（惡意資料可以在反序列化當下直接執行任意程式碼）。請幫我：\n' +
      '1. 先確認被反序列化的資料是否可能來自使用者輸入、網路請求、或其他不可信的來源，如果是，這是需要優先處理的高風險問題。\n' +
      '2. 如果資料格式不需要儲存 Python 特有的物件型態，改用 json 模組（json.loads / json.dumps）取代 pickle，JSON 格式本身不會在解析時執行程式碼。\n' +
      '3. 如果必須使用 pickle（例如處理只有自己系統產生、完全可信的內部快取資料），至少要確保這個資料來源絕對不會被外部竄改。\n' +
      '完成後請告訴我：這段資料實際的來源是什麼，以及你是否已經改用更安全的格式。'
  },
  insecure_yaml_load: {
    plain: 'Python 的 yaml.load() 在沒有指定安全載入器（SafeLoader）的情況下，跟 pickle 有類似的風險——它可以解析出任意 Python 物件，如果 YAML 內容來自不可信的來源，可能被用來執行任意程式碼。這個問題有一個很簡單的修法：改用 yaml.safe_load()，或在 yaml.load() 加上 Loader=yaml.SafeLoader 參數。',
    handoff:
      '我的 Python 程式碼裡使用了 yaml.load()，沒有指定安全的載入器（SafeLoader），這樣的寫法在處理不可信的 YAML 內容時有風險。請幫我：\n' +
      '1. 把所有 yaml.load(內容) 的呼叫改成 yaml.safe_load(內容)，這是最簡單直接的修法。\n' +
      '2. 如果基於某些原因必須使用 yaml.load()，確保每一處呼叫都明確加上 Loader=yaml.SafeLoader 參數。\n' +
      '3. 檢查專案裡還有沒有其他地方也用了沒有加安全參數的 yaml.load()。\n' +
      '完成後請告訴我：修改後這些地方是否都已經改用安全的載入方式。'
  },
  insecure_exec: {
    plain: '程式碼裡呼叫了 exec() 或 execSync()，這兩個函式會把傳入的內容當成系統指令執行，而且這裡偵測到的是「用變數組成指令」而不是固定寫死的指令。如果組成指令的變數內容來自使用者輸入，惡意使用者可能在輸入裡夾帶額外的系統指令，讓伺服器執行不該執行的操作（這叫命令注入，Command Injection），嚴重時可能取得伺服器的控制權。',
    handoff:
      '我的程式碼裡使用了 exec() 或 execSync() 執行系統指令，而且指令內容看起來是用變數動態組成的，這樣的寫法如果變數來自使用者輸入會有命令注入的風險。請幫我：\n' +
      '1. 先確認組成這個指令的變數是否可能來自使用者輸入或外部資料，如果是，這是需要優先處理的高風險問題。\n' +
      '2. 評估是否有不需要呼叫系統指令的替代做法（例如用對應的程式語言函式庫直接完成同樣的操作，而不是透過 shell 指令）。\n' +
      '3. 如果必須執行系統指令，改用 execFile() 或 spawn()（Node.js）並把參數以陣列形式個別傳入，而不是拼接成一整串字串，這樣可以避免 shell 對特殊字元的額外解讀。同時對輸入內容做嚴格的白名單驗證，只允許預期的字元或格式通過。\n' +
      '完成後請告訴我：這個指令原本的用途是什麼，以及變數的實際來源。'
  },
  insecure_function_constructor: {
    plain: '程式碼裡用 new Function(...) 動態建立函式，這跟 eval() 的風險本質上相同——傳入的字串內容會被當成程式碼執行。如果這段字串包含使用者輸入或外部資料，等於讓使用者有機會執行任意程式碼。',
    handoff:
      '我的程式碼裡使用了 new Function() 動態建立並執行程式碼，這跟 eval() 有相同等級的風險。請幫我：\n' +
      '1. 先確認傳入 new Function() 的內容是否可能包含使用者輸入或外部資料。\n' +
      '2. 找出原本想達成的目的，改用不需要動態執行任意程式碼的方式實現（例如用物件的方法對照表取代動態產生的函式邏輯）。\n' +
      '3. 檢查專案裡還有沒有其他地方使用 new Function() 或 eval()。\n' +
      '完成後請告訴我：原本的用途是什麼，以及你改用了什麼替代方案。'
  },
  route_missing_rate_limit: {
    plain: '這個路由沒有被速率限制規則涵蓋，也找不到任何預設值兜底，代表這個路由可能完全不受限速保護。如果這個路由是查詢、修改資料或觸發某種動作的端點，缺乏速率限制代表任何人都可以用腳本無限次快速呼叫它，可能被用來做暴力破解、灌爆伺服器，或耗盡你的雲端資源額度。這只是規則比對，不代表這個路由一定需要限速（例如純靜態或不敏感的端點風險就低很多），需要你自己判斷這個路由的重要性。',
    handoff:
      '我的程式碼裡有一個路由被檢查出「沒有被速率限制規則涵蓋，也沒有預設值兜底」。請幫我：\n' +
      '1. 先幫我判斷這個路由本身的敏感程度——如果是查詢、修改資料、觸發動作類的端點，代表這是需要優先處理的項目；如果只是靜態資源或健康檢查這類低風險端點，可能不需要特別處理。\n' +
      '2. 如果確認需要限速，幫我在現有的速率限制邏輯裡加上這個路由的處理分支，設定合理的呼叫頻率上限。\n' +
      '3. 提醒我這個限制的門檻值該怎麼抓比較合理（太嚴格會影響正常使用者，太寬鬆則防護效果有限）。\n' +
      '完成後請告訴我：這個路由現在的限速門檻是多少，以及你是怎麼決定這個數字的。'
  },
  route_uses_default_rate_limit: {
    plain: '這個路由沒有專屬的速率限制規則，但套用了程式碼裡設定的預設值，並不是完全沒有保護。這不一定是問題——如果這個路由的呼叫成本跟其他路由差不多，用預設值完全合理。只是提醒你確認一下：如果這個路由比較特殊（例如呼叫成本特別高，或特別敏感），可能需要一個專屬的、跟其他路由不同的限速數值，而不是沿用一體適用的預設值。',
    handoff:
      '我的程式碼裡有一個路由被檢查出「沒有專屬的速率限制規則，目前套用的是預設值」。這不一定是問題，請幫我：\n' +
      '1. 先幫我判斷這個路由的呼叫成本或敏感程度，是否跟其他已經設定專屬限速的路由明顯不同。\n' +
      '2. 如果確認這個路由需要跟其他路由不同的限速門檻，幫我加上專屬的處理分支。\n' +
      '3. 如果這個路由用預設值就已經足夠，不需要做任何修改，只要告訴我目前的預設值是多少即可。\n' +
      '完成後請告訴我：這個路由最後是維持預設值，還是設定了專屬的限速數值，理由是什麼。'
  },
  inconsistent_field_masking: {
    plain: '這裡標記的是一個「線索」，不是「確診」——請仔細看完這段說明再決定要不要處理。工具發現同一個看起來敏感的欄位名稱，在程式碼裡有好幾個地方會被送到前端或回應給使用者，但只有其中一部分地方做了看起來像「遮罩」或「過濾」的處理，另一部分沒有。這可能代表某個輸出路徑忘了做遮罩，把不該曝光的完整資料送出去了；但也可能只是工具誤判——例如兩個地方剛好用了同一個欄位名稱，但實際上處理的是完全不同、不需要遮罩的資料。工具只能靠名稱和呼叫方式做粗略比對，沒辦法確認這兩個地方是不是真的在處理同一份敏感資料，這件事只有你自己看程式碼才能判斷。',
    handoff:
      '我的程式碼裡被檢查出「疑似欄位遮罩處理不一致」：同一個欄位名稱在多個地方被送出，但只有部分地方做了遮罩或過濾處理。請注意這只是命名相似度比對，不是確診，請幫我：\n' +
      '1. 先確認這幾個地方是不是真的在處理同一份敏感資料。如果只是欄位名稱剛好相同、實際上是不同用途的資料，這裡可以直接忽略，不需要改動。\n' +
      '2. 如果確認真的是同一份資料，請告訴我沒有做遮罩的那個地方，原本是否應該跟已經做遮罩的地方一樣，只是漏掉了。\n' +
      '3. 如果確認有遺漏，幫我補上跟另一處一致的遮罩或過濾邏輯，確保不會把不該曝光的欄位內容送給使用者。\n' +
      '完成後請告訴我：這是真的遺漏了遮罩處理，還是工具誤判（兩處其實是不同用途的資料）。'
  }
};

/**
 * @param {string} kind
 * @returns {{plain:string, handoff:string}|null}
 */
function getFindingGuide(kind) {
  return FINDING_GUIDE[kind] || null;
}

/**
 * HTML escape,防止 XSS(evidence 欄位可能含使用者貼上程式碼的片段)
 * 純 JS 版本(不依賴 DOM,可在 Node.js 測試環境使用)
 * @param {string} str
 * @returns {string}
 */
function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * 各廠商金鑰能力知識庫(供 M1 一般金鑰外洩使用)。
 * ⚠️ 這是工具內建的通用知識庫,不是從程式碼萃取的資料——M1 是純正則模組,
 * 沒有 AST,天生無法從程式碼解析出結構化變數名,因此這裡的內容永遠是
 * 固定文字(依 vendor 查表),不像 M2(JWT)可以顯示真實的專案代碼。
 * 只列「能做什麼」(權限範圍),刻意不列可能造成的費用或金錢損失估計,
 * 避免對讀者做出無法驗證、可能不準確的具體金額宣稱。
 * 內容依 2026 年查證的公開文件/官方說明撰寫,AWS 因為權限完全取決於
 * 該 key 綁定的 IAM policy,無法給固定清單,用條件式措辭處理。
 */
const KEY_CAPABILITY_KB = {
  openai: {
    label: 'OpenAI',
    items: [
      '以你的帳號額度直接呼叫 OpenAI 的所有 API（文字生成、圖片生成等）',
      '產生的費用會直接算在你的帳戶上',
      '透過 API 查看你帳戶的用量與部分帳戶資訊'
    ]
  },
  anthropic: {
    label: 'Anthropic',
    items: [
      '以你的帳號額度直接呼叫 Claude 的所有 API',
      '產生的費用會直接算在你的帳戶上'
    ]
  },
  google_gemini: {
    label: 'Google / Gemini',
    items: [
      '以你的帳號額度呼叫 Gemini API 發起 AI 請求',
      '存取你透過這組金鑰上傳過的檔案與快取內容（如果你的應用程式有使用這些功能）',
      '產生的費用會直接算在你的帳戶上'
    ]
  },
  line_bot: {
    label: 'Line Bot',
    items: [
      '以你的官方帳號身份，向所有好友或已加入的群組發送訊息',
      '常被用來冒充官方帳號散布詐騙訊息或惡意連結，會直接損害帳號信譽',
      '讀取部分 Bot 的設定與訊息紀錄'
    ]
  },
  aws: {
    label: 'AWS',
    isConditional: true, // AWS 的實際權限完全取決於這組 key 綁定的 IAM policy,無法給固定清單
    items: [
      '實際能做的事完全取決於這組金鑰綁定的 IAM 權限設定——可能只能讀取單一儲存空間，也可能是整個 AWS 帳戶的完整管理權限',
      '如果綁定的權限範圍較大，可能可以建立、刪除雲端資源，這通常會直接產生費用',
      '建議到 AWS IAM 主控台查詢這組 Access Key 實際被授予了哪些權限，範圍不明時應假設風險較高'
    ]
  }
};

/**
 * 產生「這組金鑰能做的事」的視覺化展示(目前僅一般機密金鑰 kind === 'plain_key' 適用)。
 * 純 fallback 設計:M1 沒有 AST,無法萃取任何程式碼裡的結構化資訊,
 * 這裡的內容 100% 來自固定的知識庫查表(依 f.visualData.vendor),不是從程式碼解析出來的。
 * 知識庫沒有對應廠商時(vendor 是 null,或不在 KEY_CAPABILITY_KB 裡),回傳空字串,
 * 不硬湊一份「大概是這樣」的內容——沒有查證過的具體內容比不顯示還危險。
 * @param {object} f - Finding
 * @returns {string} HTML,非適用 kind 或查無廠商資料時回傳空字串
 */
function buildKeyCapabilityHtml(f) {
  if (f.kind !== 'plain_key') return '';
  const vendor = f.visualData && f.visualData.vendor;
  const kb = vendor && KEY_CAPABILITY_KB[vendor];
  if (!kb) return '';

  const itemsHtml = kb.items.map(item => `<div class="key-impact-row key-impact-bad"><i class="key-impact-icon">✕</i>${escapeHtml(item)}</div>`).join('');
  const conditionalNote = kb.isConditional
    ? `<div class="attack-demo-note">這組金鑰的實際風險範圍需要另外查證，無法從程式碼本身判斷</div>`
    : '';

  return `
    <details class="rc-attack-demo">
      <summary>查看這組金鑰能做的事</summary>
      <div class="key-impact-card key-impact-danger">
        <div class="key-impact-head">這組 ${escapeHtml(kb.label)} 金鑰能做的事</div>
        <div class="key-impact-list">${itemsHtml}</div>
      </div>
      ${conditionalNote}
    </details>`;
}

/**
 * 產生「金鑰影響範圍」的視覺化展示(目前僅 supabase_service_role / supabase_anon 適用)。
 * 與 buildAttackDemoHtml 不同:JWT 有真實可解碼的 payload,資料來源穩定,
 * 因此這裡的「fallback」情境只有一種(visualData 不存在,例如舊資料或角色未知),
 * 不像 IDOR 需要處理「部分欄位缺失」的中間狀態。
 * @param {object} f - Finding
 * @returns {string} HTML,非適用 kind 或無資料時回傳空字串
 */
function buildKeyImpactHtml(f) {
  if (f.kind === 'supabase_service_role') {
    const vd = f.visualData || {};
    const projectLabel = vd.projectRef ? `專案「${escapeHtml(vd.projectRef)}」` : '這個 Supabase 專案';
    return `
      <details class="rc-attack-demo">
        <summary>查看這組金鑰能做的事</summary>
        <div class="key-impact-card key-impact-danger">
          <div class="key-impact-head">這組金鑰對 ${projectLabel} 擁有的權限</div>
          <div class="key-impact-list">
            <div class="key-impact-row key-impact-bad"><i class="key-impact-icon">✕</i>繞過所有 Row Level Security（RLS）規則</div>
            <div class="key-impact-row key-impact-bad"><i class="key-impact-icon">✕</i>讀取任何一張資料表的全部資料</div>
            <div class="key-impact-row key-impact-bad"><i class="key-impact-icon">✕</i>修改或刪除任何一筆資料，不受權限限制</div>
            <div class="key-impact-row key-impact-bad"><i class="key-impact-icon">✕</i>新增、刪除資料表結構</div>
          </div>
        </div>
        <div class="attack-demo-note">這是資料庫管理員等級的權限，正常情況下只應該存在於後端伺服器環境變數，任何看得到這份程式碼的人都能直接冒用</div>
      </details>`;
  }

  if (f.kind === 'supabase_anon') {
    const vd = f.visualData || {};
    const projectLabel = vd.projectRef ? `專案「${escapeHtml(vd.projectRef)}」` : '這個專案';
    return `
      <details class="rc-attack-demo">
        <summary>查看這組金鑰的安全性取決於什麼</summary>
        <div class="attack-demo-grid">
          <div class="attack-demo-card attack-demo-legit">
            <div class="attack-demo-head">已正確設定 RLS</div>
            <div class="attack-demo-result-label">${projectLabel}的資料</div>
            <div class="attack-demo-result">
              <div class="attack-demo-row"><span>使用者能看到的</span><span>只有自己的資料</span></div>
            </div>
          </div>
          <div class="attack-demo-card attack-demo-evil">
            <div class="attack-demo-head">未設定或設定錯誤</div>
            <div class="attack-demo-result-label attack-demo-danger-text">${projectLabel}的資料</div>
            <div class="attack-demo-result attack-demo-result-danger">
              <div class="attack-demo-row"><span>使用者能看到的</span><span class="attack-demo-danger-text">任何人的全部資料</span></div>
            </div>
          </div>
        </div>
        <div class="attack-demo-note">這組金鑰本身出現在前端是正常的，但它完全不會限制存取範圍——實際能看到什麼，100% 取決於後端 RLS 規則有沒有正確設定</div>
      </details>`;
  }

  return '';
}

/**
 * 產生「攻擊者視角對比」的視覺化展示(目前僅 kind === 'possible_idor' 適用)。
 * 分層 fallback:能從 f.visualData 抓到真實變數名(函式名/參數名/資料庫欄位)就用真實的,
 * 抓不到(例如正則保底版沒有 visualData,或 AST 版部分欄位為 null)就退化成通用抽象示意,
 * 兩種情況畫面結構完全一致,只是文字內容不同,永遠有東西可看,不會開天窗。
 * @param {object} f - Finding
 * @returns {string} HTML,非 IDOR 或無資料時回傳空字串
 */
function buildAttackDemoHtml(f) {
  if (f.kind !== 'possible_idor') return '';

  const vd = f.visualData || {};
  const idParam = vd.idParamName || 'id';
  const ownerField = (vd.dbCall && vd.dbCall.object) ? vd.dbCall.object : '擁有者';
  const isRealData = !!(vd.idParamName || (vd.dbCall && vd.dbCall.object));

  const requestLine = isRealData
    ? `GET /resource?${escapeHtml(idParam)}=<span class="attack-id-legit">482</span>`
    : `請求參數 ${escapeHtml(idParam)} = <span class="attack-id-legit">自己的資料編號</span>`;
  const requestLineAttacker = isRealData
    ? `GET /resource?${escapeHtml(idParam)}=<span class="attack-id-evil">483</span>`
    : `請求參數 ${escapeHtml(idParam)} = <span class="attack-id-evil">隨便猜一個編號</span>`;
  const ownerLabel = isRealData ? escapeHtml(ownerField) : '擁有者';

  return `
    <details class="rc-attack-demo">
      <summary>查看攻擊示範</summary>
      <div class="attack-demo-grid">
        <div class="attack-demo-card attack-demo-legit">
          <div class="attack-demo-head">合法使用者</div>
          <div class="attack-demo-req">${requestLine}</div>
          <div class="attack-demo-result-label">看到的資料</div>
          <div class="attack-demo-result">
            <div class="attack-demo-row"><span>${ownerLabel}</span><span>你自己</span></div>
          </div>
        </div>
        <div class="attack-demo-card attack-demo-evil">
          <div class="attack-demo-head">攻擊者（只改了參數值）</div>
          <div class="attack-demo-req">${requestLineAttacker}</div>
          <div class="attack-demo-result-label attack-demo-danger-text">照樣看得到別人的資料</div>
          <div class="attack-demo-result attack-demo-result-danger">
            <div class="attack-demo-row"><span>${ownerLabel}</span><span class="attack-demo-danger-text">別人的帳號</span></div>
          </div>
        </div>
      </div>
      <div class="attack-demo-note">函式只檢查了「有沒有登入」，沒有比對「這筆資料是不是屬於這個使用者」</div>
    </details>`;
}

/**
 * 組出單一 Finding 卡片的內文(白話說明 + 攻擊示範[IDOR限定] + 技術細節 + 可選的交接指令區塊)
 * @param {object} f - Finding
 * @returns {string} HTML
 */
function buildCardBody(f) {
  const guide = getFindingGuide(f.kind);
  const plainHtml = guide ? `<div class="rc-plain">${escapeHtml(guide.plain)}</div>` : '';
  const attackDemoHtml = buildAttackDemoHtml(f);
  const keyImpactHtml = buildKeyImpactHtml(f);
  const keyCapabilityHtml = buildKeyCapabilityHtml(f);
  const techHtml = `
    <details class="rc-tech">
      <summary>技術細節</summary>
      <div class="rc-evidence">${escapeHtml(f.evidence)}</div>
    </details>`;
  let handoffHtml = '';
  if (guide && guide.handoff) {
    const handoffId = 'handoff_' + Math.random().toString(36).slice(2, 10);
    handoffHtml = `
      <div class="rc-handoff" id="${handoffId}">
        <div class="rc-handoff-head">
          <span class="rc-handoff-label">可複製，直接貼給 AI（Claude／ChatGPT 等）請它幫你處理</span>
          <button type="button" class="rc-copy-btn" data-copy-target="${handoffId}">複製指令</button>
        </div>
        <div class="rc-handoff-text">${escapeHtml(guide.handoff)}</div>
      </div>`;
  }
  return plainHtml + attackDemoHtml + keyImpactHtml + keyCapabilityHtml + techHtml + handoffHtml;
}

const CANNOT_DETECT_TEXT = '字串拆分組合的金鑰、協定層級漏洞（如 Request Smuggling）、需要動態執行才能確認的邏輯漏洞、Prompt Injection 的實際攻擊面、後端是否真的驗證了前端送出的密鑰或權杖。這些屬於需動手測試或人工審查的範疇。第二層「建議人工複查」結果（含疑似自訂密鑰、.env 格式內容、環境變數明文 fallback、疑似內部端點 URL、Supabase anon 金鑰、疑似缺少擁有權驗證）不代表確認存在漏洞，也不保證涵蓋所有情況，命名比對式的偵測誤判率高於已知格式金鑰比對。';

/**
 * 產生檔名標籤HTML,只在Finding帶有filename欄位(多檔案掃描情境)時才顯示,
 * 單一檔案掃描產生的Finding沒有這個欄位,回傳空字串,不影響既有單檔案
 * 掃描的畫面。
 * @param {object} f - Finding
 * @returns {string}
 */
function buildFilenameTagHtml(f) {
  if (!f.filename) return '';
  return `<span class="rc-filename-tag">${escapeHtml(f.filename)}</span>`;
}

/**
 * @param {Array} findings - M1-M6 合併後的 Finding[]
 * @param {string|null} languageCaveat - M7 的輸出
 * @returns {string} HTML
 */
function findingRenderer(findings, languageCaveat) {
  findings = findings || [];
  const tier1 = findings.filter(f => f.tier === 1);
  const tier2 = findings.filter(f => f.tier === 2);
  const tier3 = findings.filter(f => f.tier === 3);
  const total = tier1.length + tier2.length + tier3.length;

  let html = '';
  const summaryParts = [`高信心度發現 ${tier1.length} 項`, `建議複查 ${tier2.length} 項`];
  if (tier3.length > 0) summaryParts.push(`資訊提示 ${tier3.length} 項`);
  html += `<div class="results-summary">掃描完成 — ${summaryParts.join('，')}</div>`;

  if (total === 0) {
    html += `<div class="result-card clean">
      <div class="rc-title">未發現已知格式的明文金鑰或基礎設定缺漏</div>
    </div>`;
  }

  tier1.forEach(f => {
    html += `<div class="result-card tier1">
      <div class="rc-title"><span class="rc-tag">發現</span>${escapeHtml(f.category)} — ${escapeHtml(f.name)}${buildFilenameTagHtml(f)}</div>
      ${buildCardBody(f)}
    </div>`;
  });

  tier2.forEach(f => {
    html += `<div class="result-card tier2">
      <div class="rc-title"><span class="rc-tag">建議複查</span>${escapeHtml(f.name)}${buildFilenameTagHtml(f)}</div>
      ${buildCardBody(f)}
    </div>`;
  });

  // tier3(資訊提示):視覺權重刻意比tier2更輕(見 .result-card.tier3 CSS),
  // 避免跟真正需要人工複查的tier2項目長得一樣重、稀釋其視覺重要性。
  // 目前唯一產生tier3的模組是 M12(rate-limit-coverage-detector)的catch-all情境。
  tier3.forEach(f => {
    html += `<div class="result-card tier3">
      <div class="rc-title"><span class="rc-tag">資訊提示</span>${escapeHtml(f.name)}${buildFilenameTagHtml(f)}</div>
      ${buildCardBody(f)}
    </div>`;
  });

  const langCaveatHtml = languageCaveat ? `<p style="margin-top:8px; color: var(--text-dim);">${escapeHtml(languageCaveat)}</p>` : '';

  html += `<details class="cannot-block">
    <summary class="cb-label">本工具無法檢測</summary>
    <p>${CANNOT_DETECT_TEXT}</p>
    ${langCaveatHtml}
  </details>`;

  return html;
}

// ── 環境相容匯出:Node.js(require)與瀏覽器(<script src>)共用同一份檔案 ──
// Node 測試環境: module 物件存在 → 走 module.exports,供 require() 使用
// 瀏覽器環境: module 不存在 → 略過這段,函式/常數已是全域作用域下的宣告,
//            可直接被 index.html 或其他 <script> 使用
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { findingRenderer, getFindingGuide, escapeHtml, buildCardBody, buildAttackDemoHtml, buildKeyImpactHtml, buildKeyCapabilityHtml, buildFilenameTagHtml, KEY_CAPABILITY_KB, FINDING_GUIDE };
}
