/**
 * M1 — key-detector
 * 詳細規格見 docs/modules/MODULE_01_key-detector.md
 *
 * 職責:掃描程式碼,找出已知格式的明文 API 金鑰
 * 輸入: code (string)
 * 輸出: Finding[]
 *
 * 這是純函式,不依賴任何其他模組,可完全獨立開發與測試。
 *
 * ⚠️ 修正紀錄(2026,查證公開文件後修正):
 * Firebase 的 apiKey 原本跟 OpenAI/Anthropic/AWS 等金鑰混在同一份 KEY_RULES 裡,
 * 用同一個 tier1「明文金鑰外洩」的等級與文案處理。這是不準確的——Firebase 官方
 * 文件明確說明 apiKey 只是「識別這是哪個專案」的識別碼,不是機密憑證,設計上
 * 就是要出現在前端程式碼裡,外洩本身不構成風險。真正該檢查的是 Firebase
 * Security Rules 有沒有正確設定,那才是實際控制資料存取的機制。
 * 因此 Firebase 從 KEY_RULES 抽出,獨立成 firebaseConfigDetector,
 * 產生 tier2、kind: 'firebase_config_exposed' 的提醒性質 Finding,
 * 不再套用「金鑰外洩、需撤銷重新產生」那套適用於真正機密金鑰的文案與流程。
 *
 * ⚠️ 修正紀錄2(2026,真實AI產出程式碼實測發現的誤判):
 * Line Bot Access Token 原本跟 OpenAI/Anthropic/AWS 等金鑰混在同一份 KEY_RULES 裡,
 * 套用同一個 tier1「明文金鑰外洩」等級。這是不準確的——LINE 官方文件說明
 * channel access token 是「不透明字串(opaque string)」,沒有公開的固定格式規則
 * (不像 sk-proj-/AKIA 等有明確字首),原本的正則 /[A-Za-z0-9+/=]{100,}/ 只是「任意
 * 100字元以上的base64字元集合字串」,會誤判任何長JWT、base64編碼圖片、簽章值等
 * 完全不相關的內容。實測發現:貼上一組 Supabase JWT 金鑰,會被同時誤標成
 * 「Line Bot Access Token 外洩」(因為JWT本身也是100+字元的base64字元集合)。
 * 因此 Line Bot 比照 Firebase 的處理方式從 KEY_RULES 抽出,獨立成
 * lineBotTokenDetector:(1) 明確排除三段式JWT格式(xxx.yyy.zzz,已由M2 JWT分析器
 * 專責處理,不應由這條規則重複標記或誤標成別的廠商),(2) 降為 tier2「建議複查」
 * 而非 tier1「高信心度發現」,文案上誠實反映「這條規則沒有可靠格式特徵可比對,
 * 誤判率高於其他已知格式金鑰」,避免使用者把這類低可靠度的比對結果當成確診。
 */

// 真正的機密金鑰:外洩即代表任何人都能冒用,需要撤銷重新產生
// vendor 是給 M8 查對應「這組金鑰能做什麼」知識庫用的識別碼(純正則沒有能力
// 從程式碼萃取更多結構化資訊,這是 M1 視覺化展示唯一能提供的真實資料)
const KEY_RULES = [
  { name: 'OpenAI API Key', vendor: 'openai', re: /sk-proj-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,}/g },
  { name: 'Anthropic API Key', vendor: 'anthropic', re: /sk-ant-[A-Za-z0-9_-]{20,}/g },
  { name: 'Google / Gemini API Key', vendor: 'google_gemini', re: /AIzaSy[A-Za-z0-9_-]{33}/g },
  { name: 'AWS Access Key ID', vendor: 'aws', re: /AKIA[0-9A-Z]{16}/g },
];

// Firebase 設定值:官方設計為可公開的專案識別碼,不是機密,獨立處理
const FIREBASE_CONFIG_RULE = { name: 'Firebase 設定值', re: /"apiKey"\s*:\s*"[A-Za-z0-9_-]{20,}"/g };

// Line Bot Access Token:官方為不透明字串、無公開固定格式,獨立處理為 tier2 猜測式規則
// (見上方修正紀錄2)。判斷式而非單純正則,因為需要額外排除JWT三段式格式。
const LINE_BOT_TOKEN_RULE = { name: 'Line Bot Access Token（疑似）', vendor: 'line_bot', re: /[A-Za-z0-9+/=]{100,}/g };
// 三段式 JWT 格式(xxx.yyy.zzz),已由 M2 jwt-analyzer 專責分析,這裡需排除以免重複誤標
const JWT_SHAPE_PATTERN = /^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/;

/**
 * 遮罩比對到的字串,絕不可讓完整明文金鑰出現在輸出裡
 * @param {string} str
 * @returns {string}
 */
function maskMatch(str) {
  if (str.length <= 8) return '[MASKED]';
  return str.slice(0, 4) + '…' + str.slice(-4) + ' [MASKED]';
}

/**
 * @param {string} code - 使用者貼上的原始程式碼文字
 * @returns {Array<{tier:number, category:string, name:string, kind:string, evidence:string}>}
 */
function keyDetector(code) {
  const findings = [];

  KEY_RULES.forEach(rule => {
    const matches = code.match(rule.re);
    if (matches) {
      matches.forEach(m => {
        findings.push({
          tier: 1,
          category: '明文金鑰',
          name: rule.name,
          kind: 'plain_key',
          evidence: maskMatch(m),
          visualData: { vendor: rule.vendor }
        });
      });
    }
  });

  findings.push(...firebaseConfigDetector(code));
  findings.push(...lineBotTokenDetector(code));

  return findings;
}

/**
 * 獨立處理 Firebase apiKey:tier2 提醒性質,不是「機密外洩」。
 * @param {string} code
 * @returns {Array<{tier:number, category:string, name:string, kind:string, evidence:string}>}
 */
function firebaseConfigDetector(code) {
  const findings = [];
  const matches = code.match(FIREBASE_CONFIG_RULE.re);
  if (matches) {
    matches.forEach(m => {
      findings.push({
        tier: 2,
        category: '建議人工複查',
        name: 'Firebase 設定值（本身非機密，但請確認 Security Rules）',
        kind: 'firebase_config_exposed',
        evidence: maskMatch(m) + '　— Firebase apiKey 設計上就是要出現在前端程式碼中，本身外洩不構成風險，但實際的資料存取控制完全由 Firebase Security Rules 決定，建議確認'
      });
    });
  }
  return findings;
}

/**
 * 獨立處理 Line Bot Access Token:tier2 猜測式規則(見檔案頂部修正紀錄2)。
 * 排除三段式JWT格式(交給M2處理),避免同一段字串被兩個不同模組各報一次、
 * 標成兩種不同廠商造成使用者困惑。
 * @param {string} code
 * @returns {Array<{tier:number, category:string, name:string, kind:string, evidence:string}>}
 */
function lineBotTokenDetector(code) {
  const findings = [];
  const re = new RegExp(LINE_BOT_TOKEN_RULE.re.source, LINE_BOT_TOKEN_RULE.re.flags);
  let m;
  while ((m = re.exec(code)) !== null) {
    const matched = m[0];

    // ⚠️ 修正紀錄(2026,真實Lovable專案實測發現的問題):
    // 原本只用 JWT_SHAPE_PATTERN.test(matched) 檢查「匹配到的片段本身」是否為
    // 完整三段式JWT,但這個排除邏輯幾乎永遠失效——因為JWT的分隔符號 "." 不在
    // LINE_BOT_TOKEN_RULE.re 的字元集合[A-Za-z0-9+/=]內,正則掃描遇到"."就會
    // 截斷,實際只抓到JWT三段中的其中一段(通常是payload),這段本身當然不符合
    // "xxx.yyy.zzz"的完整格式,排除判斷因此形同虛設。實測發現:一組真實的
    // Supabase anon JWT會同時被M1的supabase_anon規則正確標記,又被這裡誤標成
    // Line Bot token,兩者互相矛盾,使用者會很困惑。
    // 修法:不檢查「匹配片段本身」,而是檢查「匹配片段的前後緊鄰處」是否存在
    // JWT的其他兩段(用.分隔、同樣是base64-like字元的片段)——如果前面或後面
    // 緊接著 "." + 另一段長度合理的base64-like字元,代表這其實是嵌在一個更大
    // JWT結構裡的其中一段,應該排除,交給M2(jwt-analyzer)處理整個JWT。
    const before = code.slice(Math.max(0, m.index - 400), m.index);
    const after = code.slice(m.index + matched.length, m.index + matched.length + 400);
    const jwtSegmentBefore = /[A-Za-z0-9_-]{8,}\.$/.test(before);
    const jwtSegmentAfter = /^\.[A-Za-z0-9_-]{8,}/.test(after);
    const looksLikeJwtFragment = JWT_SHAPE_PATTERN.test(matched) || jwtSegmentBefore || jwtSegmentAfter;

    if (looksLikeJwtFragment) continue; // 這是JWT的一部分(或完整JWT),交給M2 jwt-analyzer 處理,不在此重複標記

    findings.push({
      tier: 2,
      category: '建議人工複查',
      name: LINE_BOT_TOKEN_RULE.name,
      kind: 'line_bot_token_suspected',
      evidence: maskMatch(matched) + '　— 疑似 Line Bot channel access token，但 LINE 官方對此權杖無公開固定格式規則，本比對僅依「長度足夠的 base64 字元集合字串」判斷，誤判率高於已知格式金鑰（例如 base64 編碼的圖片、簽章值也可能誤觸發），請人工確認來源',
      visualData: { vendor: LINE_BOT_TOKEN_RULE.vendor }
    });
  }
  return findings;
}

// ── 環境相容匯出:Node.js(require)與瀏覽器(<script src>)共用同一份檔案 ──
// Node 測試環境: module 物件存在 → 走 module.exports,供 require() 使用
// 瀏覽器環境: module 不存在 → 略過這段,函式/常數已是全域作用域下的宣告,
//            可直接被 index.html 或其他 <script> 使用
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { keyDetector, firebaseConfigDetector, lineBotTokenDetector, maskMatch, KEY_RULES, FIREBASE_CONFIG_RULE, LINE_BOT_TOKEN_RULE };
}
