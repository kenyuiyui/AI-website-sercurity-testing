/**
 * M1 — key-detector
 *
 * 職責:掃描程式碼,找出已知格式的明文 API 金鑰
 * 輸入: code (string)
 * 輸出: Finding[]
 *
 * 這是純函式,不依賴任何其他模組,可完全獨立開發與測試。
 *
 * 為什麼:Firebase apiKey 設計上可公開 → 獨立為 tier2 firebase_config_exposed,不當外洩處理。(背景見 docs/CHANGELOG.md)
 *
 * 為什麼:Line Bot token 無固定格式 → tier2 猜測規則,並排除 JWT(交給 M2)。(背景見 docs/CHANGELOG.md)
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
// 判斷方式:AIzaSy 金鑰「以 apiKey 屬性指派」且「前後 600 字元內有 Firebase 設定特徵」才算 Firebase 設定,
// 否則仍當成 Google / Gemini 金鑰(tier1)。同一個值只會被其中一條規則回報。
const FIREBASE_CONFIG_RULE = {
  name: 'Firebase 設定值',
  keyRe: /AIzaSy[A-Za-z0-9_-]{33}/g,
  assignedAsApiKey: /["']?apiKey["']?\s*[:=]\s*["'`]?$/,
  context: /authDomain|firebaseapp\.com|firebaseio\.com|projectId|storageBucket|messagingSenderId|initializeApp\s*\(|firebase\/app|firebase-app/,
  window: 600
};

/**
 * 某個 AIzaSy 金鑰是否位於 Firebase 設定物件內
 * @param {string} code
 * @param {number} index - 金鑰起始位置
 */
function isFirebaseConfigKey(code, index) {
  const before = code.slice(Math.max(0, index - 40), index);
  if (!FIREBASE_CONFIG_RULE.assignedAsApiKey.test(before)) return false;
  const around = code.slice(Math.max(0, index - FIREBASE_CONFIG_RULE.window), index + FIREBASE_CONFIG_RULE.window);
  return FIREBASE_CONFIG_RULE.context.test(around);
}

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
    const re = new RegExp(rule.re.source, rule.re.flags);
    let km;
    while ((km = re.exec(code)) !== null) {
      const m = km[0];
      // Firebase 設定裡的 apiKey 交給 firebaseConfigDetector,不當成外洩
      if (rule.vendor === 'google_gemini' && isFirebaseConfigKey(code, km.index)) continue;
      findings.push({
        tier: 1,
        category: '明文金鑰',
        name: rule.name,
        kind: 'plain_key',
        evidence: maskMatch(m),
        match: m,
        index: km.index,
        visualData: { vendor: rule.vendor }
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
  const re = new RegExp(FIREBASE_CONFIG_RULE.keyRe.source, FIREBASE_CONFIG_RULE.keyRe.flags);
  let m;
  while ((m = re.exec(code)) !== null) {
    if (!isFirebaseConfigKey(code, m.index)) continue;
    findings.push({
      tier: 2,
      category: '建議人工複查',
      name: 'Firebase 設定值（本身非機密，但請確認 Security Rules）',
      kind: 'firebase_config_exposed',
      match: m[0],
      index: m.index,
      evidence: maskMatch(m[0]) + '　— Firebase apiKey 設計上就是要出現在前端程式碼中，本身外洩不構成風險，但實際的資料存取控制完全由 Firebase Security Rules 決定，建議確認'
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

    // 為什麼:排除 JWT 片段要檢查「前後緊鄰」是否有 .xxx 段,只看匹配片段本身會失效。(背景見 docs/CHANGELOG.md)
    const before = code.slice(Math.max(0, m.index - 400), m.index);
    const after = code.slice(m.index + matched.length, m.index + matched.length + 400);
    const jwtSegmentBefore = /[A-Za-z0-9_-]{8,}\.$/.test(before);
    const jwtSegmentAfter = /^\.[A-Za-z0-9_-]{8,}/.test(after);
    const looksLikeJwtFragment = JWT_SHAPE_PATTERN.test(matched) || jwtSegmentBefore || jwtSegmentAfter;

    // eyJ 開頭是 base64 編碼的 JSON(JWT 的某一段被拆成獨立字串時也是),不會是 LINE 權杖
    if (looksLikeJwtFragment || /^eyJ/.test(matched)) continue; // 這是JWT的一部分(或完整JWT),交給M2 jwt-analyzer 處理,不在此重複標記

    findings.push({
      tier: 2,
      category: '建議人工複查',
      name: LINE_BOT_TOKEN_RULE.name,
      kind: 'line_bot_token_suspected',
      index: m.index,
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
  module.exports = { isFirebaseConfigKey, keyDetector, firebaseConfigDetector, lineBotTokenDetector, maskMatch, KEY_RULES, FIREBASE_CONFIG_RULE, LINE_BOT_TOKEN_RULE };
}
