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
 */

// 真正的機密金鑰:外洩即代表任何人都能冒用,需要撤銷重新產生
// vendor 是給 M8 查對應「這組金鑰能做什麼」知識庫用的識別碼(純正則沒有能力
// 從程式碼萃取更多結構化資訊,這是 M1 視覺化展示唯一能提供的真實資料)
const KEY_RULES = [
  { name: 'OpenAI API Key', vendor: 'openai', re: /sk-proj-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,}/g },
  { name: 'Anthropic API Key', vendor: 'anthropic', re: /sk-ant-[A-Za-z0-9_-]{20,}/g },
  { name: 'Google / Gemini API Key', vendor: 'google_gemini', re: /AIzaSy[A-Za-z0-9_-]{33}/g },
  { name: 'Line Bot Access Token', vendor: 'line_bot', re: /[A-Za-z0-9+/=]{100,}/g },
  { name: 'AWS Access Key ID', vendor: 'aws', re: /AKIA[0-9A-Z]{16}/g },
];

// Firebase 設定值:官方設計為可公開的專案識別碼,不是機密,獨立處理
const FIREBASE_CONFIG_RULE = { name: 'Firebase 設定值', re: /"apiKey"\s*:\s*"[A-Za-z0-9_-]{20,}"/g };

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

// ── 環境相容匯出:Node.js(require)與瀏覽器(<script src>)共用同一份檔案 ──
// Node 測試環境: module 物件存在 → 走 module.exports,供 require() 使用
// 瀏覽器環境: module 不存在 → 略過這段,函式/常數已是全域作用域下的宣告,
//            可直接被 index.html 或其他 <script> 使用
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { keyDetector, firebaseConfigDetector, maskMatch, KEY_RULES, FIREBASE_CONFIG_RULE };
}
