/**
 * M3 — hash-detector
 *
 * 職責:偵測用不安全雜湊演算法(MD5/SHA1)處理密碼的呼叫
 * 輸入: code (string)
 * 輸出: Finding[]
 *
 * 這是純函式,不依賴任何其他模組,可完全獨立開發與測試。
 * 已知限制: 只用函式名稱+參數名稱含 password/pwd/pass 判斷,
 * 不排除 md5(passwordHash) 這類非直接雜湊密碼本身的情境,見規格文件。
 */

// Python hashlib.new('md5') 先建構、再 .update(password) 分兩段餵入的寫法
// (SecurityEval CWE-759_mitre_1)。同樣要求 update 的參數名含 password/pwd/pass,
// 避免誤傷 hashlib.new('md5') 用於檔案校驗等非密碼用途(見 legacy-tn-006)。
const HASH_RULES = [
  { name: 'MD5 用於密碼儲存（疑似）', re: /md5\s*\(\s*(password|pwd|pass)/gi },
  { name: 'SHA1 用於密碼儲存（疑似）', re: /sha1\s*\(\s*(password|pwd|pass)/gi },
  { name: 'MD5 用於密碼儲存（疑似，hashlib.new 兩段式寫法）', re: /hashlib\.new\(\s*['"]md5['"]\s*\)[\s\S]{0,200}?\.update\s*\(\s*(password|pwd|pass)/gi },
  { name: 'SHA1 用於密碼儲存（疑似，hashlib.new 兩段式寫法）', re: /hashlib\.new\(\s*['"]sha1['"]\s*\)[\s\S]{0,200}?\.update\s*\(\s*(password|pwd|pass)/gi },
];

/**
 * 為什麼:只對「真正的程式碼」報警,字串、註解、規則定義裡的 md5(password 不算(見 source-mask.js)。
 * @param {string} code
 * @param {{mask?: Uint8Array, language?: string}} [ctx] - scan-orchestrator 傳入的共用遮罩
 * @returns {Array<{tier:number, category:string, name:string, kind:string, evidence:string}>}
 */
function hashDetector(code, ctx) {
  const findings = [];
  const mask = (typeof resolveCodeMask === 'function' ? resolveCodeMask : require('./source-mask').resolveCodeMask)(code, ctx);

  HASH_RULES.forEach(rule => {
    const re = new RegExp(rule.re.source, rule.re.flags);
    let m;
    while ((m = re.exec(code)) !== null) {
      if (mask && m.index < mask.length && mask[m.index] !== 0) continue;
      const text = m[0];
      findings.push({
        tier: 1,
        category: '弱雜湊演算法',
        name: rule.name,
        kind: 'weak_hash',
        match: text,
        index: m.index,
        evidence: text.length > 40 ? text.slice(0, 40) + '…' : text
      });
    }
  });

  return findings;
}

// ── 環境相容匯出:Node.js(require)與瀏覽器(<script src>)共用同一份檔案 ──
// Node 測試環境: module 物件存在 → 走 module.exports,供 require() 使用
// 瀏覽器環境: module 不存在 → 略過這段,函式/常數已是全域作用域下的宣告,
//            可直接被 index.html 或其他 <script> 使用
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { hashDetector, HASH_RULES };
}
