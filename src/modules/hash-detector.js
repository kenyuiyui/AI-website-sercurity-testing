/**
 * M3 — hash-detector
 * 詳細規格見 docs/modules/MODULE_03_hash-detector.md
 *
 * 職責:偵測用不安全雜湊演算法(MD5/SHA1)處理密碼的呼叫
 * 輸入: code (string)
 * 輸出: Finding[]
 *
 * 這是純函式,不依賴任何其他模組,可完全獨立開發與測試。
 * 已知限制: 只用函式名稱+參數名稱含 password/pwd/pass 判斷,
 * 不排除 md5(passwordHash) 這類非直接雜湊密碼本身的情境,見規格文件。
 */

const HASH_RULES = [
  { name: 'MD5 用於密碼儲存（疑似）', re: /md5\s*\(\s*(password|pwd|pass)/gi },
  { name: 'SHA1 用於密碼儲存（疑似）', re: /sha1\s*\(\s*(password|pwd|pass)/gi },
];

/**
 * @param {string} code
 * @returns {Array<{tier:number, category:string, name:string, kind:string, evidence:string}>}
 */
function hashDetector(code) {
  const findings = [];

  HASH_RULES.forEach(rule => {
    const matches = code.match(rule.re);
    if (matches) {
      matches.forEach(m => {
        findings.push({
          tier: 1,
          category: '弱雜湊演算法',
          name: rule.name,
          kind: 'weak_hash',
          evidence: m.length > 40 ? m.slice(0, 40) + '…' : m
        });
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
