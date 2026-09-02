/**
 * M5 — csp-detector
 * 詳細規格見 docs/modules/MODULE_05_csp-detector.md
 *
 * 職責:判斷 Content Security Policy 是否有設定,區分 HTML 情境與框架設定檔情境
 * 輸入: code (string)
 * 輸出: Finding[]
 *
 * 這是純函式,不依賴任何其他模組,可完全獨立開發與測試。
 * 重點:避免對框架化專案(Next.js/Nuxt)的系統性誤判,見規格文件說明。
 */

/**
 * @param {string} code
 * @returns {Array<{tier:number, category:string, name:string, kind:string, evidence:string}>}
 */
function cspDetector(code) {
  const findings = [];

  const looksLikeHtml = /<html|<head|<!DOCTYPE/i.test(code);
  const looksLikeFrameworkConfig = /\bNextConfig\b|defineNuxtConfig\s*\(|module\.exports\s*=\s*{[\s\S]*?headers\s*:|async\s+headers\s*\(\s*\)\s*{|"headers"\s*:\s*\[/i.test(code);
  const hasCsp = /content-security-policy/i.test(code);

  if (looksLikeHtml && !hasCsp) {
    findings.push({
      tier: 1,
      category: '基礎設定',
      name: '未偵測到 Content Security Policy',
      kind: 'no_csp_html',
      evidence: '頁面中無 CSP meta 標籤；若此頁面屬於 Next.js／Nuxt 等框架專案，CSP 也可能設定在 next.config.js 的 headers() 或 vercel.json 中，建議一併確認'
    });
  } else if (looksLikeFrameworkConfig && !hasCsp) {
    findings.push({
      tier: 2,
      category: '建議人工複查',
      name: '框架設定檔中未偵測到 CSP 設定（疑似）',
      kind: 'no_csp_config',
      evidence: '此設定檔看起來像 next.config／vercel.json 等框架設定檔，但未找到 Content-Security-Policy 字樣，建議確認是否有在其他設定檔或部署平台後台單獨設定'
    });
  }

  return findings;
}

// ── 環境相容匯出:Node.js(require)與瀏覽器(<script src>)共用同一份檔案 ──
// Node 測試環境: module 物件存在 → 走 module.exports,供 require() 使用
// 瀏覽器環境: module 不存在 → 略過這段,函式/常數已是全域作用域下的宣告,
//            可直接被 index.html 或其他 <script> 使用
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { cspDetector };
}
