/**
 * M5 — csp-detector
 *
 * 職責:判斷 Content Security Policy 有沒有設定、設定得夠不夠緊,區分 HTML 情境與框架設定檔情境
 * 輸入: code (string)
 * 輸出: Finding[]
 *
 * 這是純函式,不依賴任何其他模組,可完全獨立開發與測試。
 * 重點:避免對框架化專案(Next.js/Nuxt)的系統性誤判,見規格文件說明。
 *
 * 為什麼:有 CSP 但寫了 'unsafe-inline' 等於幾乎沒有防線,只看「有沒有設定」會給出假的安心。(背景見 docs/CHANGELOG.md)
 */

// 取出 CSP 的內容:<meta ... content="…"> 或設定檔裡 "Content-Security-Policy": "…"。
// 用反向參照鎖定同一種引號,因為 CSP 內容本身就含有單引號('self'、'unsafe-inline')。
const CSP_VALUE_RE = /content-security-policy[\s\S]{0,120}?(["'])((?:(?!\1)[\s\S]){10,}?)\1/i;
// 放寬到形同虛設的寫法(只看 script 相關指令)
const CSP_WEAKNESSES = [
  { re: /'unsafe-inline'/i, label: "'unsafe-inline'（允許直接寫在網頁裡的程式碼執行）" },
  { re: /'unsafe-eval'/i, label: "'unsafe-eval'（允許把文字當程式執行）" },
  { re: /(^|\s)\*(\s|$)/, label: '* 萬用字元（等於允許任何網站的程式碼）' }
];

/** 只看 script 相關的指令:style-src 的 'unsafe-inline' 風險低很多,不在這裡報 */
function cspScriptPart(csp) {
  const m = /script-src([^;]*)/i.exec(csp);
  if (m) return m[1];
  const d = /default-src([^;]*)/i.exec(csp);
  return d ? d[1] : '';
}

/**
 * @param {string} code
 * @returns {Array<{tier:number, category:string, name:string, kind:string, evidence:string}>}
 */
function cspDetector(code) {
  const findings = [];

  const looksLikeHtml = /<html|<head|<!DOCTYPE/i.test(code);
  const looksLikeFrameworkConfig = /\bNextConfig\b|defineNuxtConfig\s*\(|module\.exports\s*=\s*{[\s\S]*?headers\s*:|async\s+headers\s*\(\s*\)\s*{|"headers"\s*:\s*\[/i.test(code);
  const hasCsp = /content-security-policy/i.test(code);

  if (hasCsp) {
    const value = (CSP_VALUE_RE.exec(code) || [])[2] || '';
    const scriptPart = cspScriptPart(value);
    const weak = CSP_WEAKNESSES.filter(w => w.re.test(scriptPart)).map(w => w.label);
    if (weak.length) {
      findings.push({
        tier: 2,
        category: '建議人工複查',
        name: 'CSP 有放寬設定，防護力打折',
        kind: 'csp_weak',
        evidence: 'CSP 的 script-src 含有 ' + weak.join('、') + '；這些設定會讓 CSP 擋不住最常見的 XSS 注入'
      });
    }
  }

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
