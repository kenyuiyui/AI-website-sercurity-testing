/**
 * M14 — xss-detector
 *
 * 職責:找出「把資料直接組成 HTML 塞進頁面」的寫法(innerHTML／outerHTML／insertAdjacentHTML／
 * document.write／jQuery .html()),判斷插進去的值有沒有經過跳脫。
 * 輸入: code (string)、ctx(選用,取得 source-mask)
 * 輸出: Finding[]
 *
 * 兩種層級:
 *   xss_from_url    — 值直接來自網址或輸入框(location.hash、input.value…):幾乎可以確定會出事
 *   html_from_data  — 值來自資料(物件欄位、變數)且沒看到跳脫:要人工確認
 *
 * 為什麼:純前端網站最主要的風險就是 XSS,但原本一條規則都沒有(實測一個純前端網站時發現)。(背景見 docs/CHANGELOG.md)
 *
 * 控制誤報的三道門檻(誠實記錄:這是取捨,會有漏判):
 *   1. 只看真正的程式碼(source-mask),說明文字與註解裡的範例不算
 *   2. 插值本身含跳脫字樣(escape/sanitize/encodeURI/DOMPurify)、或名字看起來已經是 HTML
 *      片段(safeXxx、xxxHtml)、或是數字類(length/count/index)就不算
 *   3'. 只追一層變數:`const t = `…${c.name}…`; el.innerHTML = `…${t}…`` 這種先組好再塞的寫法會追到,
 *       但再多轉一手(函式回傳、跨檔案)就追不到了
 *   3. html_from_data 還要求這個檔案真的有「外部資料」(localStorage、JSON.parse、fetch、
 *      檔案讀取、網址參數、輸入框),純靜態拼字串的頁面不報
 */

// 把字串當 HTML 放進頁面的寫法
const XSS_SINK_RE = /(?:\.(?:innerHTML|outerHTML)\s*=\s*)|(?:\.insertAdjacentHTML\s*\(\s*(?:['"][^'"]*['"])\s*,\s*)|(?:document\s*\.\s*write(?:ln)?\s*\()|(?:\)\s*\.html\s*\()/g;
// 直接來自使用者或網址的值
const XSS_SOURCE_RE = /location\s*\.\s*(?:hash|search|href|pathname)|document\s*\.\s*(?:URL|documentURI|referrer)|URLSearchParams|\.\s*value\b|innerText\b|\.\s*textContent\b/;
// 這個檔案有沒有外部進來的資料
const XSS_EXTERNAL_DATA_RE = /localStorage|sessionStorage|JSON\s*\.\s*parse|fetch\s*\(|FileReader|URLSearchParams|location\s*\.|\.\s*value\b|req\s*\.\s*(?:body|query|params)/;
// 已經處理過、或根本不是使用者資料的插值
const XSS_SAFE_PART_RE = /escape|sanitiz|encodeURI|DOMPurify|purify|textContent|^['"`]|^-?\d|^(?:true|false|null|undefined)$|\.length$|\.size$|^safe|Html$|HTML$|Icons\s*\.\s*get|getIcon/i;
// 看起來是「人打進去的文字」的欄位名。只報這一類,是為了讓結果可信:
// class 名稱、旗標、編號這種插值雖然也沒跳脫,但幾乎不會是攻擊來源,全報只會淹掉真正的問題。
// 代價是會漏掉命名特殊的欄位——這是刻意的取捨,已寫在「做不到」清單裡。
const XSS_TEXT_FIELD_RE = /\b(?:name|title|text|label|message|msg|content|description|desc|comment|note|memo|remark|author|user|username|nick|email|address|room|teacher|subject|query|search|keyword|term|input|value|url|link|href|filename)\b/i;

/** 從 sink 後面讀出這一段運算式(追蹤引號與括號,最多 600 字) */
function xssReadExpression(code, start) {
  let i = start;
  let depth = 0;
  let quote = null;
  let out = '';
  while (i < code.length && out.length < 600) {
    const ch = code[i];
    if (quote) {
      if (ch === '\\') { out += ch + (code[i + 1] || ''); i += 2; continue; }
      if (ch === quote) quote = null;
    } else if (ch === '`' || ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === '(' || ch === '[' || ch === '{') {
      depth++;
    } else if (ch === ')' || ch === ']' || ch === '}') {
      if (depth === 0) break;
      depth--;
    } else if (ch === ';' && depth === 0) {
      break;
    } else if (ch === '\n' && depth === 0
      && !/[+,?:&|(]\s*$/.test(out)
      // 換行後接著 .map(…)、+ … 這類接續寫法時,這段運算式還沒結束
      && !/^\s*[.+?:,&|]/.test(code.slice(i + 1, i + 40))) {
      break;
    }
    out += ch;
    i++;
  }
  return out;
}

/** 運算式裡「會變動的部分」:樣板字串的 ${…} 與字串相加的識別字 */
function xssDynamicParts(expr) {
  const parts = [];
  for (const m of expr.matchAll(/\$\{([^{}]{1,150})\}/g)) parts.push(m[1].trim());
  // 字串相加:把字面字串挖掉,剩下的識別字就是動態的部分
  const stripped = expr.replace(/`(?:[^`\\]|\\.)*`|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g, '""');
  // 有分號代表讀到的是一整個程式區塊(例如 items.map(it => { … })),
  // 這時只有樣板字串的 ${…} 才是真的插進 HTML;區塊裡的變數宣告不算。
  if (stripped.indexOf('+') >= 0 && stripped.indexOf(';') < 0) {
    // 允許鏈中間有呼叫,document.getElementById('q').value 才不會被拆成兩段而看不出是輸入框
    const CHAIN_RE = /[A-Za-z_$][\w$]*(?:\s*\([^()]{0,80}\))?(?:\s*\.\s*[A-Za-z_$][\w$]*(?:\s*\([^()]{0,80}\))?|\[[^\]]{1,20}\])*/g;
    for (const m of stripped.matchAll(CHAIN_RE)) parts.push(m[0].trim());
  }
  return parts.filter(p => p && !XSS_SAFE_PART_RE.test(p));
}

/** 同一個檔案裡 const/let/var NAME = … 的右邊那段(只追一層,避免變成半套的資料流分析) */
function xssResolveLocal(code, name) {
  if (!/^[A-Za-z_$][\w$]*$/.test(name)) return null;
  const m = new RegExp('(?:const|let|var)\\s+' + name + '\\s*=\\s*').exec(code);
  return m ? xssReadExpression(code, m.index + m[0].length) : null;
}

/**
 * 這個值(或它背後的中繼變數)是不是來自網址／輸入框。
 * 網址參數回顯是最典型的 XSS,而它幾乎都寫成兩段:
 *   const params = new URLSearchParams(location.search);
 *   const keyword = params.get('q');
 * 所以這個判斷允許再往回追一層(只有這裡追兩層,一般資料仍然只追一層)。
 */
function xssLooksLikeUrlSource(code, expr, depth) {
  if (XSS_SOURCE_RE.test(expr)) return true;
  if ((depth || 0) >= 1) return false;
  return (expr.match(/[A-Za-z_$][\w$]*/g) || []).slice(0, 5).some(id => {
    const src = xssResolveLocal(code, id);
    // 只追「短的、像一個值」的變數;整包工具物件(const Utils = { … })裡面一定找得到
    // .value、textContent 之類的字樣,展開它只會得到錯的結論
    if (!src || src.length > 120 || /^\s*\{/.test(src)) return false;
    return xssLooksLikeUrlSource(code, src, (depth || 0) + 1);
  });
}

/**
 * @param {string} code
 * @param {object} [ctx] - scan-orchestrator 的 ctx(取 mask)
 * @returns {Array}
 */
function xssDetector(code, ctx) {
  const findings = [];
  const mask = (typeof resolveCodeMask === 'function' ? resolveCodeMask : require('./source-mask').resolveCodeMask)(code, ctx);
  const inCode = i => !mask || i >= mask.length || mask[i] === 0;
  const hasExternalData = XSS_EXTERNAL_DATA_RE.test(code);

  const re = new RegExp(XSS_SINK_RE.source, XSS_SINK_RE.flags);
  let m;
  while ((m = re.exec(code)) !== null) {
    if (!inCode(m.index)) continue;
    const expr = xssReadExpression(code, m.index + m[0].length);
    if (!expr.trim()) continue;
    let parts = xssDynamicParts(expr);
    // innerHTML = location.hash 這種「整段就是一個運算式」的寫法,沒有樣板字串也沒有相加
    const bare = expr.trim();
    if (!parts.length && /^[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*|\[[^\]]{1,20}\])*$/.test(bare) && !XSS_SAFE_PART_RE.test(bare)) parts = [bare];
    // 整段都是寫死的字串(例如 innerHTML = '')不算
    if (!parts.length) continue;

    // 只看「會變動的部分」本身,不看整段樣板(樣板裡的 HTML 可能剛好含 this.value 之類的字樣)
    const textParts = parts.filter(p => XSS_TEXT_FIELD_RE.test(p));
    const urlParts = parts.filter(p => XSS_SOURCE_RE.test(p));
    // 一跳追蹤:插進去的是個變數時,回頭看那個變數是怎麼組出來的
    parts.forEach(p => {
      if (!/^[A-Za-z_$][\w$]*$/.test(p)) return;
      const src = xssResolveLocal(code, p);
      if (!src) return;
      // 這個變數就是跳脫後的結果(const task = escapeHtml(it.task))→ 安全,不要再往下判斷
      if (/escape|sanitiz|encodeURI|DOMPurify|purify/i.test(src)) return;
      // 變數本身就是網址／輸入框的內容 → 升級成「確定會出事」那一級
      if (xssLooksLikeUrlSource(code, src, 0)) {
        if (urlParts.indexOf(p) < 0) urlParts.push(p + '（內容來自網址或輸入框）');
        return;
      }
      if (textParts.indexOf(p) >= 0) return;
      const inner = xssDynamicParts(src).filter(x => XSS_TEXT_FIELD_RE.test(x));
      if (inner.length) textParts.push(p + '（內容是 ' + inner.slice(0, 2).join('、') + '）');
    });
    if (!textParts.length && !urlParts.length) continue;

    if (urlParts.length) {
      findings.push({
        tier: 1,
        category: '跨站腳本（XSS）',
        name: '網址或輸入框的內容被直接當成 HTML',
        kind: 'xss_from_url',
        index: m.index,
        evidence: '這裡把 ' + urlParts.slice(0, 2).join('、') + ' 直接組成 HTML 放進頁面，而這個值來自網址或輸入框，沒有看到跳脫處理'
      });
    } else if (hasExternalData) {
      findings.push({
        tier: 2,
        category: '建議人工複查',
        name: '資料被直接組成 HTML（疑似 XSS）',
        kind: 'html_from_data',
        index: m.index,
        evidence: '這裡把 ' + textParts.slice(0, 3).join('、') + ' 直接組成 HTML 放進頁面，沒有看到跳脫處理（例如 escapeHTML）'
      });
    }
  }

  return findings;
}

// ── 環境相容匯出:Node.js(require)與瀏覽器(<script src>)共用同一份檔案 ──
// Node 測試環境: module 物件存在 → 走 module.exports,供 require() 使用
// 瀏覽器環境: module 不存在 → 略過這段,函式/常數已是全域作用域下的宣告,
//            可直接被 index.html 或其他 <script> 使用
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { xssDetector };
}
