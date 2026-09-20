/**
 * M5 — csp-detector
 *
 * 職責:判斷 Content Security Policy(CSP)有沒有設定、設定得夠不夠緊、寫法有沒有錯,區分 HTML 情境與框架設定檔情境
 * 輸入: code (string)
 * 輸出: Finding[]
 *
 * 這是純函式,不依賴任何其他模組,可完全獨立開發與測試。
 * 重點:避免對框架化專案(Next.js/Nuxt)的系統性誤判,見規格文件說明。
 *
 * 流程:取出 CSP → 拆成「指令 → 來源清單」→ 逐項檢查 → 同一份 CSP 的同類問題合併成一筆。
 * 檢查面向(對照公開的 CSP 評估工具的視野,但規則與說明是自己寫的,清單也刻意精簡):
 *   csp_weak              放行行內程式碼／eval／整個協定／萬用字元／http／寫死的 nonce,或完全沒管腳本
 *   csp_allowlist_bypass  白名單放了「借得到別人程式碼」的網域(公共 CDN、共用主機的萬用網域、JSONP 端點)
 *   csp_missing_directive 缺 object-src;用 nonce／雜湊卻沒管 base-uri
 *   csp_syntax            指令拼錯、漏分號、關鍵字沒加引號、nonce／雜湊格式不對、指令重複、已淘汰的寫法
 *   csp_not_enforced      設了但沒生效:<meta> 不支援的指令、放在腳本後面、Report-Only
 * 現代瀏覽器的語意要照著判:有 nonce／雜湊時 'unsafe-inline' 會被忽略,有 'strict-dynamic' 時白名單與協定會被忽略,
 * 所以那幾種寫法(常見的相容寫法)不能報,否則會冤枉寫得好的 CSP。
 *
 * 為什麼:有 CSP 但寫了 'unsafe-inline' 等於幾乎沒有防線,只看「有沒有設定」會給出假的安心;
 *        而 CSP 一旦寫錯字或放行了共用網域,瀏覽器不會報錯,只會默默失效。(背景見 docs/CHANGELOG.md)
 */

// ── 規格資料 ──
const CSP_FETCH = ['default-src', 'script-src', 'script-src-elem', 'script-src-attr', 'style-src', 'style-src-elem', 'style-src-attr',
  'img-src', 'font-src', 'connect-src', 'media-src', 'object-src', 'frame-src', 'child-src', 'worker-src', 'manifest-src'];
const CSP_SOURCE_LISTS = new Set(CSP_FETCH.concat(['base-uri', 'form-action', 'frame-ancestors']));
const CSP_DIRECTIVES = new Set(CSP_SOURCE_LISTS);
['sandbox', 'report-uri', 'report-to', 'upgrade-insecure-requests', 'require-trusted-types-for', 'trusted-types'].forEach(d => CSP_DIRECTIVES.add(d));
const CSP_DEPRECATED = new Set(['reflected-xss', 'referrer', 'disown-opener', 'prefetch-src', 'block-all-mixed-content', 'plugin-types', 'require-sri-for', 'navigate-to']);
const CSP_KEYWORDS = ['self', 'none', 'unsafe-inline', 'unsafe-eval', 'unsafe-hashes', 'strict-dynamic', 'report-sample', 'wasm-unsafe-eval', 'inline-speculation-rules', 'trusted-types-eval'];
// <meta> 方式送出的 CSP,瀏覽器會直接忽略這幾個指令(規格明訂,只能用 HTTP 標頭)
const CSP_META_IGNORED = { 'frame-ancestors': '防止被別人的網頁嵌入', 'report-uri': '違規回報', 'report-to': '違規回報', sandbox: 'sandbox 限制' };
const CSP_PLACEHOLDER = '\u0001'; // ${…}、{{…}}、<%…%> 這類「執行時才填進去」的值(常見於 nonce)

// 白名單裡「借得到別人程式碼」的網域。只列常見的,一定不完整——沒列到不代表安全。
const CSP_BYPASS_HOSTS = {
  'ajax.googleapis.com': '託管 AngularJS 等函式庫，攻擊者能借它們執行自己的程式碼',
  'cdnjs.cloudflare.com': '託管 AngularJS 等舊函式庫，攻擊者能借它們執行自己的程式碼',
  'code.angularjs.org': '專門提供 AngularJS，攻擊者能借它執行自己的程式碼',
  'accounts.google.com': '有可被利用的 JSONP 端點，攻擊者能借它執行自己的程式碼',
  'www.google.com': '有可被利用的 JSONP 端點，攻擊者能借它執行自己的程式碼',
  'www.googleapis.com': '有可被利用的 JSONP 端點，攻擊者能借它執行自己的程式碼',
  'cdn.jsdelivr.net': '任何人都能把檔案發佈到這個 CDN，攻擊者可以載入自己的程式碼',
  'unpkg.com': '任何人都能把檔案發佈到這個 CDN，攻擊者可以載入自己的程式碼',
  'esm.sh': '任何人都能把檔案發佈到這個 CDN，攻擊者可以載入自己的程式碼',
  'cdn.skypack.dev': '任何人都能把檔案發佈到這個 CDN，攻擊者可以載入自己的程式碼',
  'raw.githack.com': '能直接載入任何 GitHub 儲存庫的檔案，攻擊者可以載入自己的程式碼',
  'rawcdn.githack.com': '能直接載入任何 GitHub 儲存庫的檔案，攻擊者可以載入自己的程式碼',
  'storage.googleapis.com': '整個雲端儲存都放行，任何人都能建立儲存桶放自己的程式碼',
  's3.amazonaws.com': '整個雲端儲存都放行，任何人都能建立儲存桶放自己的程式碼'
};
// 「*.這些網域」代表放行任何人在該平台架的網站
const CSP_SHARED_HOSTING = ['github.io', 'vercel.app', 'netlify.app', 'pages.dev', 'workers.dev', 'herokuapp.com', 'appspot.com', 'web.app',
  'firebaseapp.com', 'azurewebsites.net', 'cloudfront.net', 'amazonaws.com', 'blob.core.windows.net', 'glitch.me', 'repl.co', 'onrender.com',
  'fly.dev', 'surge.sh', 'ngrok.io', 'ngrok-free.app', 'r2.dev'];

// ── 小工具 ──
function cspAdd(arr, s) { if (arr.indexOf(s) < 0) arr.push(s); }

/** 編輯距離(只用來在打錯字時提示「是不是想寫 xxx」) */
function cspDist(a, b) {
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    prev = cur;
  }
  return prev[b.length];
}
function cspClosest(word, list) {
  let best = '';
  let bd = 3;
  list.forEach(c => { const d = cspDist(word, c); if (d < bd) { bd = d; best = c; } });
  return best;
}

/** 來源 → 主機名稱(去掉協定、埠號、路徑) */
function cspHost(tok) {
  return tok.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/[\/?#].*$/, '').replace(/:(\d+|\*)$/, '').toLowerCase();
}

// ── 1. 取出 CSP ──
// 每筆:{ text, source: 'meta'|'header'|'string'|'helmet', reportOnly, index, defaultsFilled? }

function cspNormalize(raw) {
  return raw.replace(/\$\{[^}]*\}|\{\{[^}]*\}\}|<%[\s\S]*?%>|%[A-Za-z_]+%|__[A-Za-z_]+__/g, CSP_PLACEHOLDER)
    .replace(/\\[nrt]/g, ' ').replace(/\\(.)/g, '$1').replace(/\s+/g, ' ').trim();
}

/** 這段文字像不像 CSP:至少有 min 個「以已知指令開頭」的片段 */
function cspLooksLikePolicy(text, min) {
  const n = text.split(';').filter(p => {
    const name = p.trim().split(/\s+/)[0].toLowerCase();
    return CSP_DIRECTIVES.has(name) || CSP_DEPRECATED.has(name);
  }).length;
  return n >= min;
}

/** helmet 的 directives 物件:{ scriptSrc: ["'self'"], ... } → 一般 CSP 文字 */
function cspHelmetPolicies(code) {
  const out = [];
  const re = /\bdirectives\s*:\s*\{/g;
  let m;
  while ((m = re.exec(code))) {
    let depth = 1;
    let i = re.lastIndex;
    const limit = Math.min(code.length, i + 6000); // 設定物件不會太長;有上限才不會被一堆沒閉合的括號拖慢
    while (i < limit && depth > 0) { const c = code[i++]; if (c === '{') depth++; else if (c === '}') depth--; }
    const block = code.slice(re.lastIndex, i - 1);
    re.lastIndex = Math.max(re.lastIndex, i);
    if (depth > 0) continue;
    const parts = [];
    const entry = /(["']?)([A-Za-z][\w-]*)\1\s*:\s*(\[[\s\S]*?\]|"[^"]*"|'[^']*'|`[^`]*`|true|false|null)/g;
    let e;
    while ((e = entry.exec(block))) {
      const name = e[2].replace(/[A-Z]/g, c => '-' + c.toLowerCase());
      const toks = [];
      const str = /(["'`])((?:\\.|(?!\1)[^\\])*)\1/g;
      let s;
      while ((s = str.exec(e[3]))) toks.push(s[2]);
      parts.push(name + ' ' + toks.join(' '));
    }
    if (!parts.length) continue;
    const around = code.slice(Math.max(0, m.index - 200), i + 200);
    out.push({ text: cspNormalize(parts.join('; ')), source: 'helmet', reportOnly: /reportOnly\s*:\s*true/.test(around), index: m.index, defaultsFilled: !/useDefaults\s*:\s*false/.test(around) });
  }
  return out;
}

function cspExtract(code, looksLikeHtml) {
  const policies = [];
  const push = p => { if (p.text && !policies.some(q => q.text === p.text)) policies.push(p); }; // 同一段文字只算一次,以先找到的為準(有標頭名稱的比純字串可靠)
  // HTML 註解裡的範例不算(用字串拼接寫,避免單檔版內嵌時被誤判成 HTML 註解開頭)
  const html = code.replace(new RegExp('<' + '!--[\\s\\S]*?-->', 'g'), m => ' '.repeat(m.length));

  // <meta http-equiv="Content-Security-Policy" content="…">(屬性順序、引號種類、JSX 的 httpEquiv 都可)
  const tagRe = /<meta\b[^>]{0,3000}>/gi; // 長度上限:避免沒有結尾 > 的超長輸入讓比對變成平方時間
  let t;
  while ((t = tagRe.exec(html))) {
    const eq = /http-?equiv\s*=\s*["']?\s*content-security-policy(-report-only)?/i.exec(t[0]);
    if (!eq) continue;
    const c = /\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(t[0]);
    const text = c ? cspNormalize(c[1] !== undefined ? c[1] : c[2]) : '';
    // 至少要像「指令 + 值」;說明文字裡寫的 content="…" 之類不算(拼錯的指令仍會被抓到)
    if (/[a-z][a-z-]+ \S/i.test(text)) push({ text, source: 'meta', reportOnly: !!eq[1], index: t.index });
  }

  // 標頭名稱後面接字串:JSON、setHeader('…', '…')、{ key: '…', value: '…' }、nginx add_header、Apache Header set
  const strRe = /content-security-policy(-report-only)?["'`]?\s*[:=,)]?\s*(?:value\s*:\s*)?(["'`])((?:\\[\s\S]|(?!\2)[^\\])*)\2/gi;
  let s;
  while ((s = strRe.exec(html))) {
    const text = cspNormalize(s[3]);
    if (cspLooksLikePolicy(text, 1)) push({ text, source: 'header', reportOnly: !!s[1], index: s.index });
  }

  // 沒有引號的原始標頭:Content-Security-Policy: default-src 'self'(_headers 檔、貼上的 HTTP 回應)
  const rawRe = /^[ \t]*content-security-policy(-report-only)?[ \t]*:[ \t]*([^"'`\r\n][^\r\n]*)$/gim;
  let r;
  while ((r = rawRe.exec(html))) {
    const text = cspNormalize(r[2]);
    if (cspLooksLikePolicy(text, 1)) push({ text, source: 'header', reportOnly: !!r[1], index: r.index });
  }

  if (!looksLikeHtml) {
    // 先存進變數再交給標頭的寫法(Next.js 文件範例):字串本身長得像 CSP 就算,但要求至少兩個已知指令,避免說明文字誤中
    const freeRe = /(["'`])((?:\\[\s\S]|(?!\1)[^\\]){20,}?)\1/g;
    let f;
    while ((f = freeRe.exec(code))) {
      if (!/-src\b|frame-ancestors|base-uri|form-action/.test(f[2])) continue;
      const text = cspNormalize(f[2]);
      if (cspLooksLikePolicy(text, 2)) push({ text, source: 'string', reportOnly: false, index: f.index });
    }
    cspHelmetPolicies(code).forEach(push);
  }
  return { policies, helmetOff: /contentSecurityPolicy\s*:\s*false/.exec(code) };
}

// ── 2. 解析 ──
function cspParse(text) {
  const d = Object.create(null);
  const order = [];
  const dup = [];
  text.split(';').forEach(part => {
    const toks = part.trim().split(' ').filter(Boolean);
    if (!toks.length) return;
    const name = toks[0].toLowerCase();
    if (name in d) { cspAdd(dup, name); return; }
    d[name] = toks.slice(1);
    order.push(name);
  });
  return { d, order, dup };
}

// ── 3. 檢查 ──
function cspCheckSyntax(p, out) {
  p.dup.forEach(n => cspAdd(out.syntax, `「${n}」寫了不只一次，瀏覽器只採用第一次，後面的會被忽略`));
  p.order.forEach(name => {
    const vals = p.d[name];
    const known = CSP_DIRECTIVES.has(name) || CSP_DEPRECATED.has(name);
    if (!known) {
      const bare = name.replace(/:$/, '');
      const sug = cspClosest(bare, Array.from(CSP_DIRECTIVES));
      cspAdd(out.syntax, name.slice(-1) === ':'
        ? `「${name}」後面多了冒號，設定項目名稱後面不用冒號`
        : `「${name}」不是有效的設定項目名稱${sug ? `（是不是想寫 ${sug}？）` : ''}，瀏覽器會直接忽略它`);
      return;
    }
    if (CSP_DEPRECATED.has(name)) cspAdd(out.notes, `「${name}」是已經淘汰的寫法，新版瀏覽器不再支援，可以刪掉`);
    if (!CSP_SOURCE_LISTS.has(name)) return;
    vals.forEach(tok => {
      const low = tok.toLowerCase();
      if (CSP_DIRECTIVES.has(low) && !/^'/.test(tok)) {
        cspAdd(out.syntax, `「${name}」後面的「${tok}」看起來是下一個設定項目，中間漏了分號（;）`);
      } else if (/^'[^']*'$/.test(tok)) {
        const inner = tok.slice(1, -1);
        const il = inner.toLowerCase();
        if (CSP_KEYWORDS.indexOf(il) >= 0) return;
        let m;
        if (il.indexOf('nonce-') === 0) {
          if (!/^nonce-[A-Za-z0-9+/_=\u0001-]+$/.test(inner)) cspAdd(out.syntax, `nonce「${tok}」含有不合法的字元或是空的（只能用英數字與 + / = 這幾種字元）`);
        } else if ((m = /^sha(256|384|512)-(.*)$/i.exec(inner))) {
          const v = m[2].replace(/=+$/, '');
          if (v.indexOf(CSP_PLACEHOLDER) < 0 && (!/^[A-Za-z0-9+/_-]+$/.test(v) || v.length !== { 256: 43, 384: 64, 512: 86 }[m[1]])) {
            cspAdd(out.syntax, `雜湊「${tok.slice(0, 24)}…」的長度或字元不對（sha${m[1]} 的 base64 應為 ${{ 256: 43, 384: 64, 512: 86 }[m[1]]} 字元），瀏覽器會忽略它`);
          }
        } else {
          const sug = cspClosest(il, CSP_KEYWORDS);
          cspAdd(out.syntax, `「${tok}」不是有效的關鍵字${sug ? `（是不是想寫 '${sug}'？）` : ''}，瀏覽器會忽略它`);
        }
      } else if (/^'|'$/.test(tok)) {
        cspAdd(out.syntax, `「${tok}」的單引號沒有成對`);
      } else if (CSP_KEYWORDS.indexOf(low) >= 0) {
        cspAdd(out.syntax, `「${tok}」沒有加單引號，要寫成 '${low}'；沒加的話瀏覽器會把它當成一個叫「${low}」的網站`);
      }
    });
  });
}

/** 一份「腳本來源清單」(script-src、沒寫時退而求其次的 default-src、script-src-elem/attr)的檢查 */
function cspCheckScriptList(name, vals, out) {
  const low = vals.map(v => v.toLowerCase());
  const hasNonce = low.some(v => v.indexOf("'nonce-") === 0);
  const hasHash = low.some(v => /^'sha(256|384|512)-/.test(v));
  const strictDyn = low.indexOf("'strict-dynamic'") >= 0;
  const strictLike = hasNonce || hasHash;
  // 有 nonce／雜湊時,現代瀏覽器會忽略 'unsafe-inline'(常見的向下相容寫法),不算放寬;但行內事件屬性(script-src-attr)不適用
  if (low.indexOf("'unsafe-inline'") >= 0 && (name === 'script-src-attr' || !strictLike)) cspAdd(out.weak, "'unsafe-inline'（允許直接寫在網頁裡的程式碼執行）");
  if (low.indexOf("'unsafe-eval'") >= 0) cspAdd(out.weak, "'unsafe-eval'（允許把文字當程式執行）");
  if (low.indexOf("'unsafe-hashes'") >= 0) cspAdd(out.weak, "'unsafe-hashes'（連寫在標籤上的 onclick 之類事件也能用雜湊放行，範圍比一般雜湊大）");
  if (strictDyn && !strictLike) cspAdd(out.syntax, "'strict-dynamic' 沒有搭配 nonce 或雜湊：瀏覽器會忽略白名單，網頁自己的腳本可能整個被擋");
  vals.forEach(tok => {
    if (/^'nonce-/i.test(tok) && /'$/.test(tok)) {
      const v = tok.slice(7, -1);
      // 名字就寫著 NONCE／PLACEHOLDER 的是「之後會被換掉」的佔位字,不算寫死
      if (v.indexOf(CSP_PLACEHOLDER) < 0 && !/nonce|placeholder|random|generate|replace|xxx/i.test(v)) {
        cspAdd(out.weak, `nonce 是寫死的固定值${v.length < 8 ? '，而且太短' : ''}（nonce 必須每次載入都重新產生，固定值寫在網頁裡等於公開，攻擊者可以直接沿用）`);
      }
    }
  });
  if (strictDyn) return { strictLike, strictDyn }; // 'strict-dynamic' 下白名單、協定、萬用字元都會被瀏覽器忽略,不必再看
  const http = [];
  vals.forEach(tok => {
    const t = tok.toLowerCase();
    if (t.charAt(0) === "'") return;
    if (t === '*') { cspAdd(out.weak, '* 萬用字元（等於允許任何網站的程式碼）'); return; }
    if (/^(https?|data):$/.test(t)) { cspAdd(out.weak, `${t} 整個協定（${t === 'data:' ? '攻擊者能把程式碼直接塞成 data: 網址' : '任何 ' + t.replace(':', '') + ' 網站的程式碼都能載入'}，幾乎等於沒限制）`); return; }
    if (/^[a-z][a-z0-9+.-]*:$/.test(t)) return;
    const host = cspHost(t);
    if (host === '*' || /^\*\.[a-z]+$/.test(host)) { cspAdd(out.weak, `${tok} 這類頂層網域萬用字元（幾乎等於沒限制）`); return; }
    if (/^http:\/\//.test(t) && !/^(localhost|127\.0\.0\.1|\[::1\])$/.test(host) && !/^[\d.]+$/.test(host)) http.push(host);
    if (CSP_BYPASS_HOSTS[host]) {
      cspAdd(out.bypass, `${host}（${CSP_BYPASS_HOSTS[host]}）`);
    } else if (host.slice(0, 2) === '*.') {
      const rest = host.slice(2);
      const hit = CSP_SHARED_HOSTING.filter(s => rest === s || rest.slice(-s.length - 1) === '.' + s)[0];
      if (hit) cspAdd(out.bypass, `${host}（整個 ${hit} 都放行，任何人都能在這個平台架站放自己的程式碼）`);
    }
  });
  if (http.length) cspAdd(out.weak, `http:// 來源（傳輸過程可被竄改，攻擊者能把程式碼換掉）：${http.join('、')}`);
  return { strictLike, strictDyn };
}

function cspEvaluate(p) {
  const out = { weak: [], bypass: [], missing: [], syntax: [], notes: [], notEnforced: [] };
  const d = p.d;
  cspCheckSyntax(p, out);

  const fetchNames = p.order.filter(n => CSP_FETCH.indexOf(n) >= 0);
  // 只有 frame-ancestors／upgrade-insecure-requests 這類「不管來源」的 CSP,不用求它管腳本
  const complete = fetchNames.length > 0 && !p.defaultsFilled;

  // 腳本
  const lists = [];
  if (d['script-src']) lists.push(['script-src', d['script-src']]);
  else if (d['default-src']) lists.push(['default-src', d['default-src']]);
  ['script-src-elem', 'script-src-attr'].forEach(n => { if (d[n]) lists.push([n, d[n]]); });
  let needBase = false;
  lists.forEach(l => {
    const r = cspCheckScriptList(l[0], l[1], out);
    if (r.strictLike && (r.strictDyn || l[1].some(v => /^'nonce-/i.test(v)))) needBase = true;
  });
  if (complete && !lists.length) cspAdd(out.weak, '完全沒寫 script-src 或 default-src（等於沒有限制程式碼可以從哪裡來）');

  // object-src:沒寫時看 default-src
  const obj = d['object-src'] || d['default-src'];
  if (complete && !obj) cspAdd(out.missing, "object-src（沒有限制 <object>／<embed> 能載入什麼；建議寫 object-src 'none'）");
  // base-uri:用了 nonce 卻不管 <base>,攻擊者塞一個 <base> 就能改掉相對路徑腳本的載入位置
  if (needBase && !d['base-uri'] && !p.defaultsFilled) cspAdd(out.missing, "base-uri（用了 nonce 卻沒限制 <base> 標籤，攻擊者可以改掉相對路徑腳本的載入位置；建議寫 base-uri 'none'）");
  [['object-src', obj], ['base-uri', d['base-uri']]].forEach(x => {
    if (x[1] && x[1].some(v => /^(\*|https?:|data:)$/i.test(v))) cspAdd(out.weak, `${x[0]} 允許任何來源（${x[1].filter(v => /^(\*|https?:|data:)$/i.test(v)).join(' ')}）`);
  });

  // 開發時留下的來源(任何指令)
  const dev = [];
  p.order.forEach(n => (d[n] || []).forEach(v => {
    const h = cspHost(v);
    if (v.charAt(0) !== "'" && !/^[a-z][a-z0-9+.-]*:$/i.test(v) && (h === 'localhost' || /^\d{1,3}(\.\d{1,3}){3}$/.test(h))) cspAdd(dev, v);
  }));
  if (dev.length) cspAdd(out.notes, `含有開發時自己電腦上的測試網址（${dev.join('、')}），上線前確認還需不需要`);

  // <meta> 送出的 CSP 有些指令會被忽略
  if (p.source === 'meta') {
    Object.keys(CSP_META_IGNORED).forEach(n => {
      if (d[n]) cspAdd(out.notEnforced, `這種寫法不支援 ${n}（${CSP_META_IGNORED[n]}），這個項目會被瀏覽器直接忽略，必須改由伺服器隨網頁送出（HTTP 標頭）`);
    });
  }
  return out;
}

// ── 4. 組成 Finding ──
const CSP_SOURCE_LABEL = { meta: '寫在網頁裡的 <meta> 標籤', header: '由伺服器送出的設定（HTTP 標頭）', string: '程式碼裡的設定字串', helmet: 'helmet 套件的設定' };
// kind 寫成字面值,verify 才掃得到「每個 kind 都有說明文字」(FINDING_GUIDE／PLAIN_TITLES／VALID_KINDS)
const CSP_KIND_META = {
  csp_weak: { kind: 'csp_weak', name: 'Content-Security-Policy 含放寬設定', lead: '這道防線有放寬的地方：', tail: '。這些設定會讓防線擋不住最常見的攻擊——把別人的程式碼塞進你的網頁執行' },
  csp_allowlist_bypass: { kind: 'csp_allowlist_bypass', name: 'script-src 白名單可被繞過', lead: '管「程式碼可以從哪裡來」的項目（script-src）放行了：', tail: '。攻擊者不必入侵你的網站，只要借用這些地方放程式碼就能繞過整道防線' },
  csp_missing_directive: { kind: 'csp_missing_directive', name: 'CSP 缺少 object-src／base-uri', lead: '少寫了：', tail: '。沒寫的項目瀏覽器就不會限制，攻擊者可以從這個缺口下手' },
  csp_syntax: { kind: 'csp_syntax', name: 'CSP 語法錯誤或已淘汰的指令', lead: '', tail: '。瀏覽器不會跳出錯誤，只會默默略過寫錯的部分，讓保護比你以為的少' },
  csp_not_enforced: { kind: 'csp_not_enforced', name: 'CSP 未完全生效', lead: '', tail: '' }
};

function cspFinding(kind, tier, items, source, index) {
  const m = CSP_KIND_META[kind];
  return {
    tier,
    category: tier === 3 ? '資訊提示' : '建議人工複查',
    name: m.name,
    kind: m.kind,
    evidence: `（${CSP_SOURCE_LABEL[source] || 'CSP'}）${m.lead}${items.join('；')}${m.tail}`.replace(/\u0001/g, '{動態值}'),
    index
  };
}

/**
 * 這個檔案裡有沒有「整站都會生效」的 CSP?
 * HTTP 標頭／helmet／設定檔字串是伺服器對每一頁都送出的,所以整站有效;
 * <meta> 只寫在某一頁的 HTML 裡,管不到別頁,所以不算。
 * 多檔案掃描時用這個判斷要不要對其他網頁重複提醒「沒有 CSP」(scan-orchestrator)。
 * @param {string} code
 * @returns {boolean}
 */
function cspSiteWide(code) {
  code = code || '';
  return cspExtract(code, /<html|<head|<!DOCTYPE/i.test(code))
    .policies.some(p => !p.reportOnly && p.source !== 'meta');
}

/**
 * @param {string} code
 * @returns {Array<{tier:number, category:string, name:string, kind:string, evidence:string}>}
 */
function cspDetector(code) {
  const findings = [];

  const looksLikeHtml = /<html|<head|<!DOCTYPE/i.test(code);
  const looksLikeFrameworkConfig = /\bNextConfig\b|defineNuxtConfig\s*\(|module\.exports\s*=\s*{[\s\S]*?headers\s*:|async\s+headers\s*\(\s*\)\s*{|"headers"\s*:\s*\[/i.test(code);
  const found = cspExtract(code, looksLikeHtml);
  const usesHelmet = /require\s*\(\s*['"]helmet['"]|from\s+['"]helmet['"]|\bhelmet\s*\(/.test(code);
  const hasCsp = found.policies.length > 0 || !!found.helmetOff || usesHelmet || /content-security-policy/i.test(code);

  // <meta> 的 Report-Only 瀏覽器不支援;標頭的 Report-Only 只回報不阻擋。兩者都不算「有在擋」
  const enforcing = found.policies.filter(p => !p.reportOnly);
  const reportOnly = found.policies.filter(p => p.reportOnly);

  enforcing.forEach(p => {
    const parsed = cspParse(p.text);
    parsed.defaultsFilled = !!p.defaultsFilled; // helmet 預設(useDefaults 不是 false)會補齊沒寫的指令
    parsed.source = p.source;
    const res = cspEvaluate(parsed);
    if (p.source === 'meta') {
      // 放在腳本後面:CSP 只管它後面才載入的內容
      // 只數同一份 HTML 文件裡的(從最近一個 doctype／<html 算起),一個檔案裡有好幾份 HTML 字串時不能互相牽連
      const upTo = code.slice(0, p.index);
      const from = Math.max(upTo.toLowerCase().lastIndexOf('<!doctype'), upTo.toLowerCase().lastIndexOf('<html'), 0);
      const before = (upTo.slice(from).match(/<script[\s>]/gi) || []).length;
      if (before) cspAdd(res.notEnforced, `有 ${before} 段程式碼（<script>）寫在這個設定標籤前面；這道防線只管它後面才載入的內容，前面那些不受限制`);
    }
    [['csp_weak', 'weak'], ['csp_allowlist_bypass', 'bypass'], ['csp_missing_directive', 'missing']].forEach(k => {
      if (res[k[1]].length) findings.push(cspFinding(k[0], 2, res[k[1]], p.source, p.index));
    });
    if (res.syntax.length || res.notes.length) findings.push(cspFinding('csp_syntax', res.syntax.length ? 2 : 3, res.syntax.concat(res.notes), p.source, p.index));
    if (res.notEnforced.length) findings.push(cspFinding('csp_not_enforced', 2, res.notEnforced, p.source, p.index));
  });

  if (found.helmetOff) {
    findings.push({
      tier: 2, category: '建議人工複查', name: CSP_KIND_META.csp_weak.name, kind: 'csp_weak', index: found.helmetOff.index,
      evidence: 'helmet 套件的 contentSecurityPolicy 被設成 false（整道防線被關掉）' + CSP_KIND_META.csp_weak.tail
    });
  }

  if (!enforcing.length && reportOnly.length) {
    const p = reportOnly[0];
    const meta = p.source === 'meta';
    findings.push(cspFinding('csp_not_enforced', meta ? 2 : 3, [meta
      ? '寫成 <meta http-equiv="Content-Security-Policy-Report-Only"> 瀏覽器並不支援，整條會被忽略（既不擋也不回報）；要用「只回報」模式必須改由伺服器送出（HTTP 標頭）'
      : '這道防線目前是「只回報、不阻擋」模式（Report-Only），什麼都不會擋；試跑觀察完之後記得改成正式的 Content-Security-Policy'], p.source, p.index));
  }

  if (looksLikeHtml && !hasCsp) {
    findings.push({
      tier: 1,
      category: '基礎設定',
      name: '未偵測到 Content Security Policy',
      kind: 'no_csp_html',
      evidence: '這個頁面裡找不到設定安全防線的 <meta> 標籤。如果這是 Next.js／Nuxt 這類框架做的網站，防線也可能寫在 next.config.js 的 headers() 或 vercel.json 裡，建議一併確認'
    });
  } else if (looksLikeFrameworkConfig && !hasCsp) {
    findings.push({
      tier: 2,
      category: '建議人工複查',
      name: '框架設定檔中未偵測到 CSP 設定（疑似）',
      kind: 'no_csp_config',
      evidence: '這份檔案看起來是 next.config／vercel.json 這類框架設定檔，但裡面沒有出現 Content-Security-Policy 字樣，建議確認是不是設定在別的檔案或部署平台的後台了'
    });
  }

  return findings;
}

// ── 環境相容匯出:Node.js(require)與瀏覽器(<script src>)共用同一份檔案 ──
// Node 測試環境: module 物件存在 → 走 module.exports,供 require() 使用
// 瀏覽器環境: module 不存在 → 略過這段,函式/常數已是全域作用域下的宣告,
//            可直接被 index.html 或其他 <script> 使用
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { cspDetector, cspSiteWide };
}
