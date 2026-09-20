/**
 * build-single.js — 由拆分版(index.html + assets/ + vendor/ + modules/)產生單檔版 referencesingle/index.html
 *
 * 做法:
 * - 本機 <link rel="stylesheet"> → <style>(CSS 裡的 url(fonts/…) 轉成 data: URI)
 * - 本機 <script src> → 行內 <script>(依原順序,語意與拆分版相同:各自為全域腳本)
 * - CSP meta 改寫:行內 script/style 改用 sha256 雜湊放行,字型改允許 data:;其餘限制與拆分版相同
 *
 *   node scripts/build-single.js          寫入 referencesingle/index.html
 *   node scripts/build-single.js --check  只比對,不一致時以非零結束碼離開(npm run verify / CI 使用)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const root = path.join(__dirname, '..');
const srcHtmlPath = path.join(root, 'index.html');
const outPath = path.join(root, 'referencesingle', 'index.html');

const readText = rel => fs.readFileSync(path.join(root, rel), 'utf-8').replace(/\r\n/g, '\n').replace(/\s+$/, '');
const isLocal = ref => !/^(https?:)?\/\//.test(ref);
const sha256 = text => "'sha256-" + crypto.createHash('sha256').update(text, 'utf8').digest('base64') + "'";

function inlineCss(href) {
  const baseDir = path.posix.dirname(href);
  return readText(href).replace(/url\(([^)]+\.woff2)\)/g, (all, rel) => {
    const file = path.join(root, baseDir, rel.replace(/['"]/g, ''));
    return `url(data:font/woff2;base64,${fs.readFileSync(file).toString('base64')})`;
  });
}

function build() {
  const raw = fs.readFileSync(srcHtmlPath, 'utf-8');
  const eol = raw.includes('\r\n') ? '\r\n' : '\n'; // 輸出沿用 index.html 的換行格式(Windows 常見 CRLF)
  const html = raw.replace(/\r\n/g, '\n');
  const scriptHashes = [];
  const styleHashes = [];
  let inlinedCss = 0;
  let inlinedJs = 0;

  let out = html.replace(/^([ \t]*)<link rel="stylesheet" href="([^"]+)">$/gm, (all, indent, href) => {
    if (!isLocal(href)) return all;
    href = href.replace(/\?.*$/, ''); // 去掉 ?v= 檔案指紋
    inlinedCss++;
    const body = `\n/* ── 內嵌: ${href} ── */\n${inlineCss(href)}\n`;
    styleHashes.push(sha256(body));
    return `${indent}<style>${body}</style>`;
  });

  out = out.replace(/^([ \t]*)<script src="([^"]+)"><\/script>$/gm, (all, indent, src) => {
    if (!isLocal(src)) return all;
    src = src.replace(/\?.*$/, ''); // 去掉 ?v= 檔案指紋
    inlinedJs++;
    const code = readText(src);
    // 行內 script 內容不能出現這兩種序列,否則 HTML 解析會提前結束或吞掉後面的標籤
    if (/<\/script/i.test(code) || /<!--/.test(code)) {
      throw new Error(`${src} 含有 "</script" 或 "<!--",無法安全內嵌;請改寫該字串(例如 '<' + '/script')`);
    }
    const body = `\n// ── 內嵌: ${src} ──\n${code}\n`;
    scriptHashes.push(sha256(body));
    return `${indent}<script>${body}</script>`;
  });

  // 改寫 CSP:單檔版沒有外部檔案,行內內容改以雜湊放行
  let cspFound = false;
  out = out.replace(/(<meta http-equiv="Content-Security-Policy" content=")([^"]+)(">)/, (all, a, policy, b) => {
    cspFound = true;
    const p = policy
      .replace(/script-src [^;]+/, 'script-src ' + scriptHashes.join(' '))
      .replace(/style-src [^;]+/, 'style-src ' + styleHashes.join(' '))
      .replace(/font-src [^;]+/, 'font-src data:')
      .replace(/img-src [^;]+/, 'img-src data:');
    return a + p + b;
  });
  if (!cspFound) throw new Error('index.html 找不到 Content-Security-Policy meta 標籤');

  const banner = '<!-- 此檔由 scripts/build-single.js 自動產生,請勿手動修改;改 index.html / assets/ / vendor/ / modules/ 後重新產生 -->\n';
  out = out.replace(/^<!DOCTYPE html>\n/i, m => m + banner);
  // CSP 雜湊以 LF 計算即可:HTML 解析時會先把 CRLF 正規化成 LF,所以輸出沿用 CRLF 也不影響雜湊
  out = out.replace(/\n/g, eol);
  return { out, inlinedCss, inlinedJs };
}

const { out, inlinedCss, inlinedJs } = build();

if (process.argv.includes('--check')) {
  const current = fs.existsSync(outPath) ? fs.readFileSync(outPath, 'utf-8') : '';
  const norm = s => s.replace(/\r\n/g, '\n');
  if (norm(current) !== norm(out)) {
    console.error('❌ referencesingle/index.html 與拆分版不同步,請重新產生(node scripts/build-single.js)');
    process.exit(1);
  }
  console.log('✅ referencesingle/index.html 與拆分版一致');
} else {
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, out);
  console.log(`✅ 已產生 ${path.relative(root, outPath)}(內嵌 ${inlinedCss} 個樣式表、${inlinedJs} 個腳本,CSP 雜湊 ${inlinedJs + inlinedCss} 個)`);
}
