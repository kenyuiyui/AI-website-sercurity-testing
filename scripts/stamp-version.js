/**
 * stamp-version.js — 在 index.html 的本地 CSS/JS 網址後面加上內容指紋(?v=xxxxxxxx),並更新頁尾版本號
 *
 * 為什麼需要:GitHub Pages 無法設定快取標頭,瀏覽器可能沿用舊版 JS/CSS,
 * 造成「同一個網址、同一份程式碼,結果卻不同」(新舊檔案混用)。
 * 檔案內容一改,指紋就變 → 網址不同 → 瀏覽器一定重新下載,不會新舊混用。
 *
 *   node scripts/stamp-version.js           更新 index.html(改完任何 assets/、modules/、vendor/ 檔案後執行)
 *   node scripts/stamp-version.js --check   只檢查,指紋過期時以非零結束碼離開(verify.js 使用)
 *
 * 指紋以 LF 正規化後的內容計算,Windows(CRLF)與 GitHub(LF)算出來相同。
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const root = path.join(__dirname, '..');
const htmlPath = path.join(root, 'index.html');

const TAG_RE = /(<link rel="stylesheet" href="|<script src=")([^"?#]+)(?:\?v=[0-9a-f]*)?(")/g;
const VERSION_RE = /(<span id="appVersion">)[^<]*(<\/span>)/;

const isLocal = p => !/^([a-z]+:)?\/\//i.test(p) && !p.startsWith('data:');
const normalized = rel => fs.readFileSync(path.join(root, rel), 'utf-8').replace(/\r\n/g, '\n');
const hash = s => crypto.createHash('sha256').update(s).digest('hex');

function stamp(html) {
  const all = crypto.createHash('sha256');
  const out = html.replace(TAG_RE, (m, open, rel, close) => {
    if (!isLocal(rel)) return m;
    const content = normalized(rel);
    all.update(rel + '\n' + content);
    return `${open}${rel}?v=${hash(content).slice(0, 8)}${close}`;
  });
  const version = all.digest('hex').slice(0, 8);
  if (!VERSION_RE.test(out)) throw new Error('index.html 找不到 <span id="appVersion"></span>(頁尾版本號)');
  return { html: out.replace(VERSION_RE, `$1${version}$2`), version };
}

if (require.main === module) {
  const raw = fs.readFileSync(htmlPath, 'utf-8');
  const { html, version } = stamp(raw);
  if (process.argv.includes('--check')) {
    if (html.replace(/\r\n/g, '\n') !== raw.replace(/\r\n/g, '\n')) {
      console.error('❌ index.html 的檔案指紋過期(有 JS/CSS 改了但網址沒更新),請執行 node scripts/stamp-version.js');
      process.exit(1);
    }
    console.log(version);
  } else {
    if (html !== raw) fs.writeFileSync(htmlPath, html);
    console.log(`版本 ${version}${html !== raw ? '(已更新 index.html)' : '(無變化)'}`);
  }
}

module.exports = { stamp };
