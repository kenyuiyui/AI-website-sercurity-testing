/**
 * build-single.js — 由拆分版(index.html + assets/ + modules/)產生單檔版 referencesingle/index.html
 *
 * 做法:把 index.html 中本機的 <link rel="stylesheet" href="..."> 換成 <style>,
 * 本機的 <script src="..."></script> 換成行內 <script>(依原順序,語意與拆分版相同:各自為全域腳本)。
 * 外部 CDN(https://)一律保留原樣。
 *
 *   node scripts/build-single.js          寫入 referencesingle/index.html
 *   node scripts/build-single.js --check  只比對,不一致時以非零結束碼離開(npm run verify / CI 使用)
 */

const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const srcHtmlPath = path.join(root, 'index.html');
const outPath = path.join(root, 'referencesingle', 'index.html');

const read = rel => fs.readFileSync(path.join(root, rel), 'utf-8').replace(/\r\n/g, '\n').replace(/\s+$/, '');
const isLocal = ref => !/^(https?:)?\/\//.test(ref);

function build() {
  const raw = fs.readFileSync(srcHtmlPath, 'utf-8');
  const eol = raw.includes('\r\n') ? '\r\n' : '\n'; // 輸出沿用 index.html 的換行格式(Windows 常見 CRLF)
  const html = raw.replace(/\r\n/g, '\n');
  let inlinedCss = 0;
  let inlinedJs = 0;

  let out = html.replace(/^([ \t]*)<link rel="stylesheet" href="([^"]+)">$/gm, (all, indent, href) => {
    if (!isLocal(href)) return all;
    inlinedCss++;
    return `${indent}<style>\n/* ── 內嵌: ${href} ── */\n${read(href)}\n</style>`;
  });

  out = out.replace(/^([ \t]*)<script src="([^"]+)"><\/script>$/gm, (all, indent, src) => {
    if (!isLocal(src)) return all;
    inlinedJs++;
    // 內嵌內容裡的 "</script" 會提前結束標籤,改寫成等價的 "<\/script"
    const code = read(src).replace(/<\/script/gi, '<\\/script');
    return `${indent}<script>\n// ── 內嵌: ${src} ──\n${code}\n</script>`;
  });

  const banner = '<!-- 此檔由 scripts/build-single.js 自動產生,請勿手動修改;改 index.html / assets/ / modules/ 後執行 npm run build:single -->\n';
  out = out.replace(/^<!DOCTYPE html>\n/i, m => m + banner);
  return { out: out.replace(/\n/g, eol), inlinedCss, inlinedJs };
}

const { out, inlinedCss, inlinedJs } = build();

if (process.argv.includes('--check')) {
  const current = fs.existsSync(outPath) ? fs.readFileSync(outPath, 'utf-8').replace(/\r\n/g, '\n') : '';
  if (current !== out.replace(/\r\n/g, '\n')) {
    console.error('❌ referencesingle/index.html 與拆分版不同步,請執行 npm run build:single');
    process.exit(1);
  }
  console.log('✅ referencesingle/index.html 與拆分版一致');
} else {
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, out);
  console.log(`✅ 已產生 ${path.relative(root, outPath)}(內嵌 ${inlinedCss} 個樣式表、${inlinedJs} 個腳本)`);
}
