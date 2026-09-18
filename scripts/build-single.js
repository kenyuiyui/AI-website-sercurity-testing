/**
 * build-single.js — 從拆分版(根目錄 index.html + modules/)產生單檔版 referencesingle/index.html
 *
 * 單檔版 = 拆分版 index.html,拿掉 12 個 <script src="modules/..."> 標籤,改成把模組原文
 * 依同樣順序內嵌進主邏輯 IIFE 開頭(每段以「// ── 模組: <檔名> ──」標記邊界)。
 * 修改任何模組或 index.html 後執行一次,兩個版本就不會不同步:
 *
 *   node scripts/build-single.js          (寫入 referencesingle/index.html)
 *   node scripts/build-single.js --check  (只比對,不一致時以非零結束碼離開,適合 CI)
 */

const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const srcHtmlPath = path.join(root, 'index.html');
const outPath = path.join(root, 'referencesingle', 'index.html');

const html = fs.readFileSync(srcHtmlPath, 'utf-8');
const eol = html.includes('\r\n') ? '\r\n' : '\n';
const lines = html.split(/\r?\n/);

// 1. 找出 <script src="modules/..."> 清單(含上方說明註解),依出現順序記下模組檔名
const scriptTagRe = /^<script src="modules\/([\w-]+\.js)"><\/script>$/;
const moduleFiles = [];
let firstTag = -1;
let lastTag = -1;
lines.forEach((line, i) => {
  const m = line.trim().match(scriptTagRe);
  if (m) {
    moduleFiles.push(m[1]);
    if (firstTag < 0) firstTag = i;
    lastTag = i;
  }
});
if (moduleFiles.length === 0) throw new Error('index.html 裡找不到 <script src="modules/..."> 標籤');

let removeStart = firstTag;
if (lines[firstTag - 1].trim() === '-->') {
  while (removeStart > 0 && lines[removeStart - 1].trim() !== '<!--') removeStart--;
  removeStart--; // 連同 <!-- 那一行
}
let removeEnd = lastTag;
if (lines[removeEnd + 1] !== undefined && lines[removeEnd + 1].trim() === '') removeEnd++;

// 2. 找出主邏輯裡「12 個獨立模組檔案,透過 <script src> 載入」這段說明註解,換成模組原文
const noteStart = lines.findIndex(l => l.includes('個獨立模組檔案,透過 <script src> 載入'));
if (noteStart < 0) throw new Error('index.html 主邏輯裡找不到模組載入說明註解,無法定位內嵌位置');
let noteEnd = noteStart;
while (lines[noteEnd + 1] !== undefined && lines[noteEnd + 1].trim().startsWith('//')) noteEnd++;
while (lines[noteEnd + 1] !== undefined && lines[noteEnd + 1].trim() === '') noteEnd++;

const inlined = [];
moduleFiles.forEach(file => {
  const src = fs.readFileSync(path.join(root, 'modules', file), 'utf-8').replace(/\s+$/, '');
  inlined.push(`  // ── 模組: ${file} ──`);
  inlined.push(...src.split(/\r?\n/));
  inlined.push('');
});

const out = [
  ...lines.slice(0, removeStart),
  ...lines.slice(removeEnd + 1, noteStart),
  ...inlined,
  ...lines.slice(noteEnd + 1),
].join(eol);

if (process.argv.includes('--check')) {
  const current = fs.existsSync(outPath) ? fs.readFileSync(outPath, 'utf-8') : '';
  if (current !== out) {
    console.error('❌ referencesingle/index.html 與拆分版不同步,請執行 node scripts/build-single.js');
    process.exit(1);
  }
  console.log('✅ referencesingle/index.html 與拆分版一致');
} else {
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, out);
  console.log(`✅ 已產生 ${path.relative(root, outPath)}(內嵌 ${moduleFiles.length} 個模組)`);
}
