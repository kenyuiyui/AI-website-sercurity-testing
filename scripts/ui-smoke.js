/**
 * ui-smoke.js — 畫面驗收測試(需要 playwright;在雲端或 CI 執行,本機不需要安裝)
 *
 * 拆分版用本機 HTTP 伺服器開啟(等同 GitHub Pages),單檔版用 file:// 開啟(等同雙擊)。
 * 逐項檢查驗收標準:
 *   A. 首屏不捲動就看得到輸入框與「看範例」(1280×720、390×844)
 *   B. 全程沒有 JS 錯誤、沒有 CSP 違規;除了 GitHub 匯入(已模擬)外,對外請求數 = 0
 *   C. CSP 確實生效:頁面主動連線外部網站會被瀏覽器擋下
 *   D. 範例:自動檢查、結論句、兩層結果、行號可定位
 *   E. 匯出報告:不含金鑰原文與原始碼
 *   F. 多檔案讀檔、GitHub 匯入(模擬 API 回應,含私人專案錯誤訊息)、#privacy 連結
 * 自訂瀏覽器路徑:CHROMIUM_PATH=/path/to/chrome node scripts/ui-smoke.js
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const root = path.join(__dirname, '..');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.woff2': 'font/woff2' };

function assert(cond, msg) { if (!cond) throw new Error(msg); }

function startServer() {
  const server = http.createServer((req, res) => {
    const rel = decodeURIComponent(req.url.split('?')[0]).replace(/^\/+/, '') || 'index.html';
    const file = path.join(root, rel);
    if (!file.startsWith(root) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    fs.createReadStream(file).pipe(res);
  });
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server)));
}

// 模擬 GitHub API 與 raw 檔案
async function mockGitHub(page) {
  await page.route('https://api.github.com/**', route => {
    const url = route.request().url();
    if (url.includes('/repos/demo/private')) return route.fulfill({ status: 404, contentType: 'application/json', body: '{"message":"Not Found"}' });
    if (url.includes('/git/trees/')) {
      return route.fulfill({ contentType: 'application/json', body: JSON.stringify({ truncated: false, tree: [
        { path: 'src/api/orders.js', type: 'blob', size: 200 },
        { path: 'src/config.js', type: 'blob', size: 100 },
        { path: 'node_modules/x/index.js', type: 'blob', size: 100 },
        { path: 'dist/app.min.js', type: 'blob', size: 100 },
        { path: 'README.md', type: 'blob', size: 100 }
      ] }) });
    }
    return route.fulfill({ contentType: 'application/json', body: JSON.stringify({ default_branch: 'main' }) });
  });
  await page.route('https://raw.githubusercontent.com/**', route => {
    const url = route.request().url();
    const body = url.endsWith('orders.js')
      ? 'export async function getOrder(orderId) {\n  const r = await db.orders.findOne(orderId);\n  return r;\n}\n'
      : 'export const OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890";\n';
    route.fulfill({ contentType: 'text/plain', body });
  });
}

async function checkPage(browser, url, label, viewport) {
  const page = await browser.newPage({ viewport });
  const errors = [];
  const external = [];
  page.on('pageerror', e => errors.push(e.message));
  // example.com 是 C 項刻意觸發的 CSP 攔截,不算錯誤;其他任何 CSP 違規或錯誤都算
  page.on('console', m => { if (m.type() === 'error' && !/Failed to load resource|example\.com/.test(m.text())) errors.push(m.text()); });
  page.on('request', r => { if (/^https?:/.test(r.url()) && !r.url().startsWith('http://127.0.0.1')) external.push(r.url()); });
  await mockGitHub(page);
  await page.goto(url);

  // A. 首屏
  const vh = viewport.height;
  const input = await page.$eval('#codeInput', el => el.getBoundingClientRect().top);
  const sample = await page.$eval('#sampleBtn', el => el.getBoundingClientRect().bottom);
  assert(input < vh - 40, `${label}: 首屏看不到輸入框(top=${Math.round(input)})`);
  assert(sample <= vh, `${label}: 首屏看不到「看範例」按鈕(bottom=${Math.round(sample)})`);

  // C. CSP 生效
  const blocked = await page.evaluate(() => fetch('https://example.com/').then(() => false, () => true));
  assert(blocked, `${label}: CSP 沒有擋下對外連線`);
  assert(await page.evaluate(() => typeof acorn === 'object' && typeof acornJsx === 'function'), `${label}: 本地語法分析函式庫沒有載入`);

  // D. 範例
  await page.click('#sampleBtn');
  await page.waitForSelector('.rs-headline', { timeout: 3000 });
  const headline = await page.$eval('.rs-headline', el => el.textContent);
  assert(/需要處理/.test(headline), `${label}: 結論句不正確「${headline}」`);
  const chips = await page.$$eval('.rs-chip:not([disabled]) b', els => els.map(e => Number(e.textContent)));
  assert(chips.length >= 2 && chips.every(n => n > 0), `${label}: 範例應同時產生兩層結果,實際 ${chips}`);
  await page.click('.rc-line-tag');
  const selected = await page.$eval('#codeInput', t => t.value.slice(t.selectionStart, t.selectionEnd));
  assert(selected.length > 0, `${label}: 點擊行號後沒有選取任何內容`);

  // E. 匯出報告
  await page.click('.rs-export');
  const report = await page.$eval('.ep-preview', el => el.textContent);
  assert(/資安自我檢查報告/.test(report), `${label}: 報告內容為空`);
  assert(!/fakeSignatureForDemoOnly|md5\(password|createClient\(/.test(report), `${label}: 報告含有金鑰原文或程式碼`);

  // F-1 多檔案讀檔
  await page.setInputFiles('#fileInput', [
    { name: 'a.js', mimeType: 'text/plain', buffer: Buffer.from('const k = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890";') },
    { name: 'b.py', mimeType: 'text/plain', buffer: Buffer.from('import pickle\nobj = pickle.loads(data)') }
  ]);
  await page.waitForFunction(() => document.querySelectorAll('.mf-file-item').length === 2);
  await page.click('#scanBtn');
  await page.waitForSelector('.rc-filename-tag', { timeout: 3000 });

  // F-2 GitHub 匯入(模擬)
  await page.fill('#ghUrl', 'https://github.com/demo/app');
  await page.click('#ghImportBtn');
  await page.waitForFunction(() => document.querySelectorAll('.mf-filename-input').length === 2 && document.querySelector('.rs-headline'), null, { timeout: 5000 });
  const names = await page.$$eval('.mf-filename-input', els => els.map(e => e.value).sort());
  assert(names.join() === 'src/api/orders.js,src/config.js', `${label}: GitHub 匯入的檔案篩選不正確 ${names}`);
  const ghCards = await page.$$eval('.rc-filename-tag', els => els.map(e => e.textContent));
  assert(ghCards.includes('src/config.js'), `${label}: GitHub 匯入後沒有檢查結果`);
  await page.fill('#ghUrl', 'https://github.com/demo/private');
  await page.click('#ghImportBtn');
  await page.waitForFunction(() => /私人專案/.test(document.getElementById('statusLine').textContent), null, { timeout: 3000 });

  // F-3 隱私連結
  await page.click('.trust-badge');
  await page.waitForFunction(() => !document.getElementById('tab-panel-boundary').hidden);
  await page.waitForFunction(() => { const r = document.getElementById('privacy').getBoundingClientRect(); return r.top >= 0 && r.top < window.innerHeight; }, null, { timeout: 3000 })
    .catch(() => { throw new Error(`${label}: #privacy 沒有捲到可見範圍`); });

  // B. 錯誤與對外請求
  assert(errors.length === 0, `${label}: 錯誤 ${errors.join(' | ')}`);
  const unexpected = external.filter(u => !/^https:\/\/(api\.github\.com|raw\.githubusercontent\.com|example\.com)\//.test(u));
  assert(unexpected.length === 0, `${label}: 出現非預期的對外請求 ${unexpected.join(', ')}`);
  assert(external.every(u => !/example\.com/.test(u)), `${label}: 被 CSP 擋下的請求仍然送出了`);

  console.log(`✅ ${label}`);
  await page.close();
}

(async () => {
  const server = await startServer();
  const base = `http://127.0.0.1:${server.address().port}/`;
  const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
  const targets = [
    { url: base + 'index.html', name: '拆分版(HTTP)' },
    { url: 'file://' + path.join(root, 'referencesingle', 'index.html'), name: '單檔版(file://)' }
  ];
  const viewports = [{ width: 1280, height: 720 }, { width: 390, height: 844 }];
  try {
    for (const t of targets) {
      for (const v of viewports) await checkPage(browser, t.url, `${t.name} @${v.width}×${v.height}`, v);
    }
    console.log(`${targets.length * viewports.length} 個頁面／尺寸組合通過`);
  } finally {
    await browser.close();
    server.close();
  }
})().catch(e => { console.error('❌ ' + e.message); process.exit(1); });
