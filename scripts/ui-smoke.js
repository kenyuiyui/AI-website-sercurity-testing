/**
 * ui-smoke.js — 畫面冒煙測試(選用,需要 playwright:npm i -D playwright)
 *
 * 用無頭瀏覽器開啟拆分版與單檔版,封鎖 CDN(等同離線／正則保底版),確認:
 * 無 JS 錯誤、範例可掃描且同時出現兩層結果、行號可點擊定位、多檔案讀檔、分頁網址。
 * 自訂瀏覽器路徑:CHROMIUM_PATH=/path/to/chrome node scripts/ui-smoke.js
 */

const path = require('path');
const { chromium } = require('playwright');

const root = path.join(__dirname, '..');
const pages = ['index.html', 'referencesingle/index.html'];

function assert(cond, msg) { if (!cond) throw new Error(msg); }

(async () => {
  const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
  try {
    for (const rel of pages) {
      for (const viewport of [{ width: 1280, height: 900 }, { width: 390, height: 844 }]) {
        const label = `${rel} @${viewport.width}px`;
        const page = await browser.newPage({ viewport });
        const errors = [];
        page.on('pageerror', e => errors.push(e.message));
        await page.route(/^https?:\/\//, r => r.abort()); // 模擬 CDN 無法連線
        await page.goto('file://' + path.join(root, rel));

        await page.click('#sampleBtn');
        await page.focus('#codeInput');
        await page.keyboard.press('Control+Enter');
        await page.waitForSelector('.results-summary', { timeout: 3000 });

        const chips = await page.$$eval('.rs-chip:not([disabled]) b', els => els.map(e => Number(e.textContent)));
        assert(chips.length >= 2 && chips.every(n => n > 0), `${label}: 範例應同時產生「發現」與「建議複查」,實際 ${chips}`);

        const tag = await page.$('.rc-line-tag');
        assert(tag, `${label}: 找不到行號標籤`);
        await tag.click();
        const selected = await page.$eval('#codeInput', t => t.value.slice(t.selectionStart, t.selectionEnd));
        assert(selected.length > 0, `${label}: 點擊行號後沒有選取任何內容`);

        await page.setInputFiles('#fileInput', [
          { name: 'a.js', mimeType: 'text/plain', buffer: Buffer.from('const k = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890";') },
          { name: 'b.py', mimeType: 'text/plain', buffer: Buffer.from('import pickle\nobj = pickle.loads(data)') }
        ]);
        await page.waitForFunction(() => document.querySelectorAll('.mf-file-item').length === 2);
        assert(await page.$eval('#multiFileToggle', e => e.checked), `${label}: 拖入多個檔案應自動切到多檔案模式`);
        await page.click('#scanBtn');
        await page.waitForSelector('.rc-filename-tag', { timeout: 3000 });

        await page.click('#tab-btn-boundary');
        assert((await page.evaluate(() => location.hash)) === '#boundary', `${label}: 分頁網址應為 #boundary`);

        assert(errors.length === 0, `${label}: JS 錯誤 ${errors.join(' | ')}`);
        console.log(`✅ ${label}`);
        await page.close();
      }
    }
    console.log(`${pages.length * 2} 個頁面／尺寸組合通過`);
  } finally {
    await browser.close();
  }
})().catch(e => { console.error('❌ ' + e.message); process.exit(1); });
