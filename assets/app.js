/**
 * app.js — 畫面層(DOM 事件、輸入、結果互動)
 *
 * 掃描邏輯一律呼叫 modules/scan-orchestrator.js 的 scanCode / scanFiles,
 * 結果 HTML 一律由 modules/finding-renderer.js 產生;這裡不寫任何偵測規則。
 */
(function () {
  'use strict';

  const $ = id => document.getElementById(id);
  const codeInput = $('codeInput');
  const scanBtn = $('scanBtn');
  const results = $('results');
  const statusLine = $('statusLine');
  const scanSweep = $('scanSweep');
  const inputMeta = $('inputMeta');
  const fileInput = $('fileInput');
  const singleInput = $('singleInput');
  const multiFileToggle = $('multiFileToggle');
  const multiFileContainer = $('multiFileContainer');
  const multiFileList = $('multiFileList');

  const MAX_FILE_BYTES = 2 * 1024 * 1024; // 單檔上限,避免誤拖大型二進位檔卡住頁面
  const SCAN_DELAY_MS = 280;              // 讓掃描動畫有時間出現,非必要延遲

  // ───────────────────────── 工具 ─────────────────────────

  function escapeAttr(str) {
    return String(str).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).catch(() => legacyCopy(text));
    }
    return legacyCopy(text);
  }

  function legacyCopy(text) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;opacity:0';
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    document.body.removeChild(ta);
    return ok ? Promise.resolve() : Promise.reject(new Error('copy failed'));
  }

  function flashButton(btn, text) {
    const original = btn.dataset.label || btn.textContent;
    btn.dataset.label = original;
    btn.textContent = text;
    btn.classList.add('copied');
    window.setTimeout(() => { btn.textContent = original; btn.classList.remove('copied'); }, 1800);
  }

  function prefersReducedMotion() {
    return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  function scrollIntoViewSmart(el) {
    el.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });
  }

  // ───────────────────────── 輸入框資訊 ─────────────────────────

  function updateInputMeta() {
    const v = codeInput.value;
    inputMeta.textContent = v ? (v.split('\n').length + ' 行 · ' + v.length.toLocaleString() + ' 字元') : 'code-input';
  }
  codeInput.addEventListener('input', updateInputMeta);

  // ───────────────────────── 多檔案清單 ─────────────────────────

  function isMultiFileMode() { return multiFileToggle.checked; }

  function createFileItem(filename, code) {
    const item = document.createElement('div');
    item.className = 'mf-file-item';
    item.innerHTML =
      '<div class="mf-file-header">' +
        '<input type="text" class="mf-filename-input" placeholder="檔名（例如 pages/api/orders.js）" value="' + escapeAttr(filename || '') + '">' +
        '<button type="button" class="mf-remove-btn">移除</button>' +
      '</div>' +
      '<textarea spellcheck="false" placeholder="貼上這個檔案的程式碼…"></textarea>';
    item.querySelector('textarea').value = code || ''; // 用 value 賦值,不經過 HTML 解析
    item.querySelector('.mf-remove-btn').addEventListener('click', () => {
      if (multiFileList.children.length > 1) item.remove();
      else { item.querySelector('textarea').value = ''; item.querySelector('.mf-filename-input').value = ''; }
    });
    return item;
  }

  function addFileItem(filename, code) {
    const item = createFileItem(filename, code);
    multiFileList.appendChild(item);
    return item;
  }

  function resetFileList() {
    multiFileList.innerHTML = '';
    addFileItem('', '');
    addFileItem('', '');
  }

  function collectFilesFromUI() {
    return [...multiFileList.querySelectorAll('.mf-file-item')].map(item => ({
      filename: item.querySelector('.mf-filename-input').value.trim() || null,
      code: item.querySelector('textarea').value
    }));
  }

  function clearResults() {
    results.innerHTML = '';
    statusLine.textContent = '';
  }

  multiFileToggle.addEventListener('change', () => {
    const multi = isMultiFileMode();
    singleInput.hidden = multi;
    multiFileContainer.hidden = !multi;
    if (multi && multiFileList.children.length === 0) resetFileList();
    clearResults();
  });

  $('addFileBtn').addEventListener('click', () => addFileItem('', '').querySelector('textarea').focus());

  // ───────────────────────── 讀取本機檔案(拖放／選擇) ─────────────────────────
  // 只用 FileReader 在瀏覽器內讀取,不會送出任何內容。

  function readFileAsText(file) {
    return new Promise((resolve, reject) => {
      if (file.size > MAX_FILE_BYTES) return reject(new Error(file.name + ' 超過 2MB，已略過'));
      const reader = new FileReader();
      reader.onload = () => {
        const text = String(reader.result || '');
        if (text.indexOf('\u0000') !== -1) return reject(new Error(file.name + ' 看起來不是文字檔，已略過'));
        resolve({ filename: file.webkitRelativePath || file.name, code: text });
      };
      reader.onerror = () => reject(new Error(file.name + ' 讀取失敗'));
      reader.readAsText(file);
    });
  }

  async function loadFiles(fileList) {
    const files = [...fileList];
    if (files.length === 0) return;
    const settled = await Promise.allSettled(files.map(readFileAsText));
    const loaded = settled.filter(r => r.status === 'fulfilled').map(r => r.value);
    const errors = settled.filter(r => r.status === 'rejected').map(r => r.reason.message);

    // 單一模式拖入多個檔案 → 自動切換到多檔案模式
    if (!isMultiFileMode() && loaded.length > 1) {
      multiFileToggle.checked = true;
      multiFileToggle.dispatchEvent(new Event('change'));
      multiFileList.innerHTML = '';
    }

    if (isMultiFileMode()) {
      // 先填入空白項目,再新增
      const empties = [...multiFileList.querySelectorAll('.mf-file-item')].filter(it => !it.querySelector('textarea').value.trim());
      loaded.forEach(f => {
        const slot = empties.shift();
        if (slot) {
          slot.querySelector('.mf-filename-input').value = f.filename;
          slot.querySelector('textarea').value = f.code;
        } else {
          addFileItem(f.filename, f.code);
        }
      });
      empties.forEach(it => { if (multiFileList.children.length > 1) it.remove(); });
    } else if (loaded[0]) {
      codeInput.value = loaded[0].code;
      updateInputMeta();
    }

    const msg = loaded.length ? '已讀取 ' + loaded.map(f => f.filename).join('、') + '，按「掃描」開始。' : '';
    statusLine.textContent = [msg].concat(errors).filter(Boolean).join(' ');
  }

  fileInput.addEventListener('change', () => { loadFiles(fileInput.files); fileInput.value = ''; });
  $('pickFileBtn').addEventListener('click', () => fileInput.click());
  $('pickFilesBtn').addEventListener('click', () => fileInput.click());

  document.querySelectorAll('.drop-target').forEach(zone => {
    let depth = 0;
    zone.addEventListener('dragenter', e => {
      if (!e.dataTransfer || [...e.dataTransfer.types].indexOf('Files') === -1) return;
      e.preventDefault();
      depth++;
      zone.classList.add('dragging');
    });
    zone.addEventListener('dragover', e => {
      if (zone.classList.contains('dragging')) e.preventDefault();
    });
    zone.addEventListener('dragleave', () => {
      depth = Math.max(0, depth - 1);
      if (depth === 0) zone.classList.remove('dragging');
    });
    zone.addEventListener('drop', e => {
      if (!zone.classList.contains('dragging')) return;
      e.preventDefault();
      depth = 0;
      zone.classList.remove('dragging');
      loadFiles(e.dataTransfer.files);
    });
  });

  // ───────────────────────── 掃描 ─────────────────────────

  function startScanUI() {
    scanBtn.disabled = true;
    statusLine.textContent = '掃描中…';
    scanSweep.classList.remove('running');
    void scanSweep.offsetWidth; // 重新觸發動畫
    scanSweep.classList.add('running');
  }

  function finishScanUI(findings, languageCaveat, fileCount) {
    results.innerHTML = findingRenderer(findings, languageCaveat);
    scanBtn.disabled = false;
    statusLine.textContent = fileCount > 1 ? '已掃描 ' + fileCount + ' 個檔案。' : '';
    const summary = results.querySelector('.results-summary');
    if (summary) {
      scrollIntoViewSmart(summary);
      summary.focus({ preventScroll: true });
    }
  }

  function runScan() {
    if (scanBtn.disabled) return;
    if (isMultiFileMode()) {
      const files = collectFilesFromUI();
      if (!files.some(f => (f.code || '').trim())) {
        results.innerHTML = '';
        statusLine.textContent = '請先貼上至少一個檔案的程式碼再掃描。';
        return;
      }
      startScanUI();
      window.setTimeout(() => {
        const r = scanFiles(files);
        finishScanUI(r.findings, r.languageCaveat, files.length);
      }, SCAN_DELAY_MS);
      return;
    }

    const code = codeInput.value;
    if (!code.trim()) {
      results.innerHTML = '';
      statusLine.textContent = '請先貼上程式碼再掃描。';
      codeInput.focus();
      return;
    }
    startScanUI();
    window.setTimeout(() => {
      const r = scanCode(code);
      finishScanUI(r.findings, r.languageCaveat, 1);
    }, SCAN_DELAY_MS);
  }

  scanBtn.addEventListener('click', runScan);

  // Ctrl/⌘ + Enter:在任何輸入框內都能直接掃描
  const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
  $('scanKbd').textContent = isMac ? '⌘ Enter' : 'Ctrl+Enter';
  document.addEventListener('keydown', e => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && !$('tab-panel-scan').hidden) {
      e.preventDefault();
      runScan();
    }
  });

  // ───────────────────────── 結果互動(事件委派) ─────────────────────────

  function findTextareaFor(filename) {
    if (!isMultiFileMode()) return codeInput;
    const items = [...multiFileList.querySelectorAll('.mf-file-item')];
    if (!filename) return items[0] ? items[0].querySelector('textarea') : null;
    const idx = items.findIndex((it, i) => (it.querySelector('.mf-filename-input').value.trim() || ('檔案' + (i + 1))) === filename);
    return idx >= 0 ? items[idx].querySelector('textarea') : null;
  }

  function selectRange(textarea, start, end) {
    if (!textarea) return;
    scrollIntoViewSmart(textarea.closest('.input-frame, .mf-file-item') || textarea);
    textarea.focus({ preventScroll: true });
    textarea.setSelectionRange(start, end);
    // 把選取範圍捲到 textarea 可視區中間
    const lineHeight = parseFloat(getComputedStyle(textarea).lineHeight) || 20;
    const line = textarea.value.slice(0, start).split('\n').length - 1;
    textarea.scrollTop = Math.max(0, line * lineHeight - textarea.clientHeight / 2);
  }

  function buildCopyAllText() {
    const seen = new Set();
    const items = [];
    const instructions = [];
    results.querySelectorAll('.result-card:not(.clean)').forEach((card, i) => {
      const title = card.querySelector('.rc-title-text');
      const line = card.querySelector('.rc-line-tag');
      const file = card.querySelector('.rc-filename-tag');
      const where = [file && file.textContent, line && line.textContent].filter(Boolean).join(' ');
      items.push((i + 1) + '. ' + (title ? title.textContent : '') + (where ? '（' + where + '）' : ''));
      const handoff = card.querySelector('.rc-handoff');
      if (handoff && !seen.has(handoff.dataset.kind)) {
        seen.add(handoff.dataset.kind);
        instructions.push('【' + (title ? title.textContent : '') + '】\n' + handoff.querySelector('.rc-handoff-text').textContent);
      }
    });
    return '我用資安檢查工具掃描了我的程式碼，發現以下問題：\n' + items.join('\n') +
      '\n\n請依序幫我處理，各類問題的處理要求如下：\n\n' + instructions.join('\n\n');
  }

  results.addEventListener('click', e => {
    const copyBtn = e.target.closest('.rc-copy-btn');
    if (copyBtn) {
      const text = copyBtn.closest('.rc-handoff').querySelector('.rc-handoff-text').textContent;
      copyText(text).then(() => flashButton(copyBtn, '已複製 ✓'), () => flashButton(copyBtn, '複製失敗'));
      return;
    }
    const copyAll = e.target.closest('.rs-copy-all');
    if (copyAll) {
      copyText(buildCopyAllText()).then(() => flashButton(copyAll, '已複製全部 ✓'), () => flashButton(copyAll, '複製失敗'));
      return;
    }
    const chip = e.target.closest('.rs-chip[data-jump]');
    if (chip) {
      const card = $(chip.dataset.jump);
      if (card) { scrollIntoViewSmart(card); card.focus({ preventScroll: true }); }
      return;
    }
    const lineTag = e.target.closest('.rc-line-tag');
    if (lineTag) {
      selectRange(findTextareaFor(lineTag.dataset.file), Number(lineTag.dataset.start), Number(lineTag.dataset.end));
    }
  });

  // ───────────────────────── 範例／清除 ─────────────────────────

  function buildSampleCode() {
    // 金鑰以片段組合,避免這份原始碼本身被同一套規則判定為外洩
    const serviceRoleKey = [
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
      'eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InByb2plY3RyZWYiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjIwMTU1NzYwMDB9',
      'fakeSignatureForDemoOnlyNotARealKey12345'
    ].join('.');
    // 範例需在「正則保底版」與「AST 版」都同時展示第一層與第二層發現
    return [
      'import { createClient } from "@supabase/supabase-js";',
      '',
      '// 這組金鑰是 service_role(最高權限,可繞過RLS),絕不應出現在前端程式碼中',
      'const supabase = createClient(',
      '  "https://exampleproj.supabase.co",',
      '  "' + serviceRoleKey + '"',
      ');',
      '',
      '// 只用參數刪除資料,沒有先確認 propertyId 是否屬於目前登入的使用者',
      'export async function deleteProperty(propertyId) {',
      '  const result = await supabase.from("properties").delete().eq("id", propertyId);',
      '  return result;',
      '}',
      '',
      'function hashPassword(password) {',
      '  return md5(password);',
      '}'
    ].join('\n');
  }

  $('sampleBtn').addEventListener('click', () => {
    clearResults();
    if (isMultiFileMode()) {
      // 「前端有遮罩、後端沒遮罩」的 M11 典型案例
      multiFileList.innerHTML = '';
      addFileItem('frontend/api.js', [
        'const OPENAI_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890";',
        '',
        'function publicRoom(room) {',
        '  return json({ id: room.id, state: maskState(room.state) });',
        '}'
      ].join('\n'));
      addFileItem('backend/history.js', [
        'function getOrder(req, res) {',
        '  const order = db.find(req.params.id);',
        '  res.json(order);',
        '}',
        '',
        'function publicHistoryRow(row) {',
        '  return json({ id: row.id, state: row.state });',
        '}'
      ].join('\n'));
    } else {
      codeInput.value = buildSampleCode();
      updateInputMeta();
      codeInput.focus();
    }
    statusLine.textContent = '已載入範例，按「掃描」或 Ctrl+Enter 看結果。';
  });

  $('clearBtn').addEventListener('click', () => {
    if (isMultiFileMode()) {
      resetFileList();
    } else {
      codeInput.value = '';
      updateInputMeta();
      codeInput.focus();
    }
    clearResults();
  });

  // ───────────────────────── 主題切換 ─────────────────────────
  // 初始主題已由 <head> 內的行內腳本套用(避免閃爍),這裡只負責按鈕狀態與切換。

  const THEME_KEY = 'ai-scanner-theme';
  const root = document.documentElement;

  function syncThemeButton() {
    const light = root.getAttribute('data-theme') === 'light';
    $('themeIcon').innerHTML = light ? '&#9789;' : '&#9788;';
    $('themeLabel').textContent = light ? '深色模式' : '淺色模式';
  }

  $('themeToggle').addEventListener('click', () => {
    const next = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    if (next === 'light') root.setAttribute('data-theme', 'light');
    else root.removeAttribute('data-theme');
    try { localStorage.setItem(THEME_KEY, next); } catch (e) { /* 私密模式等情況下無法儲存,忽略 */ }
    syncThemeButton();
  });
  syncThemeButton();

  // ───────────────────────── 分頁(支援網址 #boundary / #howto 直接連結) ─────────────────────────

  const tabButtons = [...document.querySelectorAll('.top-tab')];

  function activateTab(btnId, opts) {
    const target = $(btnId) || tabButtons[0];
    tabButtons.forEach(btn => {
      const active = btn === target;
      btn.setAttribute('aria-selected', active ? 'true' : 'false');
      btn.tabIndex = active ? 0 : -1;
      const panel = $(btn.getAttribute('aria-controls'));
      if (panel) panel.hidden = !active;
    });
    if (!opts || !opts.fromHash) {
      const hash = target.dataset.hash;
      history.replaceState(null, '', hash ? '#' + hash : location.pathname + location.search);
    }
    if (!opts || !opts.keepScroll) window.scrollTo({ top: 0, behavior: 'auto' });
  }

  function tabFromHash() {
    const h = location.hash.replace('#', '');
    const btn = tabButtons.find(b => b.dataset.hash === h);
    return btn ? btn.id : 'tab-btn-scan';
  }

  tabButtons.forEach((btn, i) => {
    btn.addEventListener('click', () => activateTab(btn.id));
    // 方向鍵切換分頁(WAI-ARIA tabs 慣例)
    btn.addEventListener('keydown', e => {
      if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
      const next = tabButtons[(i + (e.key === 'ArrowRight' ? 1 : -1) + tabButtons.length) % tabButtons.length];
      activateTab(next.id);
      next.focus();
    });
  });
  document.querySelectorAll('[data-goto-tab]').forEach(btn => {
    btn.addEventListener('click', () => activateTab(btn.getAttribute('data-goto-tab')));
  });
  window.addEventListener('hashchange', () => activateTab(tabFromHash(), { fromHash: true }));
  activateTab(tabFromHash(), { fromHash: true, keepScroll: true });
})();
