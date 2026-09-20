/**
 * app.js — 畫面層(DOM 事件、輸入、結果互動、匯出)
 *
 * 掃描邏輯一律呼叫 modules/scan-orchestrator.js 的 scanCode / scanFiles,
 * 結果 HTML 與報告文字一律由 modules/finding-renderer.js 產生;GitHub 匯入在 assets/github-import.js。
 * 這裡不寫任何偵測規則。
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
  const ghUrl = $('ghUrl');
  const ghImportBtn = $('ghImportBtn');

  const MAX_FILE_BYTES = 2 * 1024 * 1024; // 單檔上限,避免誤拖大型二進位檔卡住頁面
  const SCAN_DELAY_MS = 280;              // 讓掃描動畫有時間出現,非必要延遲
  const COMPACT_THRESHOLD = 4;            // 多於這個檔案數時,檔案內容預設收合
  const TOOL_URL = 'https://kenyuiyui.github.io/AI-website-sercurity-testing/';

  let lastScan = null;     // { findings, notices, astUsed, source } 供匯出報告使用
  let sourceLabel = null;  // 目前輸入的來源說明(GitHub 專案名、檔名…)
  let singleFilename = null; // 單檔模式下,內容來自哪個檔案(手動貼上時為 null)

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
    ta.className = 'sr-only';
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

  function setStatus(text) { statusLine.textContent = text || ''; }

  // ───────────────────────── 輸入框資訊 ─────────────────────────

  function updateInputMeta() {
    const v = codeInput.value;
    inputMeta.textContent = v ? (v.split('\n').length + ' 行 · ' + v.length.toLocaleString() + ' 字元') : '或直接貼上程式碼';
  }
  codeInput.addEventListener('input', () => { sourceLabel = null; singleFilename = null; updateInputMeta(); });

  // ───────────────────────── 多檔案清單 ─────────────────────────

  function isMultiFileMode() { return multiFileToggle.checked; }

  function setMultiFileMode(on) {
    if (multiFileToggle.checked !== on) multiFileToggle.checked = on;
    singleInput.hidden = on;
    multiFileContainer.hidden = !on;
    if (on && multiFileList.children.length === 0) resetFileList();
  }

  function updateMfSummary() {
    const n = multiFileList.children.length;
    $('mfSummary').textContent = (sourceLabel ? sourceLabel + ' · ' : '') + n + ' 個檔案';
  }

  function createFileItem(filename, code, compact) {
    const item = document.createElement('div');
    item.className = 'mf-file-item' + (compact ? ' compact' : '');
    item.innerHTML =
      '<div class="mf-file-header">' +
        '<input type="text" class="mf-filename-input" placeholder="檔名（例如 pages/api/orders.js）" value="' + escapeAttr(filename || '') + '">' +
        '<span class="mf-lines"></span>' +
        '<button type="button" class="mf-toggle-btn">' + (compact ? '展開' : '收合') + '</button>' +
        '<button type="button" class="mf-remove-btn">移除</button>' +
      '</div>' +
      '<textarea spellcheck="false" placeholder="貼上這個檔案的程式碼…"></textarea>';
    const ta = item.querySelector('textarea');
    ta.value = code || ''; // 用 value 賦值,不經過 HTML 解析
    const lines = item.querySelector('.mf-lines');
    const refreshLines = () => { lines.textContent = ta.value ? ta.value.split('\n').length + ' 行' : ''; };
    refreshLines();
    ta.addEventListener('input', refreshLines);
    item.querySelector('.mf-toggle-btn').addEventListener('click', () => setCompact(item, !item.classList.contains('compact')));
    item.querySelector('.mf-remove-btn').addEventListener('click', () => {
      if (multiFileList.children.length > 1) item.remove();
      else { ta.value = ''; item.querySelector('.mf-filename-input').value = ''; refreshLines(); }
      updateMfSummary();
    });
    return item;
  }

  function setCompact(item, compact) {
    item.classList.toggle('compact', compact);
    item.querySelector('.mf-toggle-btn').textContent = compact ? '展開' : '收合';
  }

  function addFileItem(filename, code, compact) {
    const item = createFileItem(filename, code, compact);
    multiFileList.appendChild(item);
    updateMfSummary();
    return item;
  }

  function resetFileList() {
    multiFileList.innerHTML = '';
    addFileItem('', '');
    addFileItem('', '');
  }

  function replaceFileList(files) {
    multiFileList.innerHTML = '';
    const compact = files.length > COMPACT_THRESHOLD;
    files.forEach(f => addFileItem(f.filename, f.code, compact));
  }

  function collectFilesFromUI() {
    return [...multiFileList.querySelectorAll('.mf-file-item')].map(item => ({
      filename: item.querySelector('.mf-filename-input').value.trim() || null,
      code: item.querySelector('textarea').value
    }));
  }

  function clearResults() {
    results.innerHTML = '';
    lastScan = null;
    setStatus('');
  }

  multiFileToggle.addEventListener('change', () => {
    setMultiFileMode(isMultiFileMode());
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
    sourceLabel = null;
    clearResults();

    if (loaded.length > 1 || isMultiFileMode()) {
      setMultiFileMode(true);
      // 保留使用者已經填了內容的項目,空白項目用新檔案填入
      const kept = collectFilesFromUI().filter(f => f.code.trim());
      replaceFileList(kept.concat(loaded));
    } else if (loaded[0]) {
      codeInput.value = loaded[0].code;
      sourceLabel = loaded[0].filename;
      singleFilename = loaded[0].filename;
      updateInputMeta();
    }

    const msg = loaded.length ? '已讀取 ' + loaded.map(f => f.filename).join('、') + '。按「開始檢查」。' : '';
    setStatus([msg].concat(errors).filter(Boolean).join(' '));
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

  // ───────────────────────── 從 GitHub 匯入 ─────────────────────────

  async function runGitHubImport() {
    const url = ghUrl.value.trim();
    if (!url) { setStatus('請先貼上 GitHub 專案網址。'); ghUrl.focus(); return; }
    ghImportBtn.disabled = true;
    ghImportBtn.textContent = '匯入中…';
    clearResults();
    try {
      const r = await importFromGitHub(url, setStatus);
      sourceLabel = 'GitHub ' + r.label;
      setMultiFileMode(true);
      replaceFileList(r.files);
      setStatus('已從 ' + r.label + ' 匯入 ' + r.files.length + ' 個檔案。' + (r.notes.length ? ' ' + r.notes.join(' ') : ''));
      runScan({ keepStatus: true });
    } catch (e) {
      setStatus(e instanceof GitHubImportError ? e.message : 'GitHub 匯入失敗，請稍後再試。');
    } finally {
      ghImportBtn.disabled = false;
      ghImportBtn.textContent = '匯入';
    }
  }

  ghImportBtn.addEventListener('click', runGitHubImport);
  ghUrl.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); runGitHubImport(); } });

  // ───────────────────────── 掃描 ─────────────────────────

  function startScanUI() {
    scanBtn.disabled = true;
    scanSweep.classList.remove('running');
    void scanSweep.offsetWidth; // 重新觸發動畫
    scanSweep.classList.add('running');
  }

  function finishScanUI(r, source, opts) {
    lastScan = { findings: r.findings, notices: r.notices, astUsed: r.astUsed, analysis: r.analysis, language: r.language, source };
    results.innerHTML = findingRenderer(r.findings, r.languageCaveat, r.notices);
    scanBtn.disabled = false;
    if (!opts || !opts.keepStatus) setStatus('');
    const summary = results.querySelector('.results-summary');
    if (summary) {
      scrollIntoViewSmart(summary);
      summary.focus({ preventScroll: true });
    }
  }

  function runScan(opts) {
    if (scanBtn.disabled) return;
    if (!opts || !opts.keepStatus) setStatus('檢查中…');
    if (isMultiFileMode()) {
      const files = collectFilesFromUI();
      if (!files.some(f => (f.code || '').trim())) {
        results.innerHTML = '';
        setStatus('請先貼上至少一個檔案的程式碼。');
        return;
      }
      startScanUI();
      window.setTimeout(() => {
        finishScanUI(scanFiles(files), sourceLabel || (files.length + ' 個檔案'), opts);
      }, SCAN_DELAY_MS);
      return;
    }

    const code = codeInput.value;
    if (!code.trim()) {
      results.innerHTML = '';
      setStatus('請先貼上程式碼，或按「看範例」試試看。');
      codeInput.focus();
      return;
    }
    startScanUI();
    window.setTimeout(() => {
      // 從檔案讀入時帶檔名,讓副檔名規則(CSP、語言、測試檔)生效
      finishScanUI(scanCode(code, { filename: singleFilename }), sourceLabel || ('貼上的程式碼（' + code.split('\n').length + ' 行）'), opts);
    }, SCAN_DELAY_MS);
  }

  scanBtn.addEventListener('click', () => runScan());

  // Ctrl/⌘ + Enter:在任何輸入框內都能直接檢查
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
    const item = textarea.closest('.mf-file-item');
    if (item && item.classList.contains('compact')) setCompact(item, false);
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
    // 「參考」(測試檔、範例假金鑰)不放進修正指令
    results.querySelectorAll('.result-card.tier1, .result-card.tier2').forEach((card, i) => {
      const title = card.querySelector('.rc-title-text');
      const where = card.dataset.where;
      items.push((i + 1) + '. ' + (title ? title.textContent : '') + (where ? '（' + where + '）' : ''));
      const handoff = card.querySelector('.rc-handoff');
      if (handoff && !seen.has(handoff.dataset.kind)) {
        seen.add(handoff.dataset.kind);
        instructions.push('【' + (title ? title.textContent : '') + '】\n' + handoff.querySelector('.rc-handoff-text').textContent);
      }
    });
    return '我用資安檢查工具檢查了我的程式碼，發現以下問題：\n' + items.join('\n') +
      '\n\n請依序幫我處理，各類問題的處理要求如下：\n\n' + instructions.join('\n\n');
  }

  // ── 匯出報告:不含原始碼、金鑰已遮罩(內容由 buildReportMarkdown 產生) ──

  // 檢查方式的白話說明:多檔案時分別列出完整分析／簡易比對／不適用的檔案數
  function describeMode(scan) {
    if (scan.analysis) {
      const a = scan.analysis;
      const parts = [];
      if (a.full) parts.push(`${a.full} 個檔案完整分析（含語法分析）`);
      if (a.simple) parts.push(`${a.simple} 個檔案簡易比對（含無法解析的語法，例如 TypeScript 型別）`);
      if (a.other) parts.push(`${a.other} 個檔案規則比對（HTML／Python 不使用語法分析）`);
      return parts.join('、');
    }
    if (scan.language === 'python' || scan.language === 'html') return '規則比對（HTML／Python 不使用語法分析）';
    return scan.astUsed ? '完整分析（含語法分析）' : '簡易比對（程式碼含無法解析的語法，例如 TypeScript 型別）';
  }

  // 頁尾版本號由 scripts/stamp-version.js 寫入;報告附上版本,結果不一致時可對照是否為同一版
  function appVersion() {
    const el = document.getElementById('appVersion');
    return el ? el.textContent.trim() : '';
  }

  function currentReport() {
    if (!lastScan) return '';
    return buildReportMarkdown(lastScan.findings, lastScan.notices, {
      generatedAt: new Date().toLocaleString('zh-TW', { hour12: false }),
      source: lastScan.source,
      mode: describeMode(lastScan),
      toolUrl: TOOL_URL,
      version: appVersion()
    });
  }

  function toggleExportPanel(anchorBtn) {
    const existing = results.querySelector('.export-panel');
    if (existing) { existing.remove(); anchorBtn.setAttribute('aria-expanded', 'false'); return; }
    const panel = document.createElement('div');
    panel.className = 'export-panel';
    const canShare = typeof navigator.share === 'function';
    panel.innerHTML =
      '<div class="ep-head">報告內容<span class="ep-note">不含你的程式碼，金鑰只顯示前後幾碼</span></div>' +
      '<pre class="ep-preview" tabindex="0"></pre>' +
      '<div class="ep-actions">' +
        '<button type="button" class="ep-copy">複製報告</button>' +
        '<button type="button" class="ep-download btn-ghost">下載 .md 檔</button>' +
        (canShare ? '<button type="button" class="ep-share btn-ghost">分享…</button>' : '') +
      '</div>';
    panel.querySelector('.ep-preview').textContent = currentReport();
    anchorBtn.closest('.results-summary').after(panel);
    anchorBtn.setAttribute('aria-expanded', 'true');
  }

  function downloadReport() {
    const blob = new Blob([currentReport()], { type: 'text/markdown;charset=utf-8' });
    const a = document.createElement('a');
    const d = new Date();
    const pad = n => String(n).padStart(2, '0');
    a.href = URL.createObjectURL(blob);
    a.download = `資安檢查報告-${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  results.addEventListener('click', e => {
    const t = e.target;
    const copyBtn = t.closest('.rc-copy-btn');
    if (copyBtn) {
      const text = copyBtn.closest('.rc-handoff').querySelector('.rc-handoff-text').textContent;
      copyText(text).then(() => flashButton(copyBtn, '已複製 ✓'), () => flashButton(copyBtn, '複製失敗'));
      return;
    }
    const copyAll = t.closest('.rs-copy-all');
    if (copyAll) {
      copyText(buildCopyAllText()).then(() => flashButton(copyAll, '已複製全部 ✓'), () => flashButton(copyAll, '複製失敗'));
      return;
    }
    const exportBtn = t.closest('.rs-export');
    if (exportBtn) { toggleExportPanel(exportBtn); return; }
    const epCopy = t.closest('.ep-copy');
    if (epCopy) {
      copyText(currentReport()).then(() => flashButton(epCopy, '已複製 ✓'), () => flashButton(epCopy, '複製失敗'));
      return;
    }
    if (t.closest('.ep-download')) { downloadReport(); return; }
    if (t.closest('.ep-share')) {
      navigator.share({ title: '資安自我檢查報告', text: currentReport() }).catch(() => { /* 使用者取消分享 */ });
      return;
    }
    const chip = t.closest('.rs-chip[data-jump]');
    if (chip) {
      const card = $(chip.dataset.jump);
      if (card) { scrollIntoViewSmart(card); card.focus({ preventScroll: true }); }
      return;
    }
    const lineTag = t.closest('.rc-line-tag');
    if (lineTag) {
      selectRange(findTextareaFor(lineTag.dataset.file), Number(lineTag.dataset.start), Number(lineTag.dataset.end));
    }
  });

  // ───────────────────────── 範例／清除 ─────────────────────────

  function buildSampleCode() {
    // 金鑰以片段組合,避免這份原始碼本身被同一套規則判定為外洩;簽章段是隨機字元(不是真的簽章),
    // 刻意不含 fake/demo 等字樣,否則會被判為「範例假金鑰」而降為參考,範例就看不到「需要處理」
    const serviceRoleKey = [
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
      'eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InByb2plY3RyZWYiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjIwMTU1NzYwMDB9',
      'Qm7vR2kLzX9pN4tW8yBc3sH6jD1fG5aE0uKi'
    ].join('.');
    // 範例需同時展示「需要處理」與「請你確認」兩層(正則版與 AST 版皆然)
    return [
      '// 範例：一段常見的 AI 產生程式碼（金鑰是假的）',
      'import { createClient } from "@supabase/supabase-js";',
      '',
      'const supabase = createClient(',
      '  "https://exampleproj.supabase.co",',
      '  "' + serviceRoleKey + '"',
      ');',
      '',
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
    sourceLabel = '範例程式碼';
    singleFilename = null;
    if (isMultiFileMode()) {
      // 「前端有遮罩、後端沒遮罩」的 M11 典型案例
      replaceFileList([
        { filename: 'frontend/api.js', code: [
          'const OPENAI_KEY = "sk-proj-' + 'Xa7Qm2Lp9Rt4Vn8Kc3Zw6Hy1Bd5Fg0Js' + '";',
          '',
          'function publicRoom(room) {',
          '  return json({ id: room.id, state: maskState(room.state) });',
          '}'
        ].join('\n') },
        { filename: 'backend/history.js', code: [
          'function getOrder(req, res) {',
          '  const order = db.find(req.params.id);',
          '  res.json(order);',
          '}',
          '',
          'function publicHistoryRow(row) {',
          '  return json({ id: row.id, state: row.state });',
          '}'
        ].join('\n') }
      ]);
    } else {
      codeInput.value = buildSampleCode();
      updateInputMeta();
    }
    runScan();
  });

  $('clearBtn').addEventListener('click', () => {
    sourceLabel = null;
    singleFilename = null;
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
  // 初始主題已由 assets/theme-init.js 在首次繪製前套用,這裡只負責按鈕狀態與切換。

  const THEME_KEY = 'ai-scanner-theme';
  const root = document.documentElement;

  function syncThemeButton() {
    const light = root.getAttribute('data-theme') === 'light';
    $('themeIcon').textContent = light ? '☽' : '☼';
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

  // ───────────────────────── 分頁(#boundary / #howto / #privacy 可直接連結) ─────────────────────────

  const tabButtons = [...document.querySelectorAll('.top-tab')];
  const HASH_ALIASES = { privacy: { tab: 'boundary', focus: 'privacy' } };

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
    if (opts && opts.focusId) {
      const el = $(opts.focusId);
      if (el) { scrollIntoViewSmart(el); el.focus({ preventScroll: true }); }
    } else if (!opts || !opts.keepScroll) {
      window.scrollTo({ top: 0, behavior: 'auto' });
    }
  }

  function applyHash(keepScroll) {
    const h = location.hash.replace('#', '');
    const alias = HASH_ALIASES[h];
    const key = alias ? alias.tab : h;
    const btn = tabButtons.find(b => b.dataset.hash === key);
    activateTab(btn ? btn.id : 'tab-btn-scan', { fromHash: true, keepScroll, focusId: alias && alias.focus });
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
  // 同一個錨點重複點擊不會觸發 hashchange,所以站內錨點自己處理
  document.querySelectorAll('a[href^="#"]').forEach(a => {
    a.addEventListener('click', e => {
      e.preventDefault();
      history.replaceState(null, '', a.getAttribute('href'));
      applyHash(false);
    });
  });
  window.addEventListener('hashchange', () => applyHash(false));
  applyHash(true);
})();
