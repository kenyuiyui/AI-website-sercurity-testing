// 在首次繪製前套用主題,避免深淺色閃爍。獨立成檔案是為了配合 CSP(script-src 'self',不允許行內腳本)。
(function () {
  var t = null;
  try { t = localStorage.getItem('ai-scanner-theme'); } catch (e) { /* 私密模式等情況無法讀取,改用系統設定 */ }
  if (!t) t = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  if (t === 'light') document.documentElement.setAttribute('data-theme', 'light');
})();
