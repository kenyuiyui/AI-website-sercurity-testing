/**
 * github-import.js — 從公開 GitHub 專案網址抓取原始碼檔案(純瀏覽器,不經過任何自家伺服器)
 *
 * 流程:解析網址 → api.github.com 取得預設分支與檔案清單(2 次 API 呼叫)
 *       → 篩選程式碼檔案 → raw.githubusercontent.com 下載內容(不計入 API 次數)
 * 只讀取、不送出任何使用者內容。CSP 的 connect-src 只允許這兩個網域。
 * 未登入的 GitHub API 限制約每小時 60 次(= 約 30 次匯入)。私人專案回 404,請使用者改用拖放。
 */

const GH_MAX_FILES = 150; // 為什麼:60 個上限曾讓 104 個程式碼檔的專案漏掃 44 個(含後台頁面)。(背景見 docs/CHANGELOG.md)
const GH_MAX_FILE_BYTES = 300 * 1024;
const GH_CONCURRENCY = 6;

const GH_CODE_EXT = /\.(m?[jt]sx?|cjs|vue|svelte|astro|py|html?|php|rb)$/i;
const GH_ENV_FILE = /(^|\/)\.env(\.[\w-]+)?$/i;           // .env、.env.local…(公開 repo 出現就是問題)
const GH_ENV_TEMPLATE = /\.(example|sample|template|dist)$/i;
const GH_CONFIG_FILE = /(^|\/)(vercel|firebase|netlify)\.json$|(^|\/)(firestore|storage|database)\.rules(\.json)?$/i;
const GH_SKIP_DIR = /(^|\/)(node_modules|dist|build|out|\.next|\.nuxt|\.svelte-kit|\.vercel|coverage|vendor|\.git|__pycache__|venv|\.venv)\//i;
const GH_SKIP_FILE = /\.min\.[jc]ss?$|\.d\.ts$|\.map$|(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/i;
// 不檢查、但與安全有關的檔案類型(資料庫規則、部署設定):不下載,只在報告的檢查範圍裡列出數量,讓使用者知道要自己看
const GH_NOT_CHECKED = /\.(sql|ya?ml|toml|conf)$/i;
// 優先匯入:最可能含金鑰、權限、資料庫邏輯的路徑
const GH_PRIORITY = /(api|server|route|routes|controller|service|lib|db|database|supabase|firebase|auth|middleware|functions|config|\.env)/i;

class GitHubImportError extends Error {}

/**
 * 解析 GitHub 網址。接受:
 * https://github.com/owner/repo、.../tree/branch/sub/path、.../blob/branch/file.js、owner/repo
 * @returns {{owner: string, repo: string, ref: string|null, path: string, singleFile: boolean}|null}
 */
function parseGitHubUrl(input) {
  let s = String(input || '').trim();
  if (!s) return null;
  s = s.replace(/^git\+/, '').replace(/^git@github\.com:/, 'https://github.com/');
  if (/^[\w.-]+\/[\w.-]+$/.test(s)) s = 'https://github.com/' + s;
  if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
  let url;
  try { url = new URL(s); } catch (e) { return null; }
  if (!/^(www\.)?github\.com$/i.test(url.hostname)) return null;
  const parts = url.pathname.split('/').filter(Boolean);
  if (parts.length < 2) return null;
  const owner = parts[0];
  const repo = parts[1].replace(/\.git$/i, '');
  let ref = null;
  let path = '';
  let singleFile = false;
  if ((parts[2] === 'tree' || parts[2] === 'blob') && parts[3]) {
    ref = decodeURIComponent(parts[3]);
    path = parts.slice(4).map(decodeURIComponent).join('/');
    singleFile = parts[2] === 'blob';
  }
  return { owner, repo, ref, path, singleFile };
}

function isWantedPath(p) {
  if (GH_SKIP_DIR.test(p) || GH_SKIP_FILE.test(p)) return false;
  if (GH_ENV_FILE.test(p)) return !GH_ENV_TEMPLATE.test(p);
  return GH_CODE_EXT.test(p) || GH_CONFIG_FILE.test(p);
}

/**
 * 從 git tree 清單挑出要匯入的檔案(依優先度排序,最多 GH_MAX_FILES 個)
 * @param {Array<{path: string, type: string, size?: number}>} tree
 * @param {string} basePath - 只取這個子資料夾底下的檔案('' = 全部)
 * @returns {{files: Array, skippedTooLarge: number, total: number}}
 */
function selectGitHubFiles(tree, basePath) {
  const prefix = basePath ? basePath.replace(/\/+$/, '') + '/' : '';
  let skippedTooLarge = 0;
  const skippedLarge = [];
  const notChecked = {};
  const candidates = tree.filter(t => {
    if (t.type !== 'blob') return false;
    if (prefix && !t.path.startsWith(prefix) && t.path !== basePath) return false;
    if (!isWantedPath(t.path)) {
      const ext = (t.path.match(GH_NOT_CHECKED) || [])[1];
      if (ext && !GH_SKIP_DIR.test(t.path) && !GH_SKIP_FILE.test(t.path) && !GH_CONFIG_FILE.test(t.path)) {
        const k = ext.toLowerCase();
        notChecked[k] = (notChecked[k] || 0) + 1;
      }
      return false;
    }
    if ((t.size || 0) > GH_MAX_FILE_BYTES) { skippedTooLarge++; skippedLarge.push(t.path); return false; }
    return true;
  });
  candidates.sort((a, b) => {
    const pa = GH_PRIORITY.test(a.path) ? 0 : 1;
    const pb = GH_PRIORITY.test(b.path) ? 0 : 1;
    return (pa - pb) || a.path.split('/').length - b.path.split('/').length || a.path.localeCompare(b.path);
  });
  const files = candidates.slice(0, GH_MAX_FILES);
  return {
    files, skippedTooLarge, total: candidates.length,
    // 檢查範圍(交給 scan-orchestrator 的 scanFiles 寫進報告):被上限擠掉的、太大的、不檢查的類型
    coverage: { total: candidates.length + skippedTooLarge, skippedLimit: candidates.slice(GH_MAX_FILES).map(t => t.path), skippedLarge, failed: [], notChecked }
  };
}

async function ghFetchJson(url) {
  let res;
  try {
    res = await fetch(url, { headers: { Accept: 'application/vnd.github+json' }, credentials: 'omit', referrerPolicy: 'no-referrer' });
  } catch (e) {
    throw new GitHubImportError('連不上 GitHub。可能是網路斷線、公司防火牆，或瀏覽器擋住了連線。');
  }
  if (res.status === 404) throw new GitHubImportError('找不到這個專案，或它是私人專案。私人專案請下載後用「開啟檔案」或拖放的方式檢查。');
  if (res.status === 403 || res.status === 429) {
    const remaining = res.headers.get('x-ratelimit-remaining');
    if (remaining === '0' || res.status === 429) {
      const reset = Number(res.headers.get('x-ratelimit-reset')) * 1000;
      const mins = reset ? Math.max(1, Math.ceil((reset - Date.now()) / 60000)) : null;
      throw new GitHubImportError('GitHub 限制了匯入次數（每小時約 30 次）' + (mins ? `，約 ${mins} 分鐘後可再試` : '，請稍後再試') + '。也可以改用拖放檔案。');
    }
    throw new GitHubImportError('GitHub 拒絕了這次讀取（HTTP 403）。');
  }
  if (!res.ok) throw new GitHubImportError(`GitHub 回應錯誤（HTTP ${res.status}），請稍後再試。`);
  return res.json();
}

function rawUrl(owner, repo, ref, path) {
  const enc = s => s.split('/').map(encodeURIComponent).join('/');
  return `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${enc(ref)}/${enc(path)}`;
}

async function fetchRaw(url) {
  const res = await fetch(url, { credentials: 'omit', referrerPolicy: 'no-referrer' });
  if (!res.ok) throw new Error('HTTP ' + res.status);
  const text = await res.text();
  if (text.indexOf('\u0000') !== -1) throw new Error('not text');
  return text;
}

/**
 * 匯入公開 GitHub 專案
 * @param {string} input - 使用者輸入的網址
 * @param {(msg: string) => void} onProgress
 * @returns {Promise<{files: Array<{filename: string, code: string}>, label: string, notes: string[], coverage: object|null}>}
 */
async function importFromGitHub(input, onProgress) {
  const info = parseGitHubUrl(input);
  if (!info) throw new GitHubImportError('看不懂這個網址。請貼上像 https://github.com/帳號/專案名稱 的專案網址。');
  const progress = onProgress || (() => {});
  const api = `https://api.github.com/repos/${encodeURIComponent(info.owner)}/${encodeURIComponent(info.repo)}`;

  progress('讀取專案資訊…');
  const repoMeta = await ghFetchJson(api);
  const ref = info.ref || repoMeta.default_branch || 'main';
  const notes = [];

  let targets;
  let coverage = null;
  if (info.singleFile) {
    targets = [{ path: info.path }];
  } else {
    progress('讀取檔案清單…');
    const tree = await ghFetchJson(`${api}/git/trees/${encodeURIComponent(ref)}?recursive=1`);
    const picked = selectGitHubFiles(tree.tree || [], info.path);
    targets = picked.files;
    coverage = picked.coverage;
    if (tree.truncated) notes.push('專案太大，GitHub 只回傳部分檔案清單；建議改貼子資料夾的網址（例如 …/tree/main/src）。');
    if (picked.total > picked.files.length) notes.push(`符合條件的檔案有 ${picked.total} 個，已優先匯入最可能有問題的 ${picked.files.length} 個；想檢查其他檔案，可改貼子資料夾的網址。`);
    if (picked.skippedTooLarge) notes.push(`略過 ${picked.skippedTooLarge} 個超過 300KB 的檔案。`);
  }
  if (!targets.length) throw new GitHubImportError('這個專案裡沒有找到可以檢查的程式碼檔案（.js／.ts／.jsx／.tsx／.py／.html 等）。');

  const files = [];
  let failed = 0;
  let done = 0;
  const queue = targets.slice();
  async function worker() {
    while (queue.length) {
      const t = queue.shift();
      try {
        files.push({ filename: t.path, code: await fetchRaw(rawUrl(info.owner, info.repo, ref, t.path)) });
      } catch (e) {
        failed++;
        if (coverage) coverage.failed.push(t.path);
      }
      done++;
      progress(`下載檔案 ${done}／${targets.length}…`);
    }
  }
  await Promise.all(Array.from({ length: Math.min(GH_CONCURRENCY, targets.length) }, worker));
  if (!files.length) throw new GitHubImportError('檔案都下載失敗了，請稍後再試。');
  if (failed) notes.push(`${failed} 個檔案下載失敗，已略過。`);

  files.sort((a, b) => targets.findIndex(t => t.path === a.filename) - targets.findIndex(t => t.path === b.filename));
  return { files, label: `${info.owner}/${info.repo}（${ref}${info.path ? '／' + info.path : ''}）`, notes, coverage };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { parseGitHubUrl, selectGitHubFiles, isWantedPath, importFromGitHub, GitHubImportError, GH_MAX_FILES };
}
