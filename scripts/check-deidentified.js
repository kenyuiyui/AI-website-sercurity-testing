/**
 * 去識別化自動檢查 — verify 的子步驟
 *
 * 職責:掃過「會寫進公開 repo 的文字」,找出可能指認出某個特定專案的痕跡:
 *   1. 不在允許清單裡的外部網址主機
 *   2. 指向特定 GitHub／GitLab 專案的網址(github.com/<擁有者>/<專案>)
 *   3. 電子郵件位址
 * 允許清單在 scripts/deidentify-allowlist.json;csp-detector 內建的網域清單會自動併入
 * (那是偵測規則本身必須列出的網域,不是誰的專案)。
 *
 * 能力邊界(要老實講):這只抓得到「機器看得出來」的那一半。
 * CLAUDE.md 真正在意的還包括獨特的資料夾／檔名、變數命名、情境描述——
 * 那些要靠人判斷,這支腳本不會也不該假裝抓得到。綠燈不等於安全,只等於沒有明顯的痕跡。
 *
 * 為什麼:去識別化原本只是 CLAUDE.md 的一條紀律,沒有任何機器檢查;
 *        這類錯誤一旦進了 git 歷史就補救不了。(背景見 docs/CHANGELOG.md)
 */
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const allow = JSON.parse(fs.readFileSync(path.join(__dirname, 'deidentify-allowlist.json'), 'utf-8'));
const { CSP_BYPASS_HOSTS, CSP_SHARED_HOSTING } = require(path.join(root, 'modules', 'csp-detector.js'));

// 允許清單刻意分兩種:
//  exact  完全相同才算(預設)。github.io、netlify.app 這類「人人可架站」的平台就是這種——
//         平台本身無所謂,但 someproject.netlify.app 正好就是會指認出某個專案的東西。
//  suffix 整個尾碼都算,只給 RFC 保留給文件用的網域(.test/.example/.invalid/.localhost),
//         那些網域不可能對應到真實的誰。
const exactRules = new Set(allow.hosts.filter(h => h.slice(0, 2) !== '*.')
  .concat(Object.keys(CSP_BYPASS_HOSTS))
  .concat(CSP_SHARED_HOSTING)                    // 平台本身
  .concat(CSP_SHARED_HOSTING.map(s => '*.' + s)) // CSP 政策裡會原樣寫出來的萬用字元
);
const SAFE_SUFFIX = ['.test', '.example', '.invalid', '.localhost'];
const suffixRules = allow.hosts.filter(h => h.slice(0, 2) === '*.').map(h => h.slice(1))
  .filter(sfx => SAFE_SUFFIX.indexOf(sfx) >= 0 || (exactRules.add(sfx.slice(1)), exactRules.add('*' + sfx), false));
const hostRules = Array.from(exactRules).concat(suffixRules.map(s => '*' + s));

function hostAllowed(host) {
  return exactRules.has(host) || suffixRules.some(sfx => host.slice(-sfx.length) === sfx);
}

/** CLAUDE.md 點名的範圍:案例、變更紀錄、程式碼註解與測試資料 */
function targets() {
  const out = [];
  const add = p => { if (fs.existsSync(p)) out.push(p); };
  const addDir = (dir, re) => {
    if (!fs.existsSync(path.join(root, dir))) return;
    fs.readdirSync(path.join(root, dir)).filter(f => re.test(f)).forEach(f => add(path.join(root, dir, f)));
  };
  addDir('eval/cases', /\.txt$/);
  addDir('eval/reference_cases', /\.(txt|md)$/);
  addDir('eval', /\.js$/);          // samples.js、false_positive_samples.js 等測試資料
  addDir('modules', /\.js$/);
  addDir('assets', /\.js$/);
  addDir('scripts', /\.js$/);
  add(path.join(root, 'docs', 'CHANGELOG.md'));
  add(path.join(root, 'eval', 'CASE_FORMAT.md'));
  return out;
}

// (?:…@)? 跳過網址裡的帳密段(https://user:pass@example.com),否則 user 會被誤當成主機名稱
const URL_RE = /\bhttps?:\/\/(?:[^\s/@'"`]+@)?([A-Za-z0-9.*-]+)((?:\/[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]*)?)/g;
const MAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
// 網址路徑裡帶著「<擁有者>/<專案>」的主機:值是要跳過幾個前置路徑段
// (raw.githack.com/<擁有者>/<專案>、cdn.jsdelivr.net/gh/<擁有者>/<專案> 一樣會指認出某個專案)
const REPO_HOSTS = {
  'github.com': 0, 'gitlab.com': 0, 'bitbucket.org': 0,
  'raw.githubusercontent.com': 0, 'raw.githack.com': 0, 'rawcdn.githack.com': 0,
  'cdn.jsdelivr.net': 1
};

/** 把拆成字串相加的網址接回來,例如 'https://user@' + 'example.com/x' */
function rejoin(line) {
  return line.replace(/(['"`])\s*\+\s*(['"`])/g, '');
}

function scan(file) {
  const rel = path.relative(root, file).replace(/\\/g, '/');
  const hits = [];
  fs.readFileSync(file, 'utf-8').split(/\r?\n/).forEach((raw, i) => {
    const line = rejoin(raw);
    const at = (why, what) => hits.push({ file: rel, line: i + 1, why, what });
    let m;
    URL_RE.lastIndex = 0;
    while ((m = URL_RE.exec(line))) {
      const url = m[0];
      if (allow.urls.some(u => url.indexOf(u) === 0)) continue;
      const host = m[1].toLowerCase().replace(/^\*\./, '*.');
      const bare = host.replace(/^\*\./, '');
      if (!hostAllowed(host) && !hostAllowed(bare)) { at('外部網址的主機不在允許清單', url); continue; }
      // github.com/<擁有者>/<專案> — 指向某個特定專案
      if (bare in REPO_HOSTS) {
        const skip = REPO_HOSTS[bare];
        const seg = m[2].split('/').filter(Boolean);
        // jsdelivr 只有 /gh/ 開頭才是 GitHub 專案;/npm/ 是套件名稱,不指認誰
        if (skip === 0 || seg[0] === 'gh') {
          const own = seg[skip === 0 ? 0 : 1];
          const repo = seg[skip === 0 ? 1 : 2];
          if (own && repo && allow.repoOwners.indexOf(own) < 0) at('指向特定的公開原始碼專案', url);
        }
      }
    }
    // 網址裡的帳密段(user:pass@host)不是信箱,先抹掉網址再找
    const noUrl = line.replace(new RegExp(URL_RE.source, 'g'), ' ');
    MAIL_RE.lastIndex = 0;
    while ((m = MAIL_RE.exec(noUrl))) {
      if (allow.emails.indexOf(m[0]) < 0) at('電子郵件位址', m[0]);
    }
  });
  return hits;
}

const files = targets();
const hits = files.reduce((acc, f) => acc.concat(scan(f)), []);

if (hits.length) {
  console.error(`❌ 發現 ${hits.length} 處可能指認出特定專案的內容:`);
  hits.slice(0, 30).forEach(h => console.error(`   ${h.file}:${h.line}  ${h.why} → ${h.what}`));
  if (hits.length > 30) console.error(`   …另有 ${hits.length - 30} 處`);
  console.error('');
  console.error('   處理方式:改寫成通用情境(example.com、a/b、v1.0.0/);');
  console.error('   確定是公開資訊(有 CVE／廠商公告／公開學術資料集)才加進 scripts/deidentify-allowlist.json。');
  process.exit(1);
}
console.log(`${files.length} 個檔案、允許清單 ${hostRules.length} 個網域`);
