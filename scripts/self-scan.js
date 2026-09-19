/**
 * self-scan.js — 用本工具掃描「本專案自己」,模擬使用者貼上本 repo 的 GitHub 網址(verify.js 的子步驟)
 *
 * 本專案是純前端靜態網站,沒有真正的資安問題,所以「需要處理」必須是 0。
 * 本專案的規則定義、說明文字、測試資料裡處處是 eval(、假金鑰、SQL 拼接範例,
 * 正好是「整包專案」輸入下最容易誤報的情境,當作整專案層級的回歸測試。
 *
 *   node scripts/self-scan.js          輸出 JSON 摘要;需要處理 > 0 時以非零結束碼離開
 *   node scripts/self-scan.js --list   另外列出每一筆結果
 */

const fs = require('fs');
const path = require('path');
const root = path.join(__dirname, '..');
require(path.join(root, 'eval', 'load-ast')); // 與網頁相同:使用 vendor/ 內的語法分析
const { selectGitHubFiles } = require(path.join(root, 'assets', 'github-import'));
const { scanFiles } = require(path.join(root, 'modules', 'scan-orchestrator'));

// 走訪專案目錄,產生與 GitHub tree API 相同形狀的清單,再用 GitHub 匯入的同一套篩選
const tree = [];
(function walk(dir) {
  fs.readdirSync(dir, { withFileTypes: true }).forEach(d => {
    if (d.name === '.git' || d.name === 'node_modules') return;
    const abs = path.join(dir, d.name);
    const rel = path.relative(root, abs).split(path.sep).join('/');
    if (d.isDirectory()) walk(abs);
    else tree.push({ path: rel, type: 'blob', size: fs.statSync(abs).size });
  });
})(root);

const picked = selectGitHubFiles(tree, '').files;
const files = picked.map(f => ({ filename: f.path, code: fs.readFileSync(path.join(root, f.path), 'utf-8') }));
const r = scanFiles(files);

const byTier = { 1: 0, 2: 0, 3: 0 };
const byKind = {};
r.findings.forEach(f => {
  byTier[f.tier]++;
  const k = `${f.tier}:${f.kind}${f.context ? '(' + f.context + ')' : ''}`;
  byKind[k] = (byKind[k] || 0) + 1;
});

if (process.argv.includes('--list')) {
  r.findings.forEach(f => console.error(`[${f.tier}] ${f.filename || ''}:${f.line || '-'} ${f.kind}${f.context ? ' (' + f.context + ')' : ''}`));
}
console.log(JSON.stringify({ files: files.length, tier1: byTier[1], tier2: byTier[2], tier3: byTier[3], byKind, analysis: r.analysis }));
if (byTier[1] > 0) process.exit(1);
