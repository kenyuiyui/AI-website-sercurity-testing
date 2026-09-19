/**
 * check-report.js — 確認「匯出報告」不含金鑰原文與原始程式碼(verify.js 的子步驟)
 * 對所有驗證樣本產生報告,檢查:偵測到的原始片段(match)不在報告裡、樣本中較長的程式碼行不在報告裡。
 */
const fs = require('fs');
const path = require('path');
const root = path.join(__dirname, '..');
const { scanCode } = require(path.join(root, 'modules', 'scan-orchestrator'));
const { buildReportMarkdown } = require(path.join(root, 'modules', 'finding-renderer'));
const { parseCaseFile } = require(path.join(root, 'eval', 'case-loader'));
const { samples } = require(path.join(root, 'eval', 'samples'));

const codes = samples.map(s => s.code);
for (const dir of ['cases', 'reference_cases']) {
  const abs = path.join(root, 'eval', dir);
  fs.readdirSync(abs).filter(f => f.endsWith('.txt')).forEach(f => codes.push(parseCaseFile(fs.readFileSync(path.join(abs, f), 'utf-8'), f).code));
}

const bad = [];
let reports = 0;
codes.forEach((code, i) => {
  const r = scanCode(code);
  if (!r.findings.length) return;
  reports++;
  const md = buildReportMarkdown(r.findings, r.notices, {});
  r.findings.forEach(f => {
    // 20 字元以上的片段(金鑰、權杖、整行設定)不得出現;短片段如 pickle.loads( 會出現在白話說明裡,不算外洩
    if (f.match && f.match.trim().length >= 20 && md.includes(f.match.trim())) bad.push(`樣本 ${i} 的報告含偵測原文(${f.kind})`);
  });
  code.split(/\r?\n/).map(l => l.trim()).filter(l => l.length >= 24).forEach(l => {
    if (md.includes(l)) bad.push(`樣本 ${i} 的報告含程式碼行:${l.slice(0, 40)}`);
  });
});

if (bad.length) {
  console.log(bad.join('\n'));
  process.exit(1);
}
console.log(reports);
