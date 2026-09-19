/**
 * snapshot.js — 輸出所有驗證樣本的掃描結果摘要(JSON 到 stdout),供 verify.js 比對行為變化。
 *
 *   node scripts/snapshot.js regex   正則保底版(不載入 acorn)
 *   node scripts/snapshot.js ast     AST 版
 *
 * 必須各自在全新的 Node 進程執行:idor-detector 只要看到 global.acorn 就會走 AST 版。
 */

const fs = require('fs');
const path = require('path');

const mode = process.argv[2] === 'ast' ? 'ast' : 'regex';
if (mode === 'ast') global.acorn = require('acorn');

const root = path.join(__dirname, '..');
const { scanCode } = require(path.join(root, 'modules', 'scan-orchestrator'));
const { parseCaseFile } = require(path.join(root, 'eval', 'case-loader'));
const { samples } = require(path.join(root, 'eval', 'samples'));
const { falsePositiveSamples } = require(path.join(root, 'eval', 'false_positive_samples'));

// 每筆 Finding 摘要成 "kind@tier:line",同一樣本內排序,避免模組順序微調造成雜訊
const summarize = code => scanCode(code).findings
  .map(f => `${f.kind}@${f.tier}:${f.line || '-'}`)
  .sort();

const out = {};
for (const dir of ['cases', 'reference_cases']) {
  const abs = path.join(root, 'eval', dir);
  fs.readdirSync(abs).filter(f => f.endsWith('.txt')).sort().forEach(f => {
    const c = parseCaseFile(fs.readFileSync(abs + '/' + f, 'utf-8'), f);
    out[`${dir}/${f}`] = summarize(c.code);
  });
}
samples.forEach(s => { out[`samples.js#${s.id}`] = summarize(s.code); });
falsePositiveSamples.forEach((s, i) => { out[`false_positive_samples.js#${s.id || i + 1}`] = summarize(s.code); });

process.stdout.write(JSON.stringify(out));
