const { runScan } = require('./eval-orchestrator');
const { samples } = require('./samples');

const acornAvailable = typeof global.acorn !== 'undefined';

console.log('═'.repeat(70));
console.log('真實世界案例評測 — 2026年AI常見資安問題 × 工具實測命中率');
console.log('模式: ' + (acornAvailable ? 'AST版(acorn已載入)' : '正則保底版(acorn未載入,模擬CDN失敗/離線)'));
console.log('═'.repeat(70));
console.log();

let totalExpected = 0;
let totalHit = 0;
let totalMiss = 0;
const missedCases = [];

samples.forEach(sample => {
  const { findings } = runScan(sample.code);
  const actualKinds = findings.map(f => f.kind);
  const expectedKinds = sample.expectedFindings;

  const hit = expectedKinds.filter(k => actualKinds.includes(k));
  const miss = expectedKinds.filter(k => !actualKinds.includes(k));

  totalExpected += expectedKinds.length;
  totalHit += hit.length;
  totalMiss += miss.length;
  if (miss.length > 0) missedCases.push({ id: sample.id, category: sample.category, miss });

  const status = miss.length === 0 ? '✅' : '❌';
  console.log(`${status} 案例 #${sample.id}: ${sample.category}`);
  if (miss.length > 0) console.log(`   漏判: ${miss.join(', ')}`);
});

console.log();
console.log('─'.repeat(70));
console.log(`命中率: ${totalHit}/${totalExpected} = ${(totalHit / totalExpected * 100).toFixed(1)}%`);
if (missedCases.length > 0) {
  console.log('漏判案例: ' + missedCases.map(c => '#' + c.id).join(', '));
}
