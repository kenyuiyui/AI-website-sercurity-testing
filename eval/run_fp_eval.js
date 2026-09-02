/**
 * 誤判率評測腳本(False Positive Rate Evaluation)
 * 執行方式:
 *   node eval/run_fp_eval.js                                    (正則保底版)
 *   node -e "global.acorn=require('acorn');require('./eval/run_fp_eval.js')"  (AST版)
 */

const { runScan } = require('../src/scan-orchestrator');
const { falsePositiveSamples } = require('./false_positive_samples');

const acornAvailable = typeof global.acorn !== 'undefined';

console.log('═'.repeat(70));
console.log('誤判率評測 — 安全程式碼是否被錯誤標記');
console.log('模式: ' + (acornAvailable ? 'AST版(acorn已載入)' : '正則保底版(acorn未載入,模擬CDN失敗/離線)'));
console.log('═'.repeat(70));
console.log();

let totalChecks = 0;
let falsePositiveCount = 0;
const fpCases = [];

falsePositiveSamples.forEach(sample => {
  const { findings } = runScan(sample.code);
  const actualKinds = findings.map(f => f.kind);

  const triggeredWrongly = sample.shouldNotTrigger.filter(k => actualKinds.includes(k));
  totalChecks += 1;

  if (triggeredWrongly.length > 0) {
    falsePositiveCount += 1;
    fpCases.push({ id: sample.id, module: sample.module, description: sample.description, triggeredWrongly });
    console.log(`❌ [${sample.id}] ${sample.module}: ${sample.description}`);
    console.log(`   誤判觸發: ${triggeredWrongly.join(', ')}`);
  } else {
    console.log(`✅ [${sample.id}] ${sample.module}: ${sample.description}`);
  }
});

console.log();
console.log('─'.repeat(70));
console.log(`誤判率: ${falsePositiveCount}/${totalChecks} = ${(falsePositiveCount / totalChecks * 100).toFixed(1)}%`);
console.log(`正確放行率: ${totalChecks - falsePositiveCount}/${totalChecks} = ${((totalChecks - falsePositiveCount) / totalChecks * 100).toFixed(1)}%`);
if (fpCases.length > 0) {
  console.log('誤判案例: ' + fpCases.map(c => c.id).join(', '));
}
