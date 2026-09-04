/**
 * run_scaled_eval.js — 規模化準確度驗證主腳本
 *
 * 讀取 eval/cases/ 底下所有 .txt 案例(格式見 CASE_FORMAT.md),
 * 分成「應偵測到問題」(true positive 樣本)與「應保持安全放行」(true negative 樣本)
 * 兩組,分別計算命中率 / 誤判率,並用 Wilson score interval 算出 95% 信賴區間,
 * 同時顯示距離 ±5 個百分點目標還需要多少樣本。
 *
 * 執行方式:
 *   node run_scaled_eval.js                                              (正則保底版)
 *   node -e "global.acorn=require('acorn');require('./run_scaled_eval.js');"  (AST完整版)
 *
 * 只驗證整體統計數字(不分模組),符合目前的驗證目標設定。
 * 案例來源(SOURCE 欄位)應為真實蒐集的案例,而非另外發想編寫 —— 這是信賴區間
 * 在統計上有效的前提:樣本需要盡量貼近真實世界分布,而不是驗證者自己預期的分布。
 */

const path = require('path');
const { runScan } = require('./eval-orchestrator');
const { loadCases } = require('./case-loader');
const { wilsonInterval, estimateRequiredN } = require('./stats');

const TARGET_HALF_WIDTH_PCT = 5; // ±5個百分點的目標
const casesDir = path.join(__dirname, 'cases');

const acornAvailable = typeof global.acorn !== 'undefined';

console.log('═'.repeat(74));
console.log('規模化準確度驗證 — 整體命中率 / 誤判率 + 統計信賴區間');
console.log('模式: ' + (acornAvailable ? 'AST版(acorn已載入)' : '正則保底版(acorn未載入,模擬CDN失敗/離線)'));
console.log('═'.repeat(74));
console.log();

let allCases;
try {
  allCases = loadCases(casesDir);
} catch (e) {
  console.error('❌ 案例載入失敗:\n');
  console.error(e.message);
  process.exit(1);
}

if (allCases.length === 0) {
  console.log('⚠️  eval/cases/ 資料夾內目前沒有正式案例(底線開頭的範例檔不算)。');
  console.log('    請依 CASE_FORMAT.md 的格式新增 .txt 案例檔案後再執行。');
  process.exit(0);
}

const tpCases = allCases.filter(c => c.expected.length > 0);
const tnCases = allCases.filter(c => c.expected.length === 0);

console.log(`已載入案例: 共 ${allCases.length} 個（應偵測到問題 ${tpCases.length} 個 / 應安全放行 ${tnCases.length} 個）`);
console.log();

// ── 命中率統計(true positive 樣本) ──
let tpExpectedTotal = 0;
let tpHitTotal = 0;
const tpMissedCases = [];

tpCases.forEach(c => {
  const { findings } = runScan(c.code);
  const actualKinds = findings.map(f => f.kind);
  const hit = c.expected.filter(k => actualKinds.includes(k));
  const miss = c.expected.filter(k => !actualKinds.includes(k));
  tpExpectedTotal += c.expected.length;
  tpHitTotal += hit.length;
  if (miss.length > 0) {
    tpMissedCases.push({ filename: c.filename, category: c.category, miss });
  }
});

// ── 誤判率統計(true negative 樣本) ──
//
// 「誤判」的判定標準(2026,依專案優先序調整):
// 只有 tier1(高信心度發現)的誤報才計入誤判率。tier2(建議人工複查)本身設計上
// 就是刻意保守——寧可多提示一則「這裡看起來可疑,建議自行確認」,也不要放過
// 真正的問題。使用者面對 tier2 提示頂多多看一眼、自行判斷排除;但如果把 tier2
// 也算進「誤判」,會逼工具在正則規則設計上變得更保守、更容易漏掉真正的問題,
// 這與專案目標使用者(不熟悉資安的人)的實際需求方向相反——漏掉一個真的外洩的
// 金鑰,代價遠高於多看一則需要自行排除的提示。
// 因此:tier1 誤報 = 真正的誤判;tier2 出現 = 正常運作,不計入誤判率。
let tnCorrectTotal = 0;
const tnFalsePositiveCases = [];
const tnTier2OnlyCases = []; // tier2提示但不算誤判的案例,單獨列出方便檢視規則是否過於敏感

tnCases.forEach(c => {
  const { findings } = runScan(c.code);
  const tier1Findings = findings.filter(f => f.tier === 1);
  const tier2Findings = findings.filter(f => f.tier === 2);

  if (tier1Findings.length === 0) {
    tnCorrectTotal += 1;
    if (tier2Findings.length > 0) {
      tnTier2OnlyCases.push({
        filename: c.filename,
        category: c.category,
        tier2Hits: tier2Findings.map(f => f.kind)
      });
    }
  } else {
    tnFalsePositiveCases.push({
      filename: c.filename,
      category: c.category,
      falseHits: tier1Findings.map(f => f.kind)
    });
  }
});

console.log('─'.repeat(74));
console.log('【命中率】(true positive 樣本)');
if (tpCases.length === 0) {
  console.log('  尚無 true positive 樣本,無法計算命中率。');
} else {
  const hitRate = tpExpectedTotal > 0 ? tpHitTotal / tpExpectedTotal : 0;
  const ci = wilsonInterval(tpHitTotal, tpExpectedTotal);
  console.log(`  ${tpHitTotal}/${tpExpectedTotal} = ${(hitRate * 100).toFixed(1)}%`);
  console.log(`  95% 信賴區間: [${(ci.lower * 100).toFixed(1)}%, ${(ci.upper * 100).toFixed(1)}%]  (半寬 ±${ci.halfWidthPct.toFixed(1)} 個百分點)`);
  if (ci.halfWidthPct <= TARGET_HALF_WIDTH_PCT) {
    console.log(`  ✅ 已達成 ±${TARGET_HALF_WIDTH_PCT}pt 目標`);
  } else {
    const requiredN = estimateRequiredN(hitRate, TARGET_HALF_WIDTH_PCT);
    const stillNeed = Math.max(0, requiredN - tpExpectedTotal);
    console.log(`  ⏳ 距離 ±${TARGET_HALF_WIDTH_PCT}pt 目標,估計還需要約 ${stillNeed} 個 true positive 樣本點(以目前比例估算,實際隨真實命中率變動而變化)`);
  }
  if (tpMissedCases.length > 0) {
    console.log();
    console.log('  漏判案例:');
    tpMissedCases.forEach(m => {
      console.log(`    - ${m.filename}（${m.category}）漏判: ${m.miss.join(', ')}`);
    });
  }
}

console.log();
console.log('【誤判率】(true negative 樣本)');
if (tnCases.length === 0) {
  console.log('  尚無 true negative 樣本,無法計算誤判率。');
} else {
  const correctRate = tnCorrectTotal / tnCases.length;
  const ci = wilsonInterval(tnCorrectTotal, tnCases.length);
  console.log(`  正確放行 ${tnCorrectTotal}/${tnCases.length} = ${(correctRate * 100).toFixed(1)}%（即誤判率 ${(100 - correctRate * 100).toFixed(1)}%）`);
  console.log(`  95% 信賴區間(正確放行率): [${(ci.lower * 100).toFixed(1)}%, ${(ci.upper * 100).toFixed(1)}%]  (半寬 ±${ci.halfWidthPct.toFixed(1)} 個百分點)`);
  if (ci.halfWidthPct <= TARGET_HALF_WIDTH_PCT) {
    console.log(`  ✅ 已達成 ±${TARGET_HALF_WIDTH_PCT}pt 目標`);
  } else {
    const requiredN = estimateRequiredN(correctRate, TARGET_HALF_WIDTH_PCT);
    const stillNeed = Math.max(0, requiredN - tnCases.length);
    console.log(`  ⏳ 距離 ±${TARGET_HALF_WIDTH_PCT}pt 目標,估計還需要約 ${stillNeed} 個 true negative 樣本(以目前比例估算,實際隨真實正確放行率變動而變化)`);
  }
  if (tnFalsePositiveCases.length > 0) {
    console.log();
    console.log('  誤判案例(tier1高信心度誤報,真正的誤判):');
    tnFalsePositiveCases.forEach(m => {
      console.log(`    - ${m.filename}（${m.category}）誤報: ${m.falseHits.join(', ')}`);
    });
  }
  if (tnTier2OnlyCases.length > 0) {
    console.log();
    console.log(`  ℹ️  以下 ${tnTier2OnlyCases.length} 個案例觸發了 tier2「建議人工複查」提示,不計入誤判率`);
    console.log('     (tier2 設計上就是刻意保守,寧可多提示也不要漏掉真正的問題;');
    console.log('      但若這裡的清單持續變長,代表某條 tier2 規則可能過於敏感,值得回頭檢視規則本身):');
    tnTier2OnlyCases.forEach(m => {
      console.log(`    - ${m.filename}（${m.category}）tier2提示: ${m.tier2Hits.join(', ')}`);
    });
  }
}

console.log();
console.log('═'.repeat(74));
console.log('提醒: 此統計的信賴區間在統計上成立的前提是案例來自真實蒐集、非另外發想編寫。');
console.log('      若案例本身帶有蒐集者的預期偏誤,信賴區間的數學意義會失真。');
console.log('═'.repeat(74));
