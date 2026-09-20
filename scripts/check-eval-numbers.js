/**
 * 報告數字與實際輸出一致 — verify 的子步驟
 *
 * 職責:實際跑一次各項準確度評測,再比對 README.md 與 eval/EVAL_REPORT.md 裡宣告的數字。
 * 文件用 HTML 註解標出自己宣告了哪些數字(看板面不會顯示):
 *   <!-- eval-numbers: cases.regex=20/21 cases.ast=21/21 -->
 * 分數對不上、或同一段文字裡少了對應的百分比,就讓 verify 紅燈。
 *
 * 為什麼:CLAUDE.md 原本只寫「跑過 eval 再依實際輸出更新」,是紀律不是檢查;
 *        結果 EVAL_REPORT.md 的命中率停在 7/9,實際早就是 8/9,過了好幾輪沒人發現。
 *        評測數字寫錯比沒寫更糟——它會讓人以為自己知道工具有多準。(背景見 docs/CHANGELOG.md)
 *
 * 能力邊界:檢查的是「標記裡的分數 = 實際跑出來的分數」,以及「寫著那個分數的那一行有對應的百分比」。
 * 同一行裡若有多處寫法而只改壞其中一處,抓不到。真正會失準的情境(分數整個過期)抓得到。
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const root = path.join(__dirname, '..');
const run = args => execFileSync('node', args, { cwd: root, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] });
const ast = script => ['-e', `require('./eval/load-ast');require('./eval/${script}');`];

/** 從輸出裡抓第一個符合的 a/b */
function frac(out, re, label) {
  const m = re.exec(out);
  if (!m) throw new Error(`評測輸出裡找不到「${label}」的數字,請確認 eval 腳本的輸出格式有沒有改`);
  return m[1] + '/' + m[2];
}

const HIT = /(\d+)\/(\d+) = \d/;                 // scaled:【命中率】下第一個 a/b
const RATE = /命中率:\s*(\d+)\/(\d+)/;            // run_eval
const FP = /誤判率:\s*(\d+)\/(\d+)/;              // run_fp_eval

const actual = {
  'cases.regex': frac(run(['eval/run_scaled_eval.js']).split('【命中率】')[1] || '', HIT, 'eval/cases 正則版命中率'),
  'cases.ast': frac(run(ast('run_scaled_eval.js')).split('【命中率】')[1] || '', HIT, 'eval/cases AST 版命中率'),
  'cases.fp': frac(run(['eval/run_fp_eval.js']), FP, '誤判率'),
  'samples.regex': frac(run(['eval/run_eval.js']), RATE, 'eval/samples.js 正則版命中率'),
  'samples.ast': frac(run(ast('run_eval.js')), RATE, 'eval/samples.js AST 版命中率')
};

/** a/b → 可接受的百分比寫法(100.0% 也允許寫成 100%) */
function percents(f) {
  const [a, b] = f.split('/').map(Number);
  const p = (a / b * 100).toFixed(1);
  return p.slice(-2) === '.0' ? [p + '%', p.slice(0, -2) + '%'] : [p + '%'];
}

const DOCS = ['README.md', 'eval/EVAL_REPORT.md'];
const MARKER = /<!--\s*eval-numbers:([^>]*?)-->/g;
const problems = [];
let declared = 0;

DOCS.forEach(rel => {
  const text = fs.readFileSync(path.join(root, rel), 'utf-8');
  let m;
  let found = false;
  MARKER.lastIndex = 0;
  while ((m = MARKER.exec(text))) {
    found = true;
    m[1].trim().split(/\s+/).filter(Boolean).forEach(pair => {
      const [key, val] = pair.split('=');
      declared++;
      if (!(key in actual)) { problems.push(`${rel}: 不認得的項目「${key}」(可用:${Object.keys(actual).join('、')})`); return; }
      if (actual[key] !== val) { problems.push(`${rel}: ${key} 宣告 ${val},實際跑出來是 ${actual[key]}`); return; }
      // 百分比必須跟分數寫在同一行(表格列),否則改了分數卻忘了改百分比就抓不到
      const want = percents(val);
      const fracRe = new RegExp('(^|[^\\d/])' + val.replace('/', '\\/') + '([^\\d/]|$)');
      const lines = text.split(/\r?\n/).filter(l => fracRe.test(l));
      if (!lines.length) problems.push(`${rel}: ${key} 宣告 ${val},但文中沒有一行寫出這個分數`);
      else if (!lines.some(l => want.some(p => l.indexOf(p) >= 0))) {
        problems.push(`${rel}: ${key} = ${val},但寫著這個分數的那一行沒有對應的百分比 ${want[0]}`);
      }
    });
  }
  if (!found) problems.push(`${rel}: 找不到 <!-- eval-numbers: … --> 標記,無法確認裡面的數字是不是最新的`);
});

if (problems.length) {
  console.error('❌ 報告數字與實際輸出不一致:');
  problems.forEach(p => console.error('   ' + p));
  console.error('');
  console.error('   處理方式:跑 npm run eval / eval:ast / eval:fp,依實際輸出更新文件裡的數字與標記。');
  process.exit(1);
}
console.log(`${DOCS.length} 份文件、${declared} 個宣告的數字` + Object.keys(actual).map(k => ` ${k}=${actual[k]}`).join(''));
