/**
 * verify.js — 一鍵驗證(改完任何東西後執行 npm run verify)
 *
 * 1. 結構檢查:modules/ 檔案、index.html 載入清單、scan-orchestrator 的 Node 清單三者一致
 * 2. 說明文字覆蓋:每個模組會產生的 kind 都有 FINDING_GUIDE 說明,且列在 case-loader 的 VALID_KINDS
 * 3. 規則回歸測試:eval/run_rule_regression.js(正則版 + AST 版)
 * 4. 行為快照:所有驗證樣本的掃描結果與 eval/findings-snapshot.json 比對(正則版 + AST 版)
 *    規則改動是刻意的 → 確認差異合理後執行 npm run verify -- --update 更新快照
 *    另含:匯出報告安全、整專案自我掃描(需要處理 = 0)、GitHub 匯入解析
 * 5. 單檔版同步:referencesingle/index.html 與拆分版一致
 * 6. 畫面冒煙測試:有安裝 playwright 時才跑(scripts/ui-smoke.js),沒有就略過
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const root = path.join(__dirname, '..');
const update = process.argv.includes('--update');
const results = [];

function step(name, fn) {
  try {
    const detail = fn();
    results.push({ name, ok: true, detail });
    console.log(`✅ ${name}${detail ? ' — ' + detail : ''}`);
  } catch (e) {
    results.push({ name, ok: false });
    console.log(`❌ ${name}\n   ${String(e.message).split('\n').join('\n   ')}`);
  }
}

function run(cmd, args, opts) {
  const r = spawnSync(cmd, args, Object.assign({ cwd: root, encoding: 'utf-8', maxBuffer: 64 * 1024 * 1024 }, opts));
  if (r.status !== 0) {
    const tail = ((r.stdout || '') + (r.stderr || '')).trim().split('\n').filter(l => /❌|Error|error/.test(l)).slice(0, 20).join('\n');
    throw new Error(`${cmd} ${args.join(' ')} 失敗\n${tail}`);
  }
  return r.stdout;
}

// ── 1. 結構檢查 ──
step('模組清單一致', () => {
  const files = fs.readdirSync(path.join(root, 'modules')).filter(f => f.endsWith('.js')).sort();
  const html = fs.readFileSync(path.join(root, 'index.html'), 'utf-8');
  const tags = [...html.matchAll(/<script src="modules\/([\w-]+\.js)"><\/script>/g)].map(m => m[1]);
  const orch = fs.readFileSync(path.join(root, 'modules', 'scan-orchestrator.js'), 'utf-8');
  const nodeList = [...orch.slice(0, orch.indexOf('].forEach')).matchAll(/'([\w-]+)'/g)].map(m => m[1] + '.js');

  const problems = [];
  const missingTag = files.filter(f => !tags.includes(f));
  if (missingTag.length) problems.push('index.html 沒有載入: ' + missingTag.join(', '));
  const missingNode = files.filter(f => f !== 'scan-orchestrator.js' && !nodeList.includes(f));
  if (missingNode.length) problems.push('scan-orchestrator.js 的 Node 清單缺少: ' + missingNode.join(', '));
  if (tags[tags.length - 1] !== 'scan-orchestrator.js') problems.push('scan-orchestrator.js 必須是最後載入的模組');
  const appIdx = html.indexOf('<script src="assets/app.js">');
  if (appIdx < html.lastIndexOf('<script src="modules/')) problems.push('assets/app.js 必須在所有模組之後載入');
  if (problems.length) throw new Error(problems.join('\n'));
  return `${files.length} 個模組`;
});

// ── 2. kind 覆蓋 ──
step('每個 kind 都有說明文字', () => {
  const { FINDING_GUIDE, PLAIN_TITLES } = require(path.join(root, 'modules', 'finding-renderer'));
  const { VALID_KINDS } = require(path.join(root, 'eval', 'case-loader'));
  const kinds = new Set();
  fs.readdirSync(path.join(root, 'modules')).filter(f => f.endsWith('.js') && f !== 'finding-renderer.js').forEach(f => {
    const src = fs.readFileSync(path.join(root, 'modules', f), 'utf-8');
    for (const m of src.matchAll(/\bkind:\s*'([a-z_]+)'/g)) kinds.add(m[1]);
  });
  const valid = new Set(VALID_KINDS);
  const noGuide = [...kinds].filter(k => !FINDING_GUIDE[k]);
  const noTitle = [...kinds].filter(k => !PLAIN_TITLES[k]);
  const notValid = [...kinds].filter(k => !valid.has(k));
  const problems = [];
  if (noGuide.length) problems.push('finding-renderer.js 的 FINDING_GUIDE 缺少: ' + noGuide.join(', '));
  if (noTitle.length) problems.push('finding-renderer.js 的 PLAIN_TITLES(白話標題)缺少: ' + noTitle.join(', '));
  if (notValid.length) problems.push('eval/case-loader.js 的 VALID_KINDS 缺少: ' + notValid.join(', '));
  if (problems.length) throw new Error(problems.join('\n'));
  return `${kinds.size} 種 kind`;
});

// ── 3. 規則回歸 ──
step('規則回歸測試(正則版)', () => { run('node', ['run_rule_regression.js'], { cwd: path.join(root, 'eval') }); });
step('規則回歸測試(AST 版)', () => {
  run('node', ['-e', "require('./load-ast');require('./run_rule_regression.js');"], { cwd: path.join(root, 'eval') });
});

// ── 4. 行為快照 ──
step(update ? '更新行為快照' : '行為快照比對', () => {
  const snapPath = path.join(root, 'eval', 'findings-snapshot.json');
  const current = {
    regex: JSON.parse(run('node', ['scripts/snapshot.js', 'regex'])),
    ast: JSON.parse(run('node', ['scripts/snapshot.js', 'ast']))
  };
  if (update || !fs.existsSync(snapPath)) {
    fs.writeFileSync(snapPath, JSON.stringify(current, null, 1) + '\n');
    return `已寫入 eval/findings-snapshot.json(${Object.keys(current.regex).length} 個樣本)`;
  }
  const saved = JSON.parse(fs.readFileSync(snapPath, 'utf-8'));
  const diffs = [];
  ['regex', 'ast'].forEach(mode => {
    const keys = new Set([...Object.keys(saved[mode] || {}), ...Object.keys(current[mode])]);
    keys.forEach(k => {
      const a = JSON.stringify((saved[mode] || {})[k] || null);
      const b = JSON.stringify(current[mode][k] || null);
      if (a !== b) diffs.push(`[${mode}] ${k}\n     之前: ${a}\n     現在: ${b}`);
    });
  });
  if (diffs.length) {
    throw new Error(`${diffs.length} 個樣本的結果改變了(若是刻意的,執行 npm run verify -- --update):\n` + diffs.slice(0, 30).join('\n'));
  }
  return `${Object.keys(current.regex).length} 個樣本 × 2 種模式無變化`;
});

// ── 4b. 報告安全 ──
step('匯出報告不含金鑰原文與原始碼', () => {
  const out = run('node', ['scripts/check-report.js']).trim();
  return `${out} 份報告檢查通過`;
});

// ── 4b-2. 整專案自我掃描 ──
step('掃描本專案自己:「需要處理」必須是 0', () => {
  const out = JSON.parse(run('node', ['scripts/self-scan.js']).trim());
  return `${out.files} 個檔案 → 需要處理 ${out.tier1}、請你確認 ${out.tier2}、參考 ${out.tier3}`;
});

// ── 4c. GitHub 網址解析與檔案篩選 ──
step('GitHub 匯入的網址解析與檔案篩選', () => {
  const { parseGitHubUrl, selectGitHubFiles } = require(path.join(root, 'assets', 'github-import'));
  const cases = [
    ['https://github.com/a/b', { owner: 'a', repo: 'b', ref: null, path: '', singleFile: false }],
    ['github.com/a/b.git', { owner: 'a', repo: 'b', ref: null, path: '', singleFile: false }],
    ['a/b', { owner: 'a', repo: 'b', ref: null, path: '', singleFile: false }],
    ['https://github.com/a/b/tree/dev/src/api', { owner: 'a', repo: 'b', ref: 'dev', path: 'src/api', singleFile: false }],
    ['https://github.com/a/b/blob/main/src/x.ts', { owner: 'a', repo: 'b', ref: 'main', path: 'src/x.ts', singleFile: true }],
    ['https://gitlab.com/a/b', null],
    ['https://github.com/a', null],
    ['', null]
  ];
  const problems = [];
  cases.forEach(([input, want]) => {
    const got = parseGitHubUrl(input);
    if (JSON.stringify(got) !== JSON.stringify(want)) problems.push(`parseGitHubUrl(${JSON.stringify(input)}) = ${JSON.stringify(got)}`);
  });
  const tree = [
    'src/api/orders.ts', 'src/App.tsx', '.env', '.env.example', 'firestore.rules', 'vercel.json',
    'node_modules/x/index.js', 'dist/app.js', 'public/app.min.js', 'src/types.d.ts', 'package-lock.json', 'README.md', 'logo.png'
  ].map(p => ({ path: p, type: 'blob', size: 100 }));
  const picked = selectGitHubFiles(tree, '').files.map(f => f.path).sort().join(',');
  const want = ['.env', 'firestore.rules', 'src/App.tsx', 'src/api/orders.ts', 'vercel.json'].sort().join(',');
  if (picked !== want) problems.push(`selectGitHubFiles 結果 ${picked},預期 ${want}`);
  const sub = selectGitHubFiles(tree, 'src/api').files.map(f => f.path).join(',');
  if (sub !== 'src/api/orders.ts') problems.push(`子資料夾篩選結果 ${sub}`);
  if (problems.length) throw new Error(problems.join('\n'));
  return `${cases.length} 個網址、2 組篩選`;
});

// ── 5. 單檔版同步 ──
step('單檔版同步', () => { run('node', ['scripts/build-single.js', '--check']); });

// ── 6. 畫面冒煙測試(選用) ──
let hasPlaywright = true;
try { require.resolve('playwright'); } catch (e) { hasPlaywright = false; }
if (hasPlaywright) {
  step('畫面冒煙測試', () => run('node', ['scripts/ui-smoke.js']).trim().split('\n').pop());
} else {
  console.log('⏭️  畫面冒煙測試 — 略過(未安裝 playwright;需要時 npm i -D playwright 後再執行)');
}

const failed = results.filter(r => !r.ok).length;
console.log();
console.log(failed ? `❌ ${failed} 項未通過` : '✅ 全部通過');
process.exitCode = failed ? 1 : 0;
