/**
 * 測試: M6 idor-detector
 * 規格見 docs/modules/MODULE_06_idor-detector.md
 * 執行方式: node test/idor-detector.test.js
 *
 * ⚠️ 函式簽名 idorDetector(code) → Finding[] 是長期契約,不因內部實作改變而變。
 *
 * 這份測試涵蓋三層:
 * 1. 正則版本身(idorDetectorRegex) — 保底邏輯,任何環境都要正確
 * 2. AST 版本身(idorDetectorAst) — 需要傳入 acorn 物件,驗證比正則版涵蓋更廣、更精確
 * 3. 對外介面(idorDetector) — 驗證「有 acorn 用 AST / 沒 acorn 退回正則 / 解析失敗退回正則」三種情境
 */

const { idorDetector, idorDetectorRegex, idorDetectorAst, resolveAcorn } = require('../src/modules/idor-detector');
const { assertEqual, assertTrue, report } = require('./_test-helpers');

// Node 測試環境用 npm 套件 acorn 模擬瀏覽器端由 CDN 載入後掛在 window.acorn 的物件。
let acornModule = null;
try {
  acornModule = require('acorn');
} catch (e) {
  console.log('[環境提示] 找不到 acorn 套件,AST 相關測試將以「Acorn 不可用」情境驗證退化行為');
}

const results = [];

// ══════════════════════════════════════════
// 第一層: 正則版本身(保底邏輯,任何環境都要正確)
// ══════════════════════════════════════════

results.push(assertTrue(
  '[正則] 無權限檢查的函式應被標記為疑似 IDOR',
  idorDetectorRegex('function getOrder(req, res) { const order = db.find(req.params.id); res.json(order); }')
    .some(f => f.kind === 'possible_idor' && f.tier === 2)
));

results.push(assertEqual(
  '[正則] 含 owner 檢查的函式不應被標記',
  idorDetectorRegex('function getOrder(req, res) { const order = db.find(req.params.id); if (order.owner !== req.user.id) return res.status(403).end(); res.json(order); }').length,
  0
));

results.push((() => {
  const code = `
    function getOrder(req, res) { const order = db.find(req.params.id); res.json(order); }
    function getSafeOrder(req, res) { const order = db.find(req.params.id); if (order.owner !== req.user.id) return; res.json(order); }
  `;
  return assertEqual('[正則] 多個函式中只回報有問題的那個', idorDetectorRegex(code).length, 1);
})());

results.push((() => {
  const r = idorDetectorRegex('const getOrder = (req, res) => { const order = db.find(req.params.id); res.json(order); };');
  return assertEqual('[正則] 已知限制:箭頭函式偵測不到(這是 AST 版存在的理由)', r.length, 0);
})());

results.push((() => {
  // 這是從真實案例實測中發現的漏判修正:export async function 語法涵蓋
  const code = 'export async function getOrder(req, res) { const order = db.find(req.params.id); res.json(order); }';
  const r = idorDetectorRegex(code);
  return assertTrue('[正則] export async function 語法應被正確涵蓋(修正前會漏判)', r.length === 1);
})());

results.push(assertEqual('[正則] 空字串應回傳空陣列', idorDetectorRegex('').length, 0));

// ══════════════════════════════════════════
// 語意修正驗證: 「只檢查登入」不應被誤判為「已做擁有權檢查」(AST版核心修正)
// ══════════════════════════════════════════

if (acornModule) {
  results.push((() => {
    // 這是從真實案例(仿Lovable IDOR事件)實測中發現的問題:只檢查req.session.userId
    // (代表「有沒有登入」)不代表真的檢查了「這筆資料是不是屬於這個使用者」,
    // 修正前的AST版會因為出現session字樣而誤判為安全,這是危險的假陰性。
    const code = 'export async function getProjectData(req, res) { const project = await db.projects.findOne({ id: req.params.projectId }); if (!req.session.userId) { return res.status(401).end(); } res.json(project); }';
    const r = idorDetectorAst(code, acornModule);
    return assertTrue(
      '[AST 語意修正] 只檢查登入(session.userId存在與否)不應被誤判為已做擁有權檢查,應標記為疑似IDOR',
      r.ok && r.findings.length === 1
    );
  })());

  results.push((() => {
    // 對照組:真正的擁有權比較(project.userId === req.session.userId)應正確判定為安全
    const code = 'export async function getProjectData(req, res) { const project = await db.projects.findOne({ id: req.params.projectId }); if (project.userId !== req.session.userId) { return res.status(403).end(); } res.json(project); }';
    const r = idorDetectorAst(code, acornModule);
    return assertEqual(
      '[AST 語意修正對照組] 真正的擁有權比較(project.userId !== session.userId)應正確判定為安全,不誤判',
      r.ok ? r.findings.length : -1,
      0
    );
  })());

  results.push((() => {
    // 只檢查 req.user 存在(登入檢查),同樣不該被當作擁有權檢查
    const code = 'function getOrder(req, res) { if (!req.user) { return; } const order = db.find(req.params.id); res.json(order); }';
    const r = idorDetectorAst(code, acornModule);
    return assertTrue(
      '[AST 語意修正] 只檢查req.user是否存在(登入檢查)不應被誤判為擁有權檢查',
      r.ok && r.findings.length === 1
    );
  })());
}

// ══════════════════════════════════════════
// 第二層: AST 版本身(需要 acorn,驗證精確度提升)
// ══════════════════════════════════════════

if (acornModule) {
  results.push((() => {
    const r = idorDetectorAst('function getOrder(req, res) { const order = db.find(req.params.id); res.json(order); }', acornModule);
    return assertTrue('[AST] 具名函式(正則版本就能抓到的案例)應仍被偵測到', r.ok && r.findings.some(f => f.kind === 'possible_idor'));
  })());

  results.push((() => {
    const r = idorDetectorAst('const getOrder = (req, res) => { const order = db.find(req.params.id); res.json(order); };', acornModule);
    return assertTrue('[AST] 箭頭函式應被偵測到(正則版做不到,AST 版的核心價值)', r.ok && r.findings.length === 1);
  })());

  results.push((() => {
    const r = idorDetectorAst('const getOrder = function(req, res) { const order = db.find(req.params.id); res.json(order); };', acornModule);
    return assertTrue('[AST] function expression 賦值寫法應被偵測到', r.ok && r.findings.length === 1);
  })());

  results.push((() => {
    const code = 'const getOrder = (req, res) => { const order = db.find(req.params.id); if (order.owner !== req.user.id) return; res.json(order); };';
    const r = idorDetectorAst(code, acornModule);
    return assertEqual('[AST] 箭頭函式+有權限檢查不應誤判', r.ok ? r.findings.length : -1, 0);
  })());

  results.push((() => {
    const code = 'function getOrder(req, res) {\n  // auth: todo check later\n  const order = db.find(req.params.id);\n  res.json(order);\n}';
    const regexResult = idorDetectorRegex(code);
    const astResult = idorDetectorAst(code, acornModule);
    return assertTrue(
      '[AST vs 正則] 註解裡的關鍵字不應讓 AST 版誤判為安全(正則版會誤放過,AST 版應正確標記)',
      regexResult.length === 0 && astResult.ok && astResult.findings.length === 1
    );
  })());

  results.push((() => {
    const pythonCode = 'def get_order(id):\n    return db.query(id)';
    let threw = false;
    let r;
    try {
      r = idorDetectorAst(pythonCode, acornModule);
    } catch (e) {
      threw = true;
    }
    return assertTrue('[AST] 非法JS語法(如Python)應回傳ok:false而非拋出例外', !threw && r.ok === false);
  })());

  results.push(assertEqual('[AST] 空字串應回傳空陣列', idorDetectorAst('', acornModule).findings.length, 0));
} else {
  console.log('(跳過 AST 直接測試,環境無 acorn 套件)');
}

// ══════════════════════════════════════════
// 第三層: 對外介面 idorDetector(code) — 三種情境的整合驗證
// ══════════════════════════════════════════

results.push((() => {
  delete globalThis.acorn;
  const code = 'const getOrder = (req, res) => { const order = db.find(req.params.id); res.json(order); };';
  const withoutAcorn = idorDetector(code);
  return assertEqual('[整合] resolveAcorn 找不到時,應靜默退化為正則版(箭頭函式偵測不到)', withoutAcorn.length, 0);
})());

if (acornModule) {
  results.push((() => {
    globalThis.acorn = acornModule;
    const code = 'const getOrder = (req, res) => { const order = db.find(req.params.id); res.json(order); };';
    const withAcorn = idorDetector(code);
    delete globalThis.acorn;
    return assertEqual('[整合] globalThis.acorn 存在時,應改用 AST 版(箭頭函式應被偵測到)', withAcorn.length, 1);
  })());

  results.push((() => {
    globalThis.acorn = acornModule;
    let threw = false;
    let r = [];
    try {
      r = idorDetector('def get_order(id):\n    return db.query(id)');
    } catch (e) {
      threw = true;
    }
    delete globalThis.acorn;
    return assertTrue('[整合] 有 acorn 但輸入非法JS時應優雅退回正則版,不拋例外', !threw);
  })());
}

results.push((() => {
  let threw = false;
  let r;
  try {
    r = resolveAcorn();
  } catch (e) {
    threw = true;
  }
  return assertTrue('[resolveAcorn] 在無 acorn 的環境下應回傳 null 而非拋例外', !threw && r === null);
})());

// ══════════════════════════════════════════
// visualData 欄位驗證(供畫面層視覺化展示使用,選用欄位)
// ══════════════════════════════════════════

if (acornModule) {
  results.push((() => {
    const code = 'export async function getOrder(req, res) { const order = db.find(req.params.id); res.json(order); }';
    const r = idorDetectorAst(code, acornModule);
    const f = r.findings[0];
    return assertTrue(
      '[visualData] AST版應正確萃取函式名/資料庫呼叫資訊',
      f.visualData
      && f.visualData.functionName === 'getOrder'
      && f.visualData.dbCall
      && f.visualData.dbCall.object === 'db'
      && f.visualData.dbCall.method === 'find'
    );
  })());

  results.push((() => {
    // 箭頭函式賦值寫法,函式名應從外層變數宣告取得不到(AST節點本身id為null),
    // 這是誠實的已知限制:箭頭函式賦值給變數時,節點本身沒有名稱資訊,
    // functionName 會是 null,畫面層需要 fallback 處理這種情況。
    const code = 'const getOrder = (req, res) => { const order = db.find(req.params.id); res.json(order); };';
    const r = idorDetectorAst(code, acornModule);
    const f = r.findings[0];
    return assertTrue(
      '[visualData] 箭頭函式賦值寫法,functionName應為null(已知限制,畫面層需fallback)',
      f.visualData && f.visualData.functionName === null && f.visualData.dbCall.method === 'find'
    );
  })());

  results.push((() => {
    const code = 'function getUserProfile(userId, res) { const profile = db.query(userId); res.json(profile); }';
    const r = idorDetectorAst(code, acornModule);
    const f = r.findings[0];
    return assertTrue(
      '[visualData] idParamName應優先取語意明確的id/userId參數',
      f.visualData && f.visualData.idParamName === 'userId'
    );
  })());
}

results.push((() => {
  // 正則版沒有能力解析結構化資訊,不應帶有 visualData 欄位(undefined),
  // 畫面層必須對此情況做 fallback,不能假設每個 Finding 都有 visualData。
  const code = 'function getOrder(req, res) { const order = db.find(req.params.id); res.json(order); }';
  const f = idorDetectorRegex(code)[0];
  return assertTrue('[visualData] 正則版不應帶有visualData欄位(畫面層須自行fallback)', f.visualData === undefined);
})());


report('M6 idor-detector', results);
