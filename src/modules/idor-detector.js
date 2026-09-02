/**
 * M6 — idor-detector
 * 詳細規格見 docs/modules/MODULE_06_idor-detector.md
 *
 * 職責:偵測疑似缺少擁有權驗證的函式(Broken Access Control / IDOR)
 * 輸入: code (string)
 * 輸出: Finding[]
 *
 * ⚠️ 函式簽名是長期契約: idorDetector(code) → Finding[] 這個介面永遠不變。
 *
 * ── 架構:正則保底 + AST(Acorn) 疊加分析 ──
 *
 * 1. 正則版一定會跑,任何環境下都能動,不依賴任何外部函式庫,是最終保底結果。
 * 2. 若全域存在 `acorn`(由 HTML 端透過 <script src="...acorn CDN..."> 載入),
 *    額外跑一次 AST 分析,取得比正則更精確的結果:
 *    - AST 能理解真正的程式結構,解決正則版已知限制:
 *      (a) 箭頭函式/函式表達式完全抓不到
 *      (b) 註解或字串裡剛好出現 auth/owner 等字樣,被正則誤判為「已檢查」而放過
 *      (c) AST 版進一步用「擁有權比較運算」取代「關鍵字是否出現」判斷擁有權檢查,
 *          解決「只檢查有沒有登入,卻誤判為已做擁有權檢查」的語意層級問題(詳見
 *          isOwnershipComparisonNode 的說明,這是拿真實案例實測後發現並修正的)
 *    - AST 分析結果會取代正則版的結果(而非疊加兩份重複的 Finding)
 * 3. 若 acorn 不存在(CDN 載入失敗、離線、或呼叫端本來就沒引入),
 *    靜默退化為純正則版,不拋出例外、不影響其他功能。此時仍套用「關鍵字出現
 *    即判定已檢查」這個較弱的判斷方式,誤判率高於 AST 版,這是正則能力的天花板。
 * 4. 語言限制:AST 分析仰賴 Acorn 是 JavaScript/TypeScript 的 parser,
 *    程式碼若不是合法 JS 語法(例如貼上的是 Python),acorn.parse 會拋出例外,
 *    此時同樣靜默退化為正則版結果,不當成錯誤處理、不中斷整個掃描。
 */

// ── 正則版(保底,永遠可用) ──
// 支援選擇性的 export/export default/async 前綴,涵蓋常見的 ES Module 寫法
// (例如 export async function getOrder(req,res){...}),這是從真實案例實測中
// 發現的漏判修正:原本只認 function xxx(){},AI生成的Express路由handler
// 常見寫成 export async function 這種形式,原版正則完全抓不到。
const IDOR_PATTERN = /(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s+\w+\s*\([^)]*\b(id|userId|req)\b[^)]*\)\s*{([^}]{0,300})}/g;
const DB_CALL_PATTERN = /\.(find|get|query|select|delete|update)\s*\(/i;
const AUTH_CHECK_PATTERN = /\b(owner|user\.id|session|auth|permission|role)\b/i;

function idorDetectorRegex(code) {
  const findings = [];
  const re = new RegExp(IDOR_PATTERN.source, IDOR_PATTERN.flags);
  let m;

  while ((m = re.exec(code)) !== null) {
    const body = m[2];
    const hasDbCall = DB_CALL_PATTERN.test(body);
    const hasAuthCheck = AUTH_CHECK_PATTERN.test(body);
    if (hasDbCall && !hasAuthCheck) {
      findings.push({
        tier: 2,
        category: '建議人工複查',
        name: '疑似缺少擁有權驗證',
        kind: 'possible_idor',
        evidence: '此函式用參數查詢資料，但未偵測到權限比對邏輯（正則比對）'
      });
    }
  }

  return findings;
}
// 已知限制(正則版,誠實記錄):AUTH_CHECK_PATTERN 只判斷「有沒有出現」owner/session/auth
// 等關鍵字,不判斷「是不是真的在做擁有權比較」。例如 if(!req.session.userId) 只是
// 檢查有沒有登入,不是檢查資料擁有權,但因為出現了 session 字樣,會被正則版誤判為
// 「已檢查」而不標記。這個語意層級的問題正則能力做不到,AST 版已改用「是否存在
// 擁有權比較運算」的判斷方式修正此問題,見下方 isOwnershipComparisonNode。

// ── AST 版(疊加分析,需要 acorn) ──

const DB_METHOD_NAMES = new Set(['find', 'get', 'query', 'select', 'delete', 'update', 'findOne', 'findById']);
const AUTH_KEYWORDS = new Set(['owner', 'session', 'auth', 'permission', 'role']);
const ID_PARAM_PATTERN = /^(id|userId|req)$/;

/**
 * 遞迴走訪整棵 AST,收集所有函式節點
 * 涵蓋三種函式型態: FunctionDeclaration(具名函式)、FunctionExpression(函式表達式)、
 * ArrowFunctionExpression(箭頭函式) — 這是相對於正則版最大的涵蓋範圍提升。
 */
function collectFunctionNodes(node, results) {
  if (!node || typeof node !== 'object') return;

  if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression') {
    results.push(node);
  }

  for (const key in node) {
    if (key === 'start' || key === 'end' || key === 'loc' || key === 'range' || key === 'parent') continue;
    const val = node[key];
    if (Array.isArray(val)) {
      val.forEach(item => collectFunctionNodes(item, results));
    } else if (val && typeof val === 'object' && val.type) {
      collectFunctionNodes(val, results);
    }
  }
}

/** 在子樹裡找是否存在符合條件的節點 */
function subtreeContains(node, predicate) {
  if (!node || typeof node !== 'object') return false;
  if (predicate(node)) return true;
  for (const key in node) {
    if (key === 'start' || key === 'end' || key === 'loc' || key === 'range' || key === 'parent') continue;
    const val = node[key];
    if (Array.isArray(val)) {
      if (val.some(item => subtreeContains(item, predicate))) return true;
    } else if (val && typeof val === 'object' && val.type) {
      if (subtreeContains(val, predicate)) return true;
    }
  }
  return false;
}

/**
 * 從函式節點的資料庫呼叫子樹中,取出被呼叫的物件與方法名稱(例如 db.find → {object:'db', method:'find'})
 * 用於視覺化展示時顯示「實際呼叫了什麼」,拿不到就回傳 null,由呼叫端 fallback 成抽象示意。
 */
function extractDbCallInfo(bodyNode) {
  let result = null;
  function walk(node) {
    if (result || !node || typeof node !== 'object') return;
    if (isDbCallNode(node)) {
      result = { object: node.callee.object.name || null, method: node.callee.property.name };
      return;
    }
    for (const key in node) {
      if (['start', 'end', 'loc', 'range', 'parent'].includes(key)) continue;
      const val = node[key];
      if (Array.isArray(val)) val.forEach(walk);
      else if (val && typeof val === 'object' && val.type) walk(val);
    }
  }
  walk(bodyNode);
  return result;
}

/**
 * 從函式參數節點取出「用於查詢的識別碼參數名」,優先取 id/userId 這類語意明確的參數,
 * 找不到就退回第一個參數名,都拿不到就回傳 null。
 */
function extractIdParamName(params) {
  const named = params.filter(p => p.type === 'Identifier');
  const semanticMatch = named.find(p => /^(id|userId)$/.test(p.name));
  if (semanticMatch) return semanticMatch.name;
  return named.length > 0 ? named[0].name : null;
}

/** 判斷是否為「資料庫呼叫」節點: obj.find(...) 這類 CallExpression */
function isDbCallNode(node) {
  return node.type === 'CallExpression'
    && node.callee
    && node.callee.type === 'MemberExpression'
    && node.callee.property
    && node.callee.property.type === 'Identifier'
    && DB_METHOD_NAMES.has(node.callee.property.name);
}

/**
 * 判斷是否為「擁有權比較」節點:
 * ⚠️ 修正紀錄(來自真實案例實測發現的問題):原本的 isAuthRelatedNode 只判斷
 * 「有沒有出現」owner/session/auth 等權限相關字樣,但這樣會把「只檢查有沒有登入」
 * (例如 if(!req.session.userId){...},只確認使用者存在,不比較資料擁有者)
 * 誤判為「已做擁有權檢查」而放過,這正是 IDOR 漏洞最典型也最危險的樣式——
 * 有登入檢查、卻沒有擁有權檢查。
 *
 * 新邏輯改為:判斷子樹中是否存在「比較運算(===/!==/==/!=),且至少一邊牽涉
 * 權限/擁有者相關的識別字或屬性存取」的節點。真正的擁有權檢查一定牽涉到
 * 「比較兩個值是否相等」(資料的擁有者 vs 目前使用者),單純的登入檢查
 * 只是「存不存在」的判斷,不涉及比較兩個值,因此能被正確區分。
 */
const COMPARISON_OPERATORS = new Set(['===', '!==', '==', '!=']);

function sideInvolvesAuth(sideNode) {
  if (!sideNode) return false;
  if (sideNode.type === 'Identifier' && AUTH_KEYWORDS.has(sideNode.name)) return true;
  if (sideNode.type === 'MemberExpression' && sideNode.property && sideNode.property.type === 'Identifier') {
    if (AUTH_KEYWORDS.has(sideNode.property.name)) return true;
    if (['user', 'id', 'userId'].includes(sideNode.property.name)) return true;
    // 遞迴檢查物件部分(例如 req.user.id 的 req.user 部分,或 order.owner.id 這類巢狀存取)
    return sideInvolvesAuth(sideNode.object);
  }
  return false;
}

function isOwnershipComparisonNode(node) {
  if (node.type !== 'BinaryExpression' || !COMPARISON_OPERATORS.has(node.operator)) return false;
  return sideInvolvesAuth(node.left) || sideInvolvesAuth(node.right);
}

/**
 * @param {string} code
 * @param {object} acornRef - 呼叫端傳入的 acorn 物件(例如全域的 window.acorn)
 * @returns {{ok: boolean, findings: Array}} ok=false 代表解析失敗(語法錯誤/非JS),呼叫端應退回正則版結果
 */
function idorDetectorAst(code, acornRef) {
  let ast;
  try {
    ast = acornRef.parse(code, { ecmaVersion: 2022, sourceType: 'module', allowReturnOutsideFunction: true });
  } catch (e) {
    return { ok: false, findings: [] };
  }

  const findings = [];
  const fnNodes = [];
  collectFunctionNodes(ast, fnNodes);

  fnNodes.forEach(fnNode => {
    const hasIdParam = fnNode.params.some(p => p.type === 'Identifier' && ID_PARAM_PATTERN.test(p.name));
    if (!hasIdParam) return;

    const hasDbCall = subtreeContains(fnNode.body, isDbCallNode);
    if (!hasDbCall) return;

    const hasAuthCheck = subtreeContains(fnNode.body, isOwnershipComparisonNode);
    if (hasAuthCheck) return;

    // 收集視覺化展示用的真實變數資訊(選用欄位,抓不到就是 null,由畫面層 fallback 成抽象示意)
    const visualData = {
      functionName: (fnNode.id && fnNode.id.name) || null,
      idParamName: extractIdParamName(fnNode.params),
      dbCall: extractDbCallInfo(fnNode.body)
    };

    findings.push({
      tier: 2,
      category: '建議人工複查',
      name: '疑似缺少擁有權驗證',
      kind: 'possible_idor',
      evidence: '此函式用參數查詢資料，但未偵測到權限比對邏輯（語法樹分析，涵蓋箭頭函式與函式表達式）',
      visualData
    });
  });

  return { ok: true, findings };
}

/**
 * 尋找目前執行環境中可用的 acorn 物件。
 * 瀏覽器端由 HTML 透過 <script src="...cdn.../acorn.min.js"> 載入後會掛在 window.acorn。
 * 若找不到(CDN 載入失敗、離線、或未引入),回傳 null,呼叫端應靜默退化為正則版。
 */
function resolveAcorn() {
  if (typeof window !== 'undefined' && window.acorn && typeof window.acorn.parse === 'function') {
    return window.acorn;
  }
  if (typeof globalThis !== 'undefined' && globalThis.acorn && typeof globalThis.acorn.parse === 'function') {
    return globalThis.acorn;
  }
  return null;
}

/**
 * @param {string} code
 * @returns {Array<{tier:number, category:string, name:string, kind:string, evidence:string}>}
 */
function idorDetector(code) {
  const regexFindings = idorDetectorRegex(code);

  const acornRef = resolveAcorn();
  if (!acornRef) {
    // Acorn 不可用(CDN 未載入/離線/未引入):靜默退化為純正則版結果
    return regexFindings;
  }

  const astResult = idorDetectorAst(code, acornRef);
  if (!astResult.ok) {
    // 語法解析失敗(通常代表這不是合法 JS,例如貼上的是 Python):同樣退回正則版結果
    return regexFindings;
  }

  // AST 分析成功:用 AST 的結果取代正則版結果(更精確,涵蓋範圍更廣),不疊加重複回報
  return astResult.findings;
}

// ── 環境相容匯出:Node.js(require)與瀏覽器(<script src>)共用同一份檔案 ──
// Node 測試環境: module 物件存在 → 走 module.exports,供 require() 使用
// 瀏覽器環境: module 不存在 → 略過這段,函式/常數已是全域作用域下的宣告,
//            可直接被 index.html 或其他 <script> 使用
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
  idorDetector,
  idorDetectorRegex,
  idorDetectorAst,
  resolveAcorn,
  extractDbCallInfo,
  extractIdParamName,
  IDOR_PATTERN,
  DB_CALL_PATTERN,
  AUTH_CHECK_PATTERN,
  DB_METHOD_NAMES,
  AUTH_KEYWORDS
};
}
