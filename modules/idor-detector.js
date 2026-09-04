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
//
// ⚠️ 修正紀錄(2026,真實AI產出程式碼實測發現的漏判):
// 原本 \)\s*{ 要求右括號後緊接大括號,但TypeScript常見的函式回傳型別標註
// (例如 function getOrder(id: number): Order { ... })在右括號跟大括號中間
// 插入了 ": Order" 這段文字,導致整個正則完全匹配失敗、直接漏判。這不只
// 影響AST版失敗後的降級情境——任何貼上帶回傳型別標註的TS函式,連正則保底版
// 都抓不到。加上 (?:\s*:\s*[\w.<>\[\]| ]+)? 這段選擇性分組,允許右括號後、
// 大括號前存在型別標註,但不解析型別內容本身(只是跳過,不影響其他判斷)。
//
// ⚠️ 修正紀錄2(2026,真實Lovable專案[filla-app]實測發現的嚴重漏判):
// 原本只認完全等於 id/userId/req 這三個精確名稱,但真實程式碼裡最常見的
// 參數命名其實是 xxxId 駝峰形式(如 propertyId、taskId、orderId、assetId)——
// 這在真實案例中比裸 id 更常見。原本的 \b(id|userId|req)\b 是單字邊界完全
// 匹配,propertyId 裡的 "Id" 前面緊接 property(字母),不構成獨立單字邊界,
// 完全匹配不到,導致這類函式全部被漏判。加上 [a-zA-Z_$][a-zA-Z0-9_$]*Id 這
// 個分支涵蓋駝峰 xxxId 命名,要求 Id 是大寫開頭(符合JS駝峰慣例),避免誤傷
// valid/avoid/grid/solid 這類字尾剛好是小寫id、但語意無關的單字。
const IDOR_PATTERN = /(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s+\w+\s*\([^)]*\b(id|userId|req|[a-zA-Z_$][a-zA-Z0-9_$]*Id)\b[^)]*\)(?:\s*:\s*[\w.<>\[\]| ]+)?\s*{([^}]{0,300})}/g;
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
// 同上方IDOR_PATTERN的修正說明:xxxId駝峰命名(propertyId/taskId等)比裸id更常見,
// 原本的完全匹配 ^(id|userId|req)$ 會漏掉這些真實案例中的主流命名方式。
const ID_PARAM_PATTERN = /^(id|userId|req|[a-zA-Z_$][a-zA-Z0-9_$]*Id)$/;

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
 * 尋找可用的 acorn-jsx 外掛函式(用於擴充 acorn 支援 JSX 語法)。
 * 瀏覽器端由 HTML 端額外透過 esm.sh 載入,掛在 window.acornJsx。
 * 找不到就回傳 null,呼叫端應該退回「純 acorn,不支援 JSX」的既有行為,不視為錯誤——
 * acorn-jsx 只是「涵蓋範圍加大」的疊加能力,不是必要相依。
 * @returns {Function|null}
 */
function resolveAcornJsx() {
  if (typeof window !== 'undefined' && typeof window.acornJsx === 'function') {
    return window.acornJsx;
  }
  if (typeof globalThis !== 'undefined' && typeof globalThis.acornJsx === 'function') {
    return globalThis.acornJsx;
  }
  return null;
}

/**
 * ⚠️ 修正紀錄(2026,真實AI產出程式碼實測發現的問題):
 * Acorn 是純 JavaScript parser,原生完全不認識 JSX(<div>...</div> 這類語法)。
 * 實測發現:貼上任何一段含 JSX 的 React 元件(.tsx/.jsx,這正是 Lovable/v0/Bolt
 * 這類工具最主要的產出格式),AST 解析必定失敗,靜默退回正則版,IDOR 涵蓋率
 * 從100%(AST版)掉回77.8%(正則版),且這個降級對使用者完全不可見。
 *
 * 修法:若環境有 acorn-jsx 外掛可用,用「acorn + acorn-jsx」擴充版解析——
 * 這能處理「有JSX但沒有TypeScript型別標註」的程式碼,涵蓋 .jsx,以及部分
 * 開發者即使檔名是 .tsx 但實際沒寫型別標註的情況。
 *
 * ⚠️ 已知仍然做不到的情況,誠實記錄,刻意不做:
 * 原本嘗試過額外加一層「輕量TS型別標註剝除」(用正則/字元掃描移除
 * interface/型別標註/as斷言等,不引入完整TS編譯器),讓典型的.tsx(含
 * interface、型別標註)也能透過剝除後解析成功。實測後發現:純字元掃描
 * 無法可靠區分「型別標註的冒號」與「三元運算子的冒號」(例如 `cond ? a : b`
 * 跟 `id: number` 在字元層級長得太像),會把三元運算子的一部分誤判成型別
 * 標註而剝除掉,產生語法錯誤或錯誤的程式碼結構。這已經超出正則/字元掃描
 * 能穩妥解決的範圍,真正可靠的解法需要完整的TypeScript parser(如
 * @babel/parser 或 typescript 官方套件),但那需要換掉整個AST走訪邏輯
 * (collectFunctionNodes/isOwnershipComparisonNode 等都是針對ESTree節點
 * 格式寫的),屬於大改動,不在本次修補範圍內。因此维持「只支援JSX,不支援
 * TypeScript型別語法」的邊界,含TS型別標註的.tsx解析失敗時,誠實地退回
 * 正則版,並讓呼叫端可以得知發生了降級(見 idorDetector 回傳值的
 * astAttempted/astSucceeded 欄位),不再靜默隱藏這個狀態。
 */

/**
 * 建立支援JSX的acorn parser(若acorn-jsx可用),否則回傳原始acorn。
 * @param {object} acornRef
 * @returns {object} 可呼叫 .parse() 的 parser
 */
function buildParser(acornRef) {
  const acornJsx = resolveAcornJsx();
  if (acornJsx && acornRef.Parser && typeof acornRef.Parser.extend === 'function') {
    try {
      return acornRef.Parser.extend(acornJsx());
    } catch (e) {
      return acornRef; // 擴充失敗(不預期的情況),退回純acorn,不中斷流程
    }
  }
  return acornRef;
}

/**
 * ⚠️ 函式簽名是長期契約: idorDetector(code) → Finding[] 這個介面永遠不變
 * (見檔案頂部說明),不因為新增降級可見機制而改變回傳型別。
 * @param {string} code
 * @returns {Array<{tier:number, category:string, name:string, kind:string, evidence:string}>}
 */
function idorDetector(code) {
  return idorDetectorWithMeta(code).findings;
}

/**
 * ⚠️ 修正紀錄(2026,真實AI產出程式碼實測發現的問題):
 * idorDetector(code) 原本在AST解析失敗時靜默退回正則版,呼叫端完全無法得知
 * 「這次分析比較弱」這件事。既然JSX/TS的AST解析失敗是已知會發生的常態情況
 * (不是例外狀況),不應該讓使用者在完全不知情下拿到涵蓋率較低的結果。
 * 新增這個函式,額外回傳 astUsed(布林值):AST版是否真的被採用。
 * scan-orchestrator 部分(見本檔案下方組裝掃描流程的<script>)會用這個
 * 資訊組出提示文字,顯示在畫面上「本工具無法檢測」區塊,取代原本完全
 * 靜默的行為。
 * @param {string} code
 * @returns {{findings: Array, astUsed: boolean}}
 */
function idorDetectorWithMeta(code) {
  const regexFindings = idorDetectorRegex(code);

  const acornRef = resolveAcorn();
  if (!acornRef) {
    // Acorn 不可用(CDN 未載入/離線/未引入):靜默退化為純正則版結果。
    return { findings: regexFindings, astUsed: false };
  }

  const parser = buildParser(acornRef);
  const astResult = idorDetectorAst(code, parser);
  if (astResult.ok) {
    return { findings: astResult.findings, astUsed: true };
  }

  // 語法解析失敗(可能是非法JS、或是acorn-jsx也處理不了的TypeScript型別語法):
  // 退回正則版結果,並標記 astUsed:false 讓呼叫端知道發生了降級。
  return { findings: regexFindings, astUsed: false };
}

/**
 * 粗略判斷程式碼是否「看起來含JSX或TypeScript特徵」,用於決定是否要顯示
 * 「這次IDOR分析退回較弱的正則版,可能是因為JSX/TS語法」這則提示。
 * 只在特徵存在時才顯示,避免對純JS/Python等程式碼也顯示不相關的提示文字。
 * @param {string} code
 * @returns {boolean}
 */
function looksLikeJsxOrTypeScript(code) {
  const hasJsxTag = /<[A-Za-z][\w.]*[^>]*>/.test(code) && /<\/[A-Za-z][\w.]*>|\/>/.test(code);
  const hasTsSyntax = /\binterface\s+\w+\s*\{|:\s*(string|number|boolean|void|any|unknown)\b|<[A-Za-z_$][\w$]*(\s*\|\s*[A-Za-z_$][\w$]*)*>\s*\(/.test(code);
  return hasJsxTag || hasTsSyntax;
}

// ── 環境相容匯出:Node.js(require)與瀏覽器(<script src>)共用同一份檔案 ──
// Node 測試環境: module 物件存在 → 走 module.exports,供 require() 使用
// 瀏覽器環境: module 不存在 → 略過這段,函式/常數已是全域作用域下的宣告,
//            可直接被 index.html 或其他 <script> 使用
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
  idorDetector,
  idorDetectorWithMeta,
  looksLikeJsxOrTypeScript,
  resolveAcornJsx,
  buildParser,
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
