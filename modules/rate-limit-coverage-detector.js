/**
 * M12 — rate-limit-coverage-detector
 * 詳細規格見 docs/modules/MODULE_12_rate-limit-coverage-detector.md
 *
 * 職責:偵測「程式碼裡定義了多條 API 路由,但速率限制規則清單沒有同步涵蓋
 *       到所有路由」的模式——新增路由時最容易忘記同步更新的手動維護清單類問題
 * 輸入: code (string) — 單檔案輸入,不需要多檔案(跟 M11 不同)
 * 輸出: Finding[]
 *
 * 這是純函式,不依賴任何其他模組,可完全獨立開發與測試。
 *
 * ⚠️ 這個模組會產生 tier 3(資訊提示)Finding,是本專案除 M1-M11 之外
 * 第一個使用 tier 3 的模組。tier 3 的呈現邏輯已在 M8(finding-renderer)
 * 完成(見該模組內的 tier3 相關程式碼),實作 M12 前已確認過 M8 能正確承接。
 *
 * ⚠️ 本模組的核心判斷邏輯(catch-all 偵測、嚴重度分級)已拿真實的
 * Cloudflare Workers 專案(yoya9933/chess-online)的 worker/index.js 與
 * worker/security.js 實測驗證過,詳見規格文件「核心邏輯」段落與
 * eval/samples.js 裡對應的真實案例。
 */

// 路由定義樣式:只認 url.pathname === '/api/xxx' 這種直接字面比對的宣告方式。
// 已知限制:不涵蓋 Express 風格 app.get(path,...)、路由表陣列、動態路徑(帶參數),
// 這是目前已驗證過確實存在於真實案例(Cloudflare Workers 生態)的樣式,
// 不預先涵蓋所有框架寫法,之後有其他真實案例再擴充(比照 M9 的漸進式擴充做法)。
const ROUTE_DEFINITION_PATTERN = /pathname\s*===\s*['"`](\/[a-zA-Z0-9\/_-]*)['"`]/g;

// 判斷「這是不是速率限制函式」:函式名稱包含 limit(不分大小寫)
const RATE_LIMIT_FUNCTION_HINT = /function\s+(\w*[Ll]imit\w*)\s*\(/g;

// catch-all 偵測:函式體結尾若存在不帶任何 pathname/url 條件限定、單獨一行的
// return 陳述式,視為有預設值兜底。
const CATCH_ALL_PATTERN = /\n\s*return\s+[\w.]+\s*;?\s*\}\s*$/;

/**
 * 用大括號配對找出函式體邊界(從第一個 { 開始,配對到對應的 })。
 * 不用固定字元數視窗——M9 曾經因為固定字元數視窗導致截斷風險,
 * 速率限制函式通常有好幾個 if 分支,這裡必須抓到完整函式體。
 * @param {string} code
 * @param {number} funcStartIndex - 函式宣告開始的字元索引
 * @returns {string|null} 函式體內容(含大括號),找不到配對回傳 null
 */
function extractFunctionBody(code, funcStartIndex) {
  const openBraceIdx = code.indexOf('{', funcStartIndex);
  if (openBraceIdx === -1) return null;
  let depth = 0;
  for (let i = openBraceIdx; i < code.length; i++) {
    if (code[i] === '{') depth++;
    else if (code[i] === '}') {
      depth--;
      if (depth === 0) return code.slice(openBraceIdx, i + 1);
    }
  }
  return null; // 大括號沒有正確配對完(程式碼片段不完整),放棄分析
}

/**
 * 從程式碼裡取出所有符合 ROUTE_DEFINITION_PATTERN 的路徑,去重複。
 * @param {string} text
 * @returns {string[]}
 */
function extractRoutePaths(text) {
  const re = new RegExp(ROUTE_DEFINITION_PATTERN.source, ROUTE_DEFINITION_PATTERN.flags);
  const matches = [...text.matchAll(re)];
  return [...new Set(matches.map(m => m[1]))];
}

/**
 * @param {string} code
 * @returns {Array<{tier:number, category:string, name:string, kind:string, evidence:string}>}
 */
function rateLimitCoverageDetector(code) {
  const findings = [];
  if (!code) return findings;

  // 第一步:找出整份程式碼裡定義過的全部路由(不限定在特定函式內)
  const allRoutes = extractRoutePaths(code);
  if (allRoutes.length === 0) return findings;

  // 第二步:找出「看起來像速率限制函式」的函式,並抽出其函式體內涵蓋的路由。
  // 邊界案例:找不到任何速率限制函式時,直接回傳空陣列——不能因為「找不到限速邏輯」
  // 就把所有路由判定為未涵蓋,那是另一個問題(根本沒有限速機制),不是本模組的職責。
  // 本模組假設「已經有限速機制、但涵蓋可能不全」這個前提成立才開始比對。
  const hintRe = new RegExp(RATE_LIMIT_FUNCTION_HINT.source, RATE_LIMIT_FUNCTION_HINT.flags);
  let hintMatch;
  let coveredRoutes = new Set();
  let hasCatchAll = false;
  let foundRateLimitFunction = false;

  while ((hintMatch = hintRe.exec(code)) !== null) {
    foundRateLimitFunction = true;
    const body = extractFunctionBody(code, hintMatch.index);
    if (!body) continue;

    extractRoutePaths(body).forEach(r => coveredRoutes.add(r));
    if (CATCH_ALL_PATTERN.test(body)) hasCatchAll = true;
  }

  if (!foundRateLimitFunction) return findings;

  // 第三步:差集 — 全部路由扣掉被具名分支涵蓋的路由
  const uncoveredRoutes = allRoutes.filter(r => !coveredRoutes.has(r));
  if (uncoveredRoutes.length === 0) return findings;

  // 第四步:依有沒有 catch-all,分成 tier2(完全未涵蓋)或 tier3(套用預設值)
  uncoveredRoutes.forEach(route => {
    if (hasCatchAll) {
      findings.push({
        tier: 3,
        category: '資訊提示',
        name: '路由套用預設速率限制值，未特別調整',
        kind: 'route_uses_default_rate_limit',
        evidence: `路由「${route}」未在速率限制函式中找到專屬的條件分支，目前套用函式的預設值（catch-all）。如果這條路由的呼叫成本或敏感程度與其他路由不同，建議確認目前的預設值是否合適，而非必然的錯誤。`
      });
    } else {
      findings.push({
        tier: 2,
        category: '建議人工複查',
        name: '路由未被速率限制規則涵蓋',
        kind: 'route_missing_rate_limit',
        evidence: `路由「${route}」在程式碼中有定義，但速率限制函式中找不到任何條件分支處理這個路徑，且函式也沒有預設值兜底，此路由可能完全不受速率限制保護。`
      });
    }
  });

  return findings;
}

// ── 環境相容匯出:Node.js(require)與瀏覽器(<script src>)共用同一份檔案 ──
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    rateLimitCoverageDetector,
    extractFunctionBody,
    extractRoutePaths,
    ROUTE_DEFINITION_PATTERN,
    RATE_LIMIT_FUNCTION_HINT,
    CATCH_ALL_PATTERN
  };
}
