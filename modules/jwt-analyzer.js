/**
 * M2 — jwt-analyzer
 * 詳細規格見 docs/modules/MODULE_02_jwt-analyzer.md
 *
 * 職責:偵測 JWT 格式字串,解析 role 欄位決定風險分層
 * 輸入: code (string)
 * 輸出: Finding[]
 *
 * 這是純函式,不依賴任何其他模組,可完全獨立開發與測試。
 * 注意: role=anon 是 tier2(設計上可公開), role=service_role 是 tier1(高風險),
 * 角色未知時保守歸為 tier2、不可略過不報。
 */

const JWT_KEY_PATTERN = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

/**
 * base64url decode,相容瀏覽器(atob)與 Node.js(Buffer)環境
 * @param {string} b64url
 * @returns {string}
 */
function base64UrlDecode(b64url) {
  const padded = b64url.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((b64url.length + 3) % 4);
  if (typeof atob === 'function') {
    return atob(padded);
  }
  return Buffer.from(padded, 'base64').toString('utf-8');
}

/**
 * 解析 JWT 完整 payload,解不出來回傳 null(不猜測,避免誤判)。
 * 之前版本只挑 role 欄位丟掉其他資訊,現在保留完整 payload,
 * 供 M8 視覺化展示使用(例如 ref 專案代碼、iss 發行者),role 判斷邏輯不變。
 * @param {string} jwt
 * @returns {object|null}
 */
function decodeJwtPayload(jwt) {
  try {
    const payloadB64 = jwt.split('.')[1];
    const json = base64UrlDecode(payloadB64);
    return JSON.parse(json);
  } catch (e) {
    return null;
  }
}

/**
 * 解析 JWT payload 裡的 role 欄位,解不出來回傳 null(不猜測,避免誤判)
 * @param {string} jwt
 * @returns {string|null}
 */
function decodeJwtRole(jwt) {
  const payload = decodeJwtPayload(jwt);
  return (payload && payload.role) || null;
}

/**
 * @param {string} code
 * @returns {Array<{tier:number, category:string, name:string, kind:string, evidence:string}>}
 */
function jwtAnalyzer(code) {
  const findings = [];
  const jwtMatches = code.match(JWT_KEY_PATTERN);

  if (jwtMatches) {
    jwtMatches.forEach(jwt => {
      const payload = decodeJwtPayload(jwt);
      const role = (payload && payload.role) || null;

      // 供 M8 視覺化展示使用的選用欄位:projectRef 讓畫面能顯示「這是哪個 Supabase 專案」,
      // 拿不到就是 null,由畫面層 fallback。issuer 目前保留但暫未在畫面上使用。
      const visualData = payload ? {
        projectRef: payload.ref || null,
        issuer: payload.iss || null
      } : null;

      if (role === 'service_role') {
        findings.push({
          tier: 1,
          category: '明文金鑰',
          name: 'Supabase service_role 金鑰（高風險）',
          kind: 'supabase_service_role',
          evidence: maskMatch(jwt) + '　— role=service_role，具備繞過 RLS 的最高權限，絕不應出現在前端程式碼',
          visualData
        });
      } else if (role === 'anon') {
        findings.push({
          tier: 2,
          category: '建議人工複查',
          name: 'Supabase anon 金鑰（設計上可公開，請確認 RLS）',
          kind: 'supabase_anon',
          evidence: maskMatch(jwt) + '　— role=anon，屬 Supabase 設計上允許出現在前端的公開金鑰，但安全性完全仰賴後端 Row Level Security 規則是否正確設定，建議自行確認',
          visualData
        });
      } else {
        findings.push({
          tier: 2,
          category: '建議人工複查',
          name: '疑似 JWT 格式金鑰（角色未知）',
          kind: 'jwt_unknown_role',
          evidence: maskMatch(jwt) + '　— 偵測到 JWT 格式字串，但無法判斷其權限角色，建議人工確認來源與用途'
        });
      }
    });
  }

  return findings;
}

// ── 環境相容匯出:Node.js(require)與瀏覽器(<script src>)共用同一份檔案 ──
// Node 測試環境: module 物件存在 → 走 module.exports,供 require() 使用
// 瀏覽器環境: module 不存在 → 略過這段,函式/常數已是全域作用域下的宣告,
//            可直接被 index.html 或其他 <script> 使用
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { jwtAnalyzer, decodeJwtRole, decodeJwtPayload, base64UrlDecode, JWT_KEY_PATTERN };
}
