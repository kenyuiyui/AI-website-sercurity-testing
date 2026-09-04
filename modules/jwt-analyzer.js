/**
 * M2 — jwt-analyzer
 * 詳細規格見 docs/modules/MODULE_02_jwt-analyzer.md
 *
 * 職責:偵測 JWT 格式字串,解析 role 欄位決定風險分層
 * 輸入: code (string)
 * 輸出: Finding[]
 *
 * ⚠️ 修正紀錄(2026,拆分成獨立檔案後才暴露的問題):
 * 本模組的 evidence 文字組裝依賴 M1(key-detector)的 maskMatch() 遮罩函式。
 * 單檔版把全部模組寫在同一個 <script> 作用域內時,這個依賴不會出錯,但拆成
 * 獨立檔案後,若載入順序不含 key-detector.js,或本檔案被單獨抽出使用,
 * 會在瀏覽器與 Node.js 兩種環境下都直接噴 ReferenceError。
 * 因此不再宣稱「不依賴任何其他模組」,改為明確處理跨模組依賴:
 * 瀏覽器端要求 index.html 必須在 jwt-analyzer.js 之前載入 key-detector.js
 * (demo_split/index.html 的載入順序已符合這個要求);Node.js 環境則直接
 * require key-detector.js 取得 maskMatch。
 * 輸入/輸出介面不變:輸入 code(string),輸出 Finding[]。
 */

const JWT_KEY_PATTERN = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

// ── 環境相容取得 maskMatch(定義於 M1 key-detector.js) ──
// 瀏覽器: key-detector.js 以 <script src> 先載入後,maskMatch 已在全域(window)作用域可用。
// Node.js: module 物件存在,直接 require 同目錄下的 key-detector.js 取得 maskMatch。
var maskMatch;
if (typeof module !== 'undefined' && module.exports) {
  maskMatch = require('./key-detector').maskMatch;
} else if (typeof window !== 'undefined') {
  maskMatch = window.maskMatch;
}

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
