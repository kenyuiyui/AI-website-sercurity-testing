# M2 — jwt-analyzer

## 你的任務
偵測程式碼中出現的 JWT 格式字串（`eyJ...` 開頭），並判讀其中的 `role` 欄位，依角色決定風險分層。這是專案裡分層邏輯最細膩的一個模組，請仔細讀完「為什麼要分層」這段再動手。

**你不需要看過這個專案的任何其他模組。這份文件是你需要的全部背景。**

## 為什麼要分層（重要，決定你的核心邏輯）

Supabase 的金鑰是 JWT 格式，本身不是單一風險等級：

- `role: "anon"` → Supabase 設計上**允許**出現在前端的公開金鑰，安全性交由後端 Row Level Security（RLS）規則負責。這種情況只需要**提醒**使用者確認 RLS 有設定，屬於 tier 2（建議複查），**不是**漏洞。
- `role: "service_role"` → 具備繞過 RLS 的最高權限，絕對不該出現在前端。這屬於 tier 1（高信心度發現）。
- 角色解不出來（格式怪異、非 Supabase 慣例的 JWT）→ 保守處理成 tier 2，附註「角色未知，建議人工確認」，**不要略過不報**。

兩者字面上都是「一串 JWT」，但風險等級天差地遠，這是本模組存在的理由。

## 函式簽名

```js
function jwtAnalyzer(code) {
  // code: string
  // 回傳: Finding[]
}
```

## 核心邏輯

```js
const JWT_KEY_PATTERN = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

function decodeJwtRole(jwt) {
  try {
    const payloadB64 = jwt.split('.')[1];
    const padded = payloadB64.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((payloadB64.length + 3) % 4);
    const json = atob(padded);   // Node 環境用 Buffer.from(padded, 'base64').toString('utf-8') 替代
    const payload = JSON.parse(json);
    return payload.role || null;
  } catch (e) {
    return null;   // 解不出來就不猜測,避免誤判
  }
}
```

**注意環境差異**：`atob` 是瀏覽器 API。若你的測試環境是 Node.js，需要用 `Buffer.from(padded, 'base64').toString('utf-8')` 達成一樣的效果，並確保瀏覽器執行時仍用 `atob`（可用環境判斷或直接維持兩種寫法皆可運作的 polyfill）。

## 依角色產生對應 Finding

| role 值 | tier | kind | name |
|---|---|---|---|
| `service_role` | 1 | `supabase_service_role` | `Supabase service_role 金鑰（高風險）` |
| `anon` | 2 | `supabase_anon` | `Supabase anon 金鑰（設計上可公開，請確認 RLS）` |
| 其他/解不出來 | 2 | `jwt_unknown_role` | `疑似 JWT 格式金鑰（角色未知）` |

evidence 欄位一律用遮罩過的字串（規則同 M1，見 `maskMatch`），並附加角色說明，例如：

```
maskMatch(jwt) + '　— role=service_role，具備繞過 RLS 的最高權限，絕不應出現在前端程式碼'
```

## visualData：供 M8 視覺化展示使用的選用欄位

`service_role` 與 `anon` 兩種 Finding 會額外附加 `visualData`，讓 M8 可以畫出「這組金鑰能做的事」或「安全性取決於什麼」的視覺化展示：

```js
{
  tier: 1, category: '...', name: '...', kind: 'supabase_service_role', evidence: '...',
  visualData: {
    projectRef: 'xyzcompany',  // JWT payload 裡的 ref 欄位(Supabase 專案代碼),沒有就是 null
    issuer: 'supabase'         // JWT payload 裡的 iss 欄位,目前保留但畫面尚未使用
  }
}
```

**這個模組跟 M6（IDOR）不同的地方**：JWT 本身是可解碼的結構化資料（`decodeJwtPayload` 會回傳完整 payload），資料來源穩定，不像 M6 需要處理「AST 走訪抓不抓得到某個節點」的不確定性。因此這裡的 fallback 情境只有一種——**`visualData` 整個不存在**（例如角色判斷不出來，走 `jwt_unknown_role` 分支時故意不附加，因為連角色都不確定，不該硬做視覺化猜測該顯示哪種內容）。`projectRef` 抓不到（payload 沒有 `ref` 欄位）時是 `null`，畫面層要處理這種部分缺失的情況。

`decodeJwtPayload` 是這次新增的函式，取代原本只挑 `role` 欄位的做法，改成保留完整 payload 供後續（不只是視覺化，未來若要用到其他欄位也可以直接取用），`decodeJwtRole` 仍然保留、內部改呼叫 `decodeJwtPayload`，對外行為不變。

## 明確不在你職責範圍內的東西

- 非 JWT 格式的其他金鑰（OpenAI/AWS 等）→ 屬於 M1
- 判斷 JWT 是否真的來自 Supabase（本模組不驗證來源，只解析 payload 裡的 role 欄位）

## 測試要求

1. **service_role 案例**：造一個 payload 含 `{"role":"service_role"}` 的假 JWT，驗證輸出 tier=1、kind='supabase_service_role'
2. **anon 案例**：payload 含 `{"role":"anon"}`，驗證輸出 tier=2、kind='supabase_anon'
3. **角色未知案例**：payload 不含 role 欄位，或整段字串格式像 JWT 但 base64 解不開，驗證輸出 tier=2、kind='jwt_unknown_role'，且**不能拋出例外中斷整個掃描**
4. **無 JWT 案例**：`code` 完全不含 JWT 格式字串，回傳空陣列
5. **evidence 遮罩檢查**：輸出的 evidence 欄位絕不能包含完整的 JWT 明文字串

### 造測試用假 JWT 的方法

```js
function makeFakeJwt(payloadObj) {
  const header = Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT'})).toString('base64url');
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString('base64url');
  return `${header}.${payload}.fakesignature1234567890`;
}
// makeFakeJwt({role: 'service_role'}) 之類
```

## 對照基準

`reference/index__1_.html` 裡搜尋 `JWT_KEY_PATTERN` 與 `decodeJwtRole` 及其呼叫段落（`jwtMatches.forEach`），是本模組已驗證的行為基準。
