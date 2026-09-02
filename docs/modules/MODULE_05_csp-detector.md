# M5 — csp-detector

## 你的任務
判斷貼上的程式碼裡，Content Security Policy（CSP）是否有設定。這裡的難點不是正則本身，是**避免對框架化專案的系統性誤判**，請仔細讀完再動手。

**你不需要看過這個專案的任何其他模組。這份文件是你需要的全部背景。**

## 函式簽名

```js
function cspDetector(code) {
  // code: string
  // 回傳: Finding[]
}
```

## 為什麼要分兩種情境判斷（重要）

現代框架（Next.js、Nuxt 等）慣例把 CSP 設在 `next.config.js` 的 `headers()` 函式或部署平台設定檔（如 `vercel.json`），而不是 HTML meta 標籤裡。

如果只看「HTML 裡有沒有 CSP meta 標籤」，對框架化專案會產生**系統性誤判**：使用者貼上的若只是頁面元件（`layout.tsx`／`page.js` 之類），本來就不會有 meta 標籤，但不代表這個專案沒有設定 CSP。

因此本模組要先判斷「這段內容看起來像什麼」，再套用對應的期待：

```js
const looksLikeHtml = /<html|<head|<!DOCTYPE/i.test(code);

// 判斷依據用「檔案內容特徵」而非檔名字串——使用者貼上的是檔案內容,不是檔名,
// 所以不能用 "next.config." 這種路徑字樣去比對
const looksLikeFrameworkConfig = /\bNextConfig\b|defineNuxtConfig\s*\(|module\.exports\s*=\s*{[\s\S]*?headers\s*:|async\s+headers\s*\(\s*\)\s*{|"headers"\s*:\s*\[/i.test(code);

const hasCsp = /content-security-policy/i.test(code);
```

## 判斷邏輯

```js
if (looksLikeHtml && !hasCsp) {
  // tier 1 — 這是可直接判斷的情境
  {
    tier: 1,
    category: '基礎設定',
    name: '未偵測到 Content Security Policy',
    kind: 'no_csp_html',
    evidence: '頁面中無 CSP meta 標籤；若此頁面屬於 Next.js／Nuxt 等框架專案，CSP 也可能設定在 next.config.js 的 headers() 或 vercel.json 中，建議一併確認'
  }
} else if (looksLikeFrameworkConfig && !hasCsp) {
  // tier 2 — 這只是「設定檔裡沒看到」,不代表專案真的沒設定(可能設在別處)
  {
    tier: 2,
    category: '建議人工複查',
    name: '框架設定檔中未偵測到 CSP 設定（疑似）',
    kind: 'no_csp_config',
    evidence: '此設定檔看起來像 next.config／vercel.json 等框架設定檔，但未找到 Content-Security-Policy 字樣，建議確認是否有在其他設定檔或部署平台後台單獨設定'
  }
}
// 兩個條件都不成立(例如貼上的只是一段普通函式,既不像 HTML 也不像框架設定檔) → 不產生任何 Finding,不要硬報
```

## 明確不在你職責範圍內的東西

- 判斷 CSP 內容本身是否設得夠嚴格（例如允不允許 `unsafe-inline`）→ 目前不在範圍內，若未來要做，屬於本模組職責但需要另外確認需求
- HTML 以外或框架設定檔以外的情境（例如後端伺服器程式碼直接設定 response header）→ 目前不涵蓋，屬於已知限制

## 測試要求

1. **True positive（HTML 情境）**：含 `<!DOCTYPE html>` 但無 CSP 字樣 → tier 1, kind='no_csp_html'
2. **True negative（HTML 情境）**：含 `<!DOCTYPE html>` 且有 `Content-Security-Policy` meta 標籤 → 不產生 Finding
3. **True positive（框架設定檔情境）**：含 `NextConfig` 型別但無 CSP → tier 2, kind='no_csp_config'
4. **防呆：既非 HTML 也非框架設定檔**：一段普通的 JS 函式（例如 M6 的範例函式），不應產生任何 CSP 相關 Finding
5. **兩個條件都符合的邊界情況**：理論上 `looksLikeHtml` 和 `looksLikeFrameworkConfig` 應該互斥，但寫一個測試驗證優先權邏輯（目前實作是 `if / else if`，HTML 判斷優先）

## 對照基準

`reference/index__1_.html` 搜尋 `looksLikeHtml`（約在 1052 行附近）到 CSP 判斷邏輯結束，是本模組已驗證的行為基準。
