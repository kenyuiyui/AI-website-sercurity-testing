# M3 — hash-detector

## 你的任務
偵測程式碼中是否用已知不安全的雜湊演算法（MD5、SHA1）來處理密碼。這是本專案中規則最單純的模組。

**你不需要看過這個專案的任何其他模組。這份文件是你需要的全部背景。**

## 函式簽名

```js
function hashDetector(code) {
  // code: string
  // 回傳: Finding[]
}
```

## 規則庫（現有 demo 的規則，作為起點）

```js
const HASH_RULES = [
  { name: 'MD5 用於密碼儲存（疑似）', re: /md5\s*\(\s*(password|pwd|pass)/gi },
  { name: 'SHA1 用於密碼儲存（疑似）', re: /sha1\s*\(\s*(password|pwd|pass)/gi },
];
```

對每一條規則：用 `code.match(rule.re)`，每個 match 產生一個 Finding：

```js
{
  tier: 1,
  category: '弱雜湊演算法',
  name: rule.name,
  kind: 'weak_hash',
  evidence: m.length > 40 ? m.slice(0,40)+'…' : m
}
```

## 已知限制（誠實記錄，不要自行修補除非有明確指示）

目前規則只用「函式名稱 + 參數名稱含 password/pwd/pass」判斷，不會排除非密碼用途的呼叫，例如 `md5(salt)` 或 `md5(passwordHash)` 這種變數名稱剛好含 pass 但實際不是在雜湊密碼本身的情境。若你的測試發現這類誤判，記錄下來回報，不要擅自修改判斷邏輯範圍——這牽涉到誤判率的產品判斷。

## 明確不在你職責範圍內的東西

- 其他弱加密演算法（例如 DES、RC4）→ 若要新增，屬於本模組職責，但需要先確認是否要新增規則（見任務說明是否有提到）
- 密碼強度或密碼政策檢查 → 不在本工具範圍內

## 測試要求

1. **True positive**：`md5(password)`、`sha1(pwd)`、`MD5(PASSWORD)`（大小寫不敏感）皆應命中
2. **True negative**：`md5(username)`、`bcrypt(password)` 不應命中
3. **已知誤判案例（記錄用，非必須修）**：`md5(passwordHash)` 目前規則會誤判為命中，寫一個測試案例標記這個已知限制（可以用 `test.skip` 或註解說明，不要強行讓它通過）
4. **空輸入**：`code = ''` 回傳空陣列

## 對照基準

`reference/index__1_.html` 裡搜尋 `HASH_RULES` 及其呼叫段落，是本模組已驗證的行為基準。
