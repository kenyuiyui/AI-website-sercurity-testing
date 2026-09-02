# M4 — secret-heuristics

## ⚠️ 這個模組有一個相依，跟其他模組不一樣，請先讀完「相依說明」再動手

## 你的任務
實作一組「猜測式」的 tier 2 偵測規則集合：自訂密鑰／權杖變數含明文字串、疑似內部服務端點 URL、環境變數讀取帶明文 fallback、.env 格式內容裡的明文密鑰。這些規則沒有固定格式可百分百比對，靠命名與字串特徵判斷，因此**全部固定為 tier 2**，不可調成 tier 1。

## 相依說明

本模組需要知道 M1（key-detector）已經抓到哪些字串，避免同一段明文金鑰被 M1 和 M4 各報一次（例如一個變數同時符合「OpenAI 金鑰格式」與「變數名含 secret」兩種特徵）。

**你不需要真的去呼叫 M1 或看過 M1 的原始碼。** 你只需要知道 M1 的輸出格式（Finding[]，每筆有 `evidence` 欄位，內容是遮罩過的字串如 `sk-p...3456 [MASKED]`），並依此設計去重複邏輯。

## 函式簽名

```js
function secretHeuristics(code, existingFindings) {
  // code: string — 使用者貼上的原始程式碼文字
  // existingFindings: Finding[] — M1(key-detector) 的輸出結果,用於去重複
  // 回傳: Finding[]
}
```

測試時**不需要真的先跑 M1**，直接手工造一組假的 `existingFindings` 陣列即可：

```js
const fakeM1Output = [
  { tier: 1, category: '明文金鑰', name: 'OpenAI API Key', kind: 'plain_key', evidence: 'sk-p...cdef [MASKED]' }
];
secretHeuristics(someCode, fakeM1Output);
```

## 四組規則

### 4.1 自訂密鑰／權杖變數含明文字串

```js
const CUSTOM_SECRET_RULES = [{
  name: '自訂密鑰／權杖變數含明文字串（疑似）',
  re: /\b((?:[a-zA-Z_$][a-zA-Z0-9_$]*)?(?:secret|token|apikey|api_key|password|passwd|credential)[a-zA-Z0-9_$]*)\s*[:=]\s*["']([^"'\n]{8,})["']/gi,
  isPlaceholder: (val) => /^(your|my|xxx|placeholder|example|test|todo|change[-_]?me|<.*>|\{\{.*\}\}|\$\{.*\}|貼上|請輸入|輸入你|範例)/i.test(val.trim()) || val.trim() === ''
}];
```

命中時，先檢查 `isPlaceholder(val)`，是佔位字樣就跳過。再檢查是否已被 M1 抓過（去重複邏輯見下）。都通過才產生：

```js
{
  tier: 2,
  category: '建議人工複查',
  name: '自訂密鑰／權杖變數含明文字串（疑似）',
  kind: 'custom_secret_var',
  evidence: '變數 "' + varName + '" 疑似含明文密鑰／權杖，前端程式碼中不建議直接寫死此類值'
}
```

**去重複邏輯**：
```js
const tier1Evidences = existingFindings.filter(f => f.tier === 1 && f.category === '明文金鑰').map(f => f.evidence);
const alreadyFlagged = tier1Evidences.some(ev => ev.includes(val.slice(0, 8)));
if (alreadyFlagged) continue; // M1 已經抓過這段字串,不重複列出
```

### 4.2 內部端點 URL

```js
const ENDPOINT_URL_RULES = [
  { name: 'Google Apps Script 部署端點（疑似）', re: /https:\/\/script\.google\.com\/macros\/s\/[A-Za-z0-9_-]{20,}\/exec/g },
  { name: 'Webhook／內部 API 端點（疑似）', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/_-]{20,}/g },
];
```

命中產生：`kind: 'endpoint_url'`，evidence 用遮罩過的 URL（同 M1 的 `maskMatch` 規則）。

### 4.3 環境變數讀取帶明文 fallback

```js
const ENV_FALLBACK_RULES = [
  { name: '環境變數讀取帶明文 fallback（疑似，JavaScript）',
    re: /process\.env\.([A-Za-z_][A-Za-z0-9_]*)\s*\|\|\s*["']([^"'\n]{4,})["']/g },
  { name: '環境變數讀取帶明文 fallback（疑似，Python）',
    re: /os\.(?:environ\.get|getenv)\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*,\s*["']([^"'\n]{4,})["']\s*\)/g },
];
const ENV_FALLBACK_PLACEHOLDER = (val) =>
  /^(your|my|xxx|placeholder|example|test|todo|change[-_]?me|<.*>|\{\{.*\}\}|\$\{.*\}|貼上|請輸入|輸入你|範例|localhost|127\.0\.0\.1)/i.test(val.trim())
  || val.trim() === '';
```

命中且非佔位字樣時，產生 `kind: 'env_fallback'`。

### 4.4 .env 格式內容（逐行掃描，非正則單次比對）—— ✅ 已完成

.env 檔案格式是 `KEY=VALUE`，每行一組，跟前三組的「程式碼賦值語法」不同，需要獨立逐行處理：

```js
function scanEnvFormatLines(code) {
  const findings = [];
  const lines = code.split('\n');
  const envLinePattern = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$/;
  const secretNamePattern = /(secret|token|key|password|passwd|credential)/i;
  // 排除看起來是程式碼而非 .env 字面值的行(避免跟 4.3 規則重複報同一行)
  const looksLikeCodeNotEnvValue = /[(){}]|\.\w+\(|=>|;\s*$/;

  lines.forEach(line => {
    const m = line.match(envLinePattern);
    if (!m) return;
    const varName = m[1];
    let val = m[2].replace(/^["']|["']$/g, '');
    if (!secretNamePattern.test(varName)) return;
    if (looksLikeCodeNotEnvValue.test(m[2])) return;
    if (ENV_FALLBACK_PLACEHOLDER(val) || val.length < 8) return; // 排除佔位字樣與過短的值
    findings.push({
      tier: 2,
      category: '建議人工複查',
      name: '.env 格式中疑似含明文密鑰／權杖（疑似）',
      kind: 'env_file_secret',
      evidence: '變數 "' + varName + '" 在 .env 格式內容中疑似含明文密鑰／權杖，若此檔案已提交進版本控制，建議立即撤銷並更換該金鑰'
    });
  });
  return findings;
}
```

排除邏輯與 4.3（環境變數 fallback）共用同一個 `ENV_FALLBACK_PLACEHOLDER` 判斷式，額外加上「值長度需 ≥ 8 字元」的門檻，避免過短的字串（不足以構成有意義的密鑰）被誤判。

## 明確不在你職責範圍內的東西

- JWT 格式金鑰 → M2
- IDOR 偵測 → M6
- 已知固定格式的金鑰（OpenAI/AWS 等）→ M1（但要跟它做去重複）

## 測試要求

每組規則至少：
1. True positive 範例
2. 佔位字樣應被排除的範例（如 `"your-token-here"`）
3. 4.1 規則需額外測試「已被 M1 抓過的字串不應重複列出」：手工造一筆 `existingFindings`，驗證同樣的字串不會出現在 M4 輸出裡
4. 4.3 與 4.4 需要測試「這是同一行但屬於不同格式（程式碼 vs .env 字面值），不應被兩組規則各報一次」

## 對照基準

`reference/index__1_.html` 搜尋 `CUSTOM_SECRET_RULES`、`ENDPOINT_URL_RULES`、`ENV_FALLBACK_RULES`、`scanEnvFormatLines`，是本模組已驗證的行為基準。
