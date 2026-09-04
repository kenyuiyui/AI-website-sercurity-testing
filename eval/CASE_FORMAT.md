# 案例蒐集格式說明

每個案例是一個獨立的 `.txt` 檔案，放在 `eval/cases/` 資料夾底下，檔名格式：
`{來源}-{編號}.txt`，例如 `github-001.txt`、`v0-002.txt`。

不需要碰任何 JS 語法、不用處理字串跳脫，複製貼上程式碼原文即可。

---

## 檔案內容格式（固定四個區塊，用 `===` 分隔）

```
===SOURCE===
（這段程式碼從哪來，例如：GitHub public repo, user/repo-name, 檔案路徑, 2026-XX-XX 存取；
  或：v0.dev 產出的公開分享連結；或：手動改寫自某公開技術文章案例）

===CATEGORY===
（這個案例主要在測什麼問題，用一句話描述，例如：硬編碼 API 金鑰）

===EXPECTED===
（這個案例「應該」被偵測到的項目，一行一個 kind 值，完全沒有問題的安全案例則寫 NONE）

===CODE===
（貼上實際程式碼原文，這個區塊到檔案結尾為止，不用跳脫任何符號）
```

---

## EXPECTED 可以填的 kind 值（複製貼上即可，只能用下面清單裡的字）

**金鑰／密鑰類**
- `plain_key` — 明文 API 金鑰（OpenAI/Anthropic/Gemini/AWS 等已知格式）
- `firebase_config_exposed` — Firebase config 外洩
- `line_bot_token_suspected` — 疑似 Line Bot Token
- `custom_secret_var` — 疑似自訂密鑰變數含明文
- `endpoint_url` — 疑似內部服務端點 URL 寫死
- `env_fallback` — 環境變數讀取帶明文 fallback
- `env_file_secret` — 貼上的 .env 格式內容含金鑰

**JWT / Supabase**
- `supabase_service_role` — Supabase service_role 金鑰（高風險）
- `supabase_anon` — Supabase anon 金鑰
- `jwt_unknown_role` — JWT 格式但無法判斷角色

**弱雜湊**
- `weak_hash` — MD5/SHA1 用於密碼儲存

**CSP**
- `no_csp_html` — HTML 頁面缺少 CSP
- `no_csp_config` — 框架設定檔缺少 CSP

**存取控制**
- `possible_idor` — 疑似缺少擁有權驗證

**注入 / 反序列化**
- `possible_sql_injection` — SQL Injection
- `insecure_eval` — 不安全的 eval
- `insecure_exec` — 不安全的 exec
- `insecure_function_constructor` — 不安全的 Function constructor
- `insecure_pickle` — 不安全的 pickle
- `insecure_yaml_load` — 不安全的 yaml.load

**速率限制**
- `route_missing_rate_limit` — 路由完全缺少速率限制
- `route_uses_default_rate_limit` — 路由僅用框架預設速率限制

**多檔案（跨檔案比對，這類案例先跳過，框架暫不支援單檔蒐集格式）**
- `inconsistent_field_masking` — 跨檔案欄位遮罩不一致

---

## 兩種案例都要蒐集，缺一不可

1. **「應該被抓到」的案例**（true positive 樣本）：EXPECTED 填實際的 kind
2. **「不該被抓到」的案例**（true negative 樣本，也就是誤判測試用）：程式碼本身是安全、正確的寫法，EXPECTED 填 `NONE`

兩種案例的比例建議接近 1:1——只蒐集「有問題」的案例只能驗證命中率，驗證不了誤判率，兩個數字都需要獨立的樣本支撐。

---

## 「誤判」的判定標準

`EXPECTED=NONE` 的案例（安全、正確的寫法）如果被工具標記，不會每一次都算「誤判」：

- **tier1（高信心度發現）誤報 → 算誤判。** 這是工具很確定但錯了，例如把安全的寫法直接判成明文金鑰。
- **tier2（建議人工複查）出現 → 不算誤判。** tier2 本身設計上就是刻意保守——寧可多提示一則「這裡看起來可疑，建議自行確認」，也不要漏掉真正的問題。這與專案的優先序一致：對不熟悉資安的目標使用者來說，多看一則需要自行排除的提示，代價遠低於漏掉一個真的外洩的金鑰。

框架會把觸發 tier2 但沒有 tier1 誤報的案例單獨列出（不計入誤判率），方便你留意「如果這份清單持續變長，某條 tier2 規則可能設計得過於敏感」，但不會直接扣分。

**特殊情況：工具涵蓋範圍外的內容**（例如 AWS IAM policy JSON、雲端權限設定這類工具完全不涵蓋的問題類型）。這類案例雖然也是「EXPECTED=NONE」，但驗證的目標跟一般的 true negative 案例不同——一般 true negative 驗證的是「工具認得這類寫法是安全的」，這類則是驗證「工具面對自己完全不懂的東西時，不會硬湊一個假結果出來」。建議把這類案例的檔名開頭加底線（例如 `_out-of-scope-xxx.txt`），排除在正式統計之外，另外用文字說明記錄，避免混進誤判率把兩種不同性質的驗證混為一談。

---

## 範例檔案

看 `eval/cases/_example-true-positive.txt` 和 `eval/cases/_example-true-negative.txt` 兩個範例檔案（檔名開頭底線的不會被框架讀取，純粹展示格式）。
