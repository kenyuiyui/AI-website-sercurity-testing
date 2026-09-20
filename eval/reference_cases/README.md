# reference_cases/ 是什麼

這個資料夾跟 `../cases/` 是**兩個完全不同性質**的東西，不要混用：

| | `cases/` | `reference_cases/`(這裡) |
|---|---|---|
| 案例來源 | 真實蒐集(GitHub public repo、真實分享連結等) | 依已公開發表的資安事件技術報告**改寫**,或依常見問題模式改寫的去識別化樣本 |
| 進不進 `run_scaled_eval.js` 的統計 | 是 | **否** |
| 用途 | 建立有統計意義的準確率信賴區間 | 擴充問題模式覆蓋面、當教學範例、記錄已知規則邊界 |
| 新增時的品質要求 | 必須是真實案例，不能是發想 | 可以是改寫，但**必須**標明真實事件來源，不能是純虛構 |

## 為什麼這批案例不能進統計

`run_scaled_eval.js` 算出來的信賴區間，統計上成立的前提是樣本**真實蒐集**、不帶蒐集者的預期偏誤。這個資料夾裡的案例雖然取材自真實發生過的資安事件（CVE-2025-48757、Moltbook、Base44 等），但「把事件描述改寫成一段程式碼」這個動作本身，仍然由改寫者決定要凸顯哪個技術細節、用什麼變數命名、程式碼要多像「典型 AI 產出的樣子」——這些選擇都帶有改寫者的預期，跟真正逐字蒐集來的程式碼在統計性質上不同。硬把它們混進 `cases/` 會讓信賴區間的數學意義失真。

## 這批案例的實際用途

1. **覆蓋面擴充**：`cases/` 裡的既有樣本集中在幾類常見問題（金鑰、IDOR、SQLi），這批案例補上一些真實事件曾經出現過、但既有樣本沒測到的模式（例如 Next.js 設定檔缺 CSP、Cloudflare Workers 風格路由缺速率限制）。
2. **規則邊界發現**：驗證過程中兩個案例（`incident-base44-2025.txt`、`incident-moltbook-2026.txt`）發現 M6(idor-detector) 正則保底版不涵蓋 Express 路由掛載式寫法（`app.get(path, (req,res)=>{...})`），已修正，修正紀錄見對應檔案的 `===SOURCE===` 區塊。
3. **教學／文件用途**：每個案例都附了真實事件的技術背景說明，比起完全抽象的規則描述，更容易讓人理解「這條規則在防什麼真實會發生的事」。

## 去識別化原則（2026-09 起）

拿別人的專案實測之後，**不可以把那個專案寫進案例裡**——不寫 repo 名稱、帳號、網址、
獨特的資料夾或檔名，變數與欄位一律改成通用名稱。對方現在沒意見不代表以後沒意見，
而且案例內容等於在說「這個專案有什麼問題」。

`incident-*.txt` 是例外：那些對照的是已經正式公開揭露、有 CVE 或廠商公告的事件，
本來就是公開資訊，所以可以在 `===SOURCE===` 具名引用來源。
`pattern-*.txt` 則完全不對應特定專案，只描述問題模式。

## 案例清單與對照事件

| 檔案 | 對照事件/來源 | 驗證結果 |
|---|---|---|
| `incident-lovable-cve-2025-48757.txt` | CVE-2025-48757, Lovable RLS 事件(2025年6月) | ✅ 命中 |
| `incident-moltbook-2026.txt` | Moltbook 事件(2026年1月) | ✅ 命中(正則版原本漏判 Express callback 寫法，已修正) |
| `incident-base44-2025.txt` | Base44 平台層級認證繞過(2025年7月, Wiz Research) | ✅ 命中(同上) |
| `incident-ai-credentials-gitguardian-2026.txt` | GitGuardian《State of Secrets Sprawl 2026》AI服務憑證統計 | ✅ 命中 |
| `incident-tenzai-nextjs-csp-2025.txt` | Tenzai 2025年12月研究(0/15應用程式設定安全標頭) | ✅ 命中 |
| `incident-tenzai-ratelimit-2025.txt` | Tenzai 2025年12月研究(1/15應用程式嘗試速率限制) | ✅ 命中 |
| `pattern-xss-innerhtml-unescaped.txt` | 常見問題模式改寫（資料未跳脫就組成 HTML），不對應特定專案 | ✅ 命中 `html_from_data` |
| `pattern-xss-via-local-variable.txt` | 同上，但資料先組成字串變數再塞進 HTML | ✅ 命中（一跳追蹤補上後才抓到） |
| `pattern-xss-url-parameter.txt` | 網址參數直接回顯（典型反射型 XSS） | ✅ 命中 `xss_from_url`（URL 來源追兩層後才抓到） |
| `pattern-xss-escaped-safe.txt` | 同樣的渲染需求但有正確跳脫（負向案例） | ✅ 正確放行 |
| `pattern-csp-unsafe-inline.txt` | 有 CSP 但 `script-src` 含 `unsafe-inline` | ✅ 命中 `csp_weak` |
| `pattern-csp-allowlist-bypass.txt` | 白名單放行公共 CDN 與 `*.github.io`（問題模式改寫，不對應特定專案） | ✅ 命中 `csp_allowlist_bypass` |
| `pattern-csp-missing-directives.txt` | nonce 型 CSP 沒寫 `base-uri`、`object-src` | ✅ 命中 `csp_missing_directive` |
| `pattern-csp-syntax-typo.txt` | 指令拼錯、`'self'` 漏單引號 | ✅ 命中 `csp_syntax` |
| `pattern-csp-meta-limits.txt` | meta 型 CSP 寫了 `frame-ancestors`、且放在腳本後面 | ✅ 命中 `csp_not_enforced` |
| `pattern-csp-strict-nonce-safe.txt` | 寫得好的 nonce＋strict-dynamic CSP（負向案例） | ✅ 正確放行 |

## 這批案例發現的規則漏判（2026-09）

`pattern-xss-via-local-variable.txt` 與 `pattern-xss-url-parameter.txt` 加進來時都是**不命中**的，
兩個都是真的漏判，因此修正了 M14：

- 插進 HTML 的是個變數時，回頭看同檔案裡那個變數是怎麼組出來的（一跳）。
- 判斷「值是否來自網址」時允許再追一層，因為 `const params = new URLSearchParams(location.search)` →
  `const keyword = params.get('q')` → 塞進 HTML 是最典型的兩段式寫法。

## 已修正的規則邊界

[`HANDOFF_rule_boundary_fixes.md`](./HANDOFF_rule_boundary_fixes.md) 列的 4 項規則邊界已全部修正：

- **M6(idor-detector)**：正則保底版新增 `ROUTE_CALLBACK_PATTERN`，涵蓋 `app.get/post(path, (req,res)=>{...})` 與 `function (req, res) {...}` callback
- **M9(sql-injection-detector)**：新增 `PERCENT_FORMAT_PATTERN`，涵蓋 Python `"...%s..." % var`
- **M10(insecure-deserialize-detector)**：新增 `insecure_python_exec`，涵蓋 `exec()` 內容由 `%`／f-string／`.format()` 組成的寫法
- **M3(hash-detector)**：新增 `hashlib.new('md5'/'sha1')` 再 `.update(password...)` 的兩段式規則

原本留在這裡的三個 SecurityEval known-gap 案例（逐字取自資料集的真實樣本）現在都能命中，已移回 `../cases/` 計入統計，改名為 `securityeval-cwe089-codeql1.txt`、`securityeval-cwe094-sonar1.txt`、`securityeval-cwe759-mitre1.txt`。

## 如果要驗證這批案例

`../run_rule_regression.js` 會逐一跑這個資料夾內所有案例，並附上四條修正規則的正負向邊界測試。它只是回歸測試，不產生統計數字（刻意不做，避免看起來像是另一份「正式」的統計報告）：

```bash
cd eval
node run_rule_regression.js
```
