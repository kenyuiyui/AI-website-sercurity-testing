# reference_cases/ 是什麼

這個資料夾跟 `../cases/` 是**兩個完全不同性質**的東西，不要混用：

| | `cases/` | `reference_cases/`(這裡) |
|---|---|---|
| 案例來源 | 真實蒐集(GitHub public repo、真實分享連結等) | 依已公開發表的資安事件技術報告**改寫** |
| 進不進 `run_scaled_eval.js` 的統計 | 是 | **否** |
| 用途 | 建立有統計意義的準確率信賴區間 | 擴充問題模式覆蓋面、當教學範例、記錄已知規則邊界 |
| 新增時的品質要求 | 必須是真實案例，不能是發想 | 可以是改寫，但**必須**標明真實事件來源，不能是純虛構 |

## 為什麼這批案例不能進統計

`run_scaled_eval.js` 算出來的信賴區間，統計上成立的前提是樣本**真實蒐集**、不帶蒐集者的預期偏誤。這個資料夾裡的案例雖然取材自真實發生過的資安事件（CVE-2025-48757、Moltbook、Base44 等），但「把事件描述改寫成一段程式碼」這個動作本身，仍然由改寫者決定要凸顯哪個技術細節、用什麼變數命名、程式碼要多像「典型 AI 產出的樣子」——這些選擇都帶有改寫者的預期，跟真正逐字蒐集來的程式碼在統計性質上不同。硬把它們混進 `cases/` 會讓信賴區間的數學意義失真。

## 這批案例的實際用途

1. **覆蓋面擴充**：`cases/` 裡的既有樣本集中在幾類常見問題（金鑰、IDOR、SQLi），這批案例補上一些真實事件曾經出現過、但既有樣本沒測到的模式（例如 Next.js 設定檔缺 CSP、Cloudflare Workers 風格路由缺速率限制）。
2. **已知邊界記錄**：驗證過程中兩個案例（`incident-base44-2025.txt`、`incident-moltbook-2026.txt`）發現 M6(idor-detector) 正則保底版目前不涵蓋 Express 路由掛載式寫法（`app.get(path, (req,res)=>{...})`），已在對應檔案的 `===SOURCE===` 區塊詳細記錄，作為之後要不要修規則的參考，本次先不修。
3. **教學／文件用途**：每個案例都附了真實事件的技術背景說明，比起完全抽象的規則描述，更容易讓人理解「這條規則在防什麼真實會發生的事」。

## 案例清單與對照事件

| 檔案 | 對照事件/來源 | 驗證結果 |
|---|---|---|
| `incident-lovable-cve-2025-48757.txt` | CVE-2025-48757, Lovable RLS 事件(2025年6月) | ✅ 命中 |
| `incident-moltbook-2026.txt` | Moltbook 事件(2026年1月) | ⚠️ 已知邊界(Express callback 寫法未涵蓋) |
| `incident-base44-2025.txt` | Base44 平台層級認證繞過(2025年7月, Wiz Research) | ⚠️ 已知邊界(同上) |
| `incident-ai-credentials-gitguardian-2026.txt` | GitGuardian《State of Secrets Sprawl 2026》AI服務憑證統計 | ✅ 命中 |
| `incident-tenzai-nextjs-csp-2025.txt` | Tenzai 2025年12月研究(0/15應用程式設定安全標頭) | ✅ 命中 |
| `incident-tenzai-ratelimit-2025.txt` | Tenzai 2025年12月研究(1/15應用程式嘗試速率限制) | ✅ 命中 |
| `securityeval-cwe094-sonar1-known-gap.txt` | SecurityEval 資料集(CWE-094_sonar_1) | ⚠️ 已知邊界(exec含%s格式化字串未涵蓋) |
| `securityeval-cwe089-percent-format-known-gap.txt` | SecurityEval 資料集(CWE-089_codeql_1) | ⚠️ 已知邊界(SQL用%s格式化字串未涵蓋) |
| `securityeval-cwe759-hashlib-new-known-gap.txt` | SecurityEval 資料集(CWE-759_mitre_1) | ⚠️ 已知邊界(hashlib.new兩段式建構未涵蓋) |

## 待修正的規則邊界

三個檔名結尾為 `-known-gap.txt` 的案例（`securityeval-cwe094-sonar1-known-gap.txt`、`securityeval-cwe089-percent-format-known-gap.txt`、`securityeval-cwe759-hashlib-new-known-gap.txt`）與前六個 `incident-*.txt` 性質略有不同：前六個是依真實事件**改寫**（取材真實、文字是改寫的）；後三個是從 SecurityEval 學術資料集**逐字取用**（MIT 授權），但因為驗證時發現工具規則漏判，不適合當作有意義的統計樣本（硬要放進 `cases/` 只會製造固定的漏判記錄，混淆誤判率的定義），因此比照已知邊界案例的處理方式，一併留在這裡。

**這批案例裡有 4 項待修正的規則邊界，完整交接文件（含精確位置、建議修法、風險提醒）見 [`HANDOFF_rule_boundary_fixes.md`](./HANDOFF_rule_boundary_fixes.md)。** 這裡只列摘要：

- **M6(idor-detector)**：⚠️ **只有正則保底版**不涵蓋 Express 路由掛載式寫法 `app.get/post(path, (req,res)=>{...})`——AST 版（acorn 載入成功時）已經能正確偵測，之前誤以為整個模組都不涵蓋，後來用 AST 版重測才發現只是正則保底版的問題，範圍比原先評估的小。
- **M9(sql-injection-detector)**：不涵蓋 Python 的 `%` 字串格式化語法(`"...%s..." % var`)，只認字串拼接(`+`)、模板插值、f-string
- **M10(insecure-deserialize-detector)**：不涵蓋 `exec()` 內容本身由字串格式化組成的寫法(`exec("...%s..." % var)`)，只認直接傳入的形態
- **M3(hash-detector)**：不涵蓋 `hashlib.new('md5')` 兩段式建構寫法，只認 `md5(password...)` 單行呼叫

## 如果要驗證這批案例

沒有獨立的執行腳本（刻意不做，避免看起來像是另一份「正式」的統計報告）。要看結果的話：

```bash
cd eval
node -e "
const { parseCaseFile } = require('./case-loader');
const { runScan } = require('./eval-orchestrator');
const fs = require('fs');
fs.readdirSync('reference_cases').filter(f => f.endsWith('.txt')).forEach(f => {
  const parsed = parseCaseFile(fs.readFileSync('reference_cases/' + f, 'utf-8'), f);
  const { findings } = runScan(parsed.code);
  console.log(f, '→', findings.map(x => x.kind).join(', ') || '(無)');
});
"
```
