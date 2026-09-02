# M8 — finding-renderer

## 你的任務
把所有偵測模組（M1-M6）合併後的 `Finding[]`，加上 M7 的語言提示字串，轉成使用者看到的 HTML。這是唯一碰 DOM／輸出 HTML 的模組。

**你不需要看過 M1-M7 的內部邏輯，只需要知道它們輸出的 Finding 格式（見下方），以及每個模組目前會用到哪些 `kind` 值（見下方對照表）。**

## 函式簽名

```js
function findingRenderer(findings, languageCaveat) {
  // findings: Finding[] — 所有模組(M1-M6)輸出結果合併後的陣列
  // languageCaveat: string | null — M7 的輸出
  // 回傳: string (HTML)
}
```

## Finding 輸入格式（你不需要知道怎麼產生，只需要知道長相）

```js
{
  tier: 1 | 2,
  category: string,
  name: string,
  kind: string,   // 對應下方 FINDING_GUIDE 字典的 key
  evidence: string
}
```

## FINDING_GUIDE 字典（本模組的核心資產：kind → 白話說明 + 可複製給 AI 的協作指令）

**這個字典的 key 必須跟所有其他模組會產生的 `kind` 值完全對齊**，否則某個 Finding 出現時，畫面上只會顯示技術證據（`evidence`），不會有白話說明，使用者體驗會缺一塊。

現有需要涵蓋的 `kind` 值（來自 M1-M6，共 11 種）：

| kind | 來源模組 | 用途 |
|---|---|---|
| `plain_key` | M1 | 已知格式金鑰 |
| `supabase_service_role` | M2 | Supabase 高權限金鑰 |
| `supabase_anon` | M2 | Supabase 公開金鑰 |
| `jwt_unknown_role` | M2 | JWT 角色未知 |
| `weak_hash` | M3 | 弱雜湊演算法 |
| `custom_secret_var` | M4 | 自訂密鑰變數 |
| `endpoint_url` | M4 | 內部端點 URL |
| `env_fallback` | M4 | 環境變數明文 fallback |
| `env_file_secret` | M4 | .env 檔案內容含密鑰 |
| `no_csp_html` | M5 | HTML 缺 CSP |
| `no_csp_config` | M5 | 框架設定檔疑似缺 CSP |
| `possible_idor` | M6 | 疑似缺少擁有權驗證 |

每個 key 對應的內容結構：

```js
FINDING_GUIDE[kind] = {
  plain: '一段白話說明,給不熟悉技術的人看的',
  handoff: '一段可複製貼給 AI(Claude/ChatGPT)的協作指令模板,通常包含: 1.先做什麼確認 2.具體修復步驟 3.完成後要回報什麼'
}
```

完整的 11 組文案內容，請直接參照 `reference/index__1_.html` 裡的 `FINDING_GUIDE` 常數（搜尋 `const FINDING_GUIDE`，約在文件中段），逐字複製過來即可，不需要重寫文案。**這些文案是已經打磨過的產品文字，不要自行改寫語氣或內容**，除非任務明確要求修改特定文案。

## 渲染邏輯（分層呈現）

```
1. 分離 tier 1 與 tier 2 的 findings
2. 顯示摘要列:「掃描完成 — 高信心度發現 N 項，建議複查 M 項」
3. 若兩者皆為 0:顯示「未發現已知格式的明文金鑰或基礎設定缺漏」
4. tier 1 逐項顯示,標籤用「發現」
5. tier 2 逐項顯示,標籤用「建議複查」
6. 每一項的內容組成:
   a. 白話說明(來自 FINDING_GUIDE[kind].plain)
   b. 可展開的「技術細節」區塊(顯示 evidence)
   c. 若有 handoff 文案,顯示「可複製貼給 AI」按鈕與文字(該區塊需要一個隨機 `handoffId`,如 `handoff_` + 隨機字串,同時放在外層 wrapper 的 `id` 與按鈕的 `data-copy-target` 屬性上,供畫面互動層的複製按鈕邏輯找到對應文字節點——複製邏輯本身屬於畫面互動層,不在 M8 職責內,但 markup 要預留給它用)
7. 最後固定顯示「本工具無法檢測」區塊(固定文字,見 reference 檔案)
8. 若 languageCaveat 不是 null,附加在「本工具無法檢測」區塊下方
```

## 安全要求（不可省略）

所有插入 HTML 的文字內容（尤其是 `evidence`，因為它可能包含使用者貼上程式碼裡的片段）都必須做 HTML escape，避免 XSS。現有 demo 用這個做法：

```js
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
```

**這一點是本模組最重要的安全底線**：一個檢查別人程式碼安全性的工具，如果自己因為沒有做輸出 escape 而被貼上的惡意程式碼片段攻擊（反射型 XSS），會是非常諷刺且嚴重的問題。務必在所有插入 `evidence`／`name`／`category` 等來自輸入資料的欄位時都呼叫 `escapeHtml`。

## 攻擊示範視覺化（buildAttackDemoHtml，目前僅 IDOR 適用）

`buildCardBody` 除了白話說明、技術細節、交接指令之外，還會呼叫 `buildAttackDemoHtml(f)`，只有 `f.kind === 'possible_idor'` 時才產生內容，其他 kind 一律回傳空字串（不影響其他 9 種 kind 的呈現）。

**分層 fallback 設計**：這個展示區塊要顯示「合法使用者 vs 攻擊者」的請求與結果對比，資料來源是 M6 附加的 `f.visualData`：

- **有真實資料**（`visualData.idParamName` 或 `visualData.dbCall.object` 存在）：顯示真實的參數名、物件名，例如 `GET /resource?orderId=482`
- **沒有真實資料**（正則保底版沒有 `visualData`，或 AST 版部分欄位是 `null`）：退化成通用抽象示意，例如「請求參數 id = 自己的資料編號」

**兩種情況畫面結構完全一致，只是文字內容不同**，永遠有東西可看，不會因為抓不到真實變數名就整個區塊消失。修改這個函式時，務必同時測試「有 visualData」「visualData 欄位全 null」「完全沒有 visualData」三種情況，確保都能正確 fallback。

**互動方式**：用原生 `<details>`/`<summary>` 元素包裹（class `rc-attack-demo`），跟現有「技術細節」區塊同一種摺疊機制，預設收合、點擊才展開，不會讓卡片一開始就過長。

**視覺配色**：沿用既有的 `--amber`（危險/攻擊者）與 `--green`（安全/合法使用者）色彩變數，不引入新色系，維持與 tier1/tier2 標籤一致的視覺語言。CSS 定義在 HTML 檔案的 `<style>` 區塊，class 前綴為 `attack-demo-*`。

**擴充到其他 kind 時的注意事項**：如果未來要幫其他問題類型（例如 M9 SQL Injection）也做類似的攻擊示範，記得：(1) 對應模組要先設計 `visualData` 該帶哪些欄位，(2) 不同問題類型的示範內容通常需要不同版型，不建議硬套同一個模板——`buildAttackDemoHtml`（IDOR用）與 `buildKeyImpactHtml`（JWT/Supabase用）就是實際案例：兩者結構不同（前者是雙欄對比，後者依 tier 用單卡列表或雙欄對比），各自獨立成一個函式，`buildCardBody` 依序呼叫兩者並串接，不適用的 kind 各自回傳空字串即可，不需要合併成單一巨大函式硬做 if/else 判斷。

## 金鑰影響範圍視覺化（buildKeyImpactHtml，目前僅 supabase_service_role / supabase_anon 適用）

跟 `buildAttackDemoHtml` 是同一批「攻擊示範」系列的展示，但資料特性不同，因此邏輯獨立：

- **`supabase_service_role`**（tier1，最高風險）：顯示單一危險卡片，列出這組金鑰能繞過的防護與能做的事（繞過 RLS、讀寫刪除任意資料、修改資料表結構），強調破壞力是**全域性**的，不是單一資源被看到
- **`supabase_anon`**（tier2，設計上可公開）：顯示「已正確設定 RLS」vs「未設定或設定錯誤」的雙欄條件對比，強調**這組金鑰本身沒問題，安全性完全取決於後端設定**，跟 `service_role` 的「絕對危險」論述不同

兩者都用 `f.visualData.projectRef`（來自 M2 解碼的 JWT payload）顯示真實的 Supabase 專案代碼，沒有就 fallback 成「這個 Supabase 專案」等通用說法。`jwt_unknown_role`（角色判斷不出來）不觸發任何視覺化，因為連角色都不確定時，不該猜測該顯示哪一種展示內容。

跟 `buildAttackDemoHtml` 的差異：M6 的 fallback 要處理「部分欄位缺失」的中間狀態（AST 走訪可能只拿到函式名、拿不到參數名），M2 的 JWT payload 是穩定的結構化資料，fallback 只有「整個 visualData 不存在」這一種情況，判斷邏輯相對單純。

## 金鑰能力清單視覺化（buildKeyCapabilityHtml，目前僅 kind === 'plain_key' 適用）

這是三種視覺化裡「fallback 程度最徹底」的一個——**M1 是純正則，沒有 AST，天生無法從程式碼萃取任何結構化資訊**，不像 M6 能解析函式名/參數名、不像 M2 能解碼 JWT payload 拿到真實專案代碼。因此這裡顯示的內容 100% 來自工具內建的知識庫查表（`KEY_CAPABILITY_KB`，依 `f.visualData.vendor` 查詢），完全不是從程式碼解析出來的。

**知識庫內容的撰寫原則**：
- 只列「這組金鑰能做的事」（權限範圍），**刻意不列可能造成的費用或金錢損失估計**——具體金額會隨時間、匯率、使用量劇烈變動，寫死一個數字或範圍是無法驗證、容易失準的宣稱，不寫比寫錯更負責任
- **AWS 是特例**：AWS Access Key 的實際權限完全取決於這組 key 綁定的 IAM policy，不像 OpenAI/Anthropic 是固定範圍的 API 存取權限。因此 AWS 條目用 `isConditional: true` 標記，畫面上會多顯示一行「這組金鑰的實際風險範圍需要另外查證，無法從程式碼本身判斷」，不能像其他廠商一樣給一份「確定會怎樣」的清單
- **查無對應廠商時回傳空字串，不硬湊內容**——如果未來新增了金鑰規則但還沒補上對應的知識庫條目，`buildKeyCapabilityHtml` 會安靜地不顯示任何東西，而不是顯示一份「大概是這樣」的猜測內容。沒有查證過的具體內容比不顯示還危險，這點呼應整個工具「沒有查證過的判斷比沒有判斷更危險」的核心原則

**擴充知識庫時**：新增一個廠商的權限清單前，務必先查證該服務官方文件對這個金鑰類型的實際能力範圍說明，不要憑印象或推測填寫。內容格式參考現有的 `openai`/`anthropic`/`google_gemini`/`line_bot` 條目（固定清單）或 `aws` 條目（條件式，`isConditional: true`）。

## 明確不在你職責範圍內的東西

- 決定某個發現屬於 tier 1 還是 tier 2 → 那是各偵測模組的職責，本模組只負責呈現
- 複製按鈕的剪貼簿邏輯（`navigator.clipboard` / fallback）可視為本模組的一部分，但屬於次要的互動邏輯，核心是渲染 HTML 字串本身

## 測試要求

1. **空結果**：`findings = []`, `languageCaveat = null` → 應顯示「未發現…」的乾淨結果
2. **只有 tier 1**：驗證摘要數字正確、只出現「發現」標籤
3. **tier 1 + tier 2 混合**：驗證兩者都正確分組顯示，數量統計正確
4. **languageCaveat 有值**：驗證提示文字有出現在畫面上
5. **XSS 防護測試（重要）**：造一個 `evidence` 欄位含 `<script>alert(1)</script>` 的假 Finding，驗證輸出的 HTML 裡這段字串已被跳脫（不會被瀏覽器當成可執行的 script 標籤）
6. **未知 kind 值**：造一個 `kind` 不在 FINDING_GUIDE 字典裡的 Finding，驗證不會拋出例外，至少能顯示 evidence（沒有白話說明也不能讓整個渲染掛掉）

## 對照基準

`reference/index__1_.html` 搜尋 `FINDING_GUIDE`、`buildCardBody`、`render`、`escapeHtml` 函式，是本模組已驗證的行為基準。
