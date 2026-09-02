# 需求 → 模組對照表

**用途：你有一個新需求或 bug，想知道該改哪個模組，先查這份表。找到後，把對應的三個檔案（`docs/modules/MODULE_xx_*.md` + `src/modules/xx.js` + `test/xx.test.js`）交給任一個 AI 即可獨立處理，不需要整包資料一起給（M4、M8、orchestrator 除外，見備註）。**

| 你想做的事 / 遇到的問題 | 對應模組 | 備註 |
|---|---|---|
| 金鑰漏抓了一種新格式（如新的 LLM 廠商金鑰） | M1 key-detector | 完全獨立 |
| 金鑰誤判（把不是金鑰的字串抓進去） | M1 key-detector | 完全獨立 |
| Supabase／JWT 判斷邏輯要調整 | M2 jwt-analyzer | 完全獨立 |
| 新增一種弱雜湊演算法偵測 | M3 hash-detector | 完全獨立 |
| 自訂密鑰變數規則誤判太多 / 要調整 | M4 secret-heuristics | 需要 M1 輸出格式範例（已內含在模組文件） |
| .env 格式內容偵測有問題 | M4 secret-heuristics | 同上 |
| 環境變數 fallback 偵測邏輯要改 | M4 secret-heuristics | 同上 |
| 內部端點 URL 規則要新增/調整 | M4 secret-heuristics | 同上 |
| CSP 判斷邏輯要改（例如新增別的框架設定檔特徵） | M5 csp-detector | 完全獨立 |
| IDOR 偵測準確度要提升，要換成 AST（Acorn）分析 | M6 idor-detector | ✅ **已完成**：現況為「正則保底 + AST 疊加」架構，介面不變（輸入 code、輸出 Finding[]），不影響其他模組。若要繼續調整 AST 判斷規則本身（例如新增更多資料庫方法名稱、權限關鍵字），屬於本模組職責，完全獨立 |
| IDOR 誤判 / 漏判調整 | M6 idor-detector | 完全獨立 |
| 要多支援一種程式語言的規則涵蓋 | 視情況橫跨 M1/M4/M6 + 一定要更新 M7 | 見下方「多語言支援」說明 |
| 語言提示文字要改 | M7 language-detector | 完全獨立 |
| 畫面文案（白話說明、複製給 AI 的指令模板）要改 | M8 finding-renderer | 只改 `FINDING_GUIDE` 字典，不影響邏輯 |
| 畫面排版／樣式要改 | M8 finding-renderer | 完全獨立 |
| 新增一種全新的偵測種類（不屬於現有任何模組） | 新增 M9 + 更新 orchestrator + 更新 M8 的 FINDING_GUIDE | **不建議單獨外包，需要知道全貌，見下方說明** |
| 掃描結果的執行順序要調整 | `src/scan-orchestrator.js` | 不建議單獨外包 |
| SQL Injection 誤判/漏判調整 | M9 sql-injection-detector | 完全獨立。修改前務必先讀模組文件裡「CONCAT_PATTERN 的設計取捨」段落——這個模組已經發生過兩輪連鎖修正（解決漏判時放寬條件、卻意外造成新誤判），改動後務必同時跑 `test/sql-injection-detector.test.js` + `eval/run_eval.js` + `eval/run_fp_eval.js` 三份測試，缺一不可 |
| 要新增其他 SQL 拼接模式(如 DDL 語句、跨行拼接) | M9 sql-injection-detector | 完全獨立 |
| 不安全反序列化偵測要新增規則(如新的危險函式) | M10 insecure-deserialize-detector | 完全獨立 |
| tier 1 / tier 2 分層邏輯本身要重新檢討 | 產品層級決策，非單一模組 | 見下方說明 |

---

## 「新增一種全新偵測種類」的標準流程

當需求不屬於任一現有模組（例如未來要做「偵測不安全的 CORS 設定」），流程如下：

1. 決定這是 tier 1 還是 tier 2（判斷原則見 `docs/ARCHITECTURE.md`「分層邏輯」一節）
2. 建立新模組檔案 `src/modules/M9-xxx.js`，遵循與其他模組相同的資料契約（輸入 `code` 字串、輸出 `Finding[]`）
3. 在 `docs/modules/` 新增對應的 `MODULE_09_xxx.md`
4. 在 `src/scan-orchestrator.js` 加入這個模組的呼叫
5. 在 M8 的 `FINDING_GUIDE` 字典裡新增這個模組所有 `kind` 值對應的白話文案與 AI 協作指令模板
6. 補上 `test/M9-xxx.test.js`

**步驟 2、3、6 可以外包給 AI 獨立完成**（給它資料契約說明即可）；步驟 4、5 需要知道全貌，建議由你或熟悉整體架構的人處理，或明確告知該 AI「這是新增模組，請一併更新 orchestrator 與 M8」並提供這兩個檔案。

## 「多語言支援」需求的處理方式

目前 M1、M3 天生不受語言限制（字面樣式比對）。M4、M6 的規則主要針對 JS/TS 設計。若要支援新語言（例如 Python 的 IDOR 偵測）：

1. 判斷是新增規則到既有模組（M4 或 M6 內新增一組 Python 專用正則/規則），還是該語言的偵測邏輯差異大到需要獨立成新模組
2. 無論哪種，完成後都要同步更新 M7（`language-detector.js`）的提示邏輯——如果新語言已經有專門規則涵蓋，M7 的提示文字要跟著調整，否則使用者會看到「規則對這個語言涵蓋有限」的過時警語，即使規則其實已經支援了

## 把多個模組塞進同一個 HTML `<script>` 標籤時的注意事項

8 個模組檔各自獨立撰寫、各自測試沒問題，但**組裝進同一個瀏覽器 `<script>` 標籤（同一個全域/IIFE 作用域）時**，如果不同模組各自定義了同名的輔助函式（例如 M1、M2、M4 都各自定義了一份 `maskMatch`），會變成重複宣告。

行為上通常不會直接報錯（後面的宣告會覆蓋前面的，只要內容一致就不影響結果），但這是需要留意的組裝步驟：**把模組拼進單一 HTML 檔案時，順手檢查是否有同名的 top-level function/const 重複出現，重複的只保留一份**。這不是模組檔案本身要修的問題（各模組保持獨立、各自定義是刻意設計，方便個別測試），是「組裝」這個步驟該處理的事。

## 收到使用者回報「這個結果好像是誤判」時的標準流程

1. 先確認回報的案例對應哪個模組（查上方對照表，或看 Finding 的 `kind` 值對照 `docs/modules/` 裡各模組文件的 kind 清單）
2. 把這個案例加進 `eval/false_positive_samples.js`，跑 `node eval/run_fp_eval.js` 確認現況是否真的誤判（有時候使用者回報的「誤判」其實是 tier2「建議複查」被誤解成「確診」，這種情況不是規則錯，是文案或呈現方式需要調整，不要急著改判斷邏輯）
3. 若確認是真誤判，比照 `eval/FALSE_POSITIVE_REPORT.md` 裡 fp-8 的修正方式：找出誤判的根本原因（通常是排除清單漏了某個安全的合理值），只把該模組的 `docs/modules/MODULE_xx_*.md` + 對應 `.js` + `.test.js` 三個檔案交給任一個 AI，不需要整包資料
4. 修正後務必跑一次全部模組回歸測試（`for f in test/*.test.js; do node "$f"; done`），並重新跑 `eval/run_fp_eval.js` 確認誤判率沒有因為這次修正而在其他案例上升
5. 把這個新案例保留在 `false_positive_samples.js` 裡（不要修完就刪掉），作為之後的回歸防護，避免同樣的誤判日後又發生

## Tier 1 / Tier 2 分層本身要調整時

這不是單一模組的程式邏輯問題，是產品判斷（見 `AI產出程式碼資安檢查器_專案報告.docx` 核心誠實聲明段落）。不應該讓執行單一模組任務的 AI 自行決定，這類決策應由你拍板後，再交代對應模組去調整 `tier` 欄位的值。
