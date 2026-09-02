# 系統架構

## 資料流

```
使用者貼上程式碼 code(string)
        │
        ▼
┌─────────────────────────────────────────────────┐
│  scan-orchestrator.js  ── 唯一的協調層             │
│                                                   │
│   const m1 = keyDetector(code)                   │
│   const m2 = jwtAnalyzer(code)                   │
│   const m3 = hashDetector(code)                  │
│   const m4 = secretHeuristics(code, m1)   ◀── 唯一相依：M4 讀 M1 結果去重複
│   const m5 = cspDetector(code)                   │
│   const m6 = idorDetector(code)                  │
│                                                   │
│   const allFindings = [...m1,...m2,...m3,...m4,...m5,...m6]
└─────────────────────────────────────────────────┘
        │
        ▼
  m7 = languageDetector(code)   // string | null
        │
        ▼
  m8 = findingRenderer(allFindings, m7)   // → HTML string
        │
        ▼
       DOM
```

## 設計原則

1. **模組 M1-M7 全部是純函式**：固定輸入必得固定輸出，不碰 DOM、不碰全域狀態、不需要瀏覽器環境（除 M8 外都能在 Node.js 測試環境直接跑）。這是「能個別獨立測試」的根本前提。
2. **M8 是唯一碰 DOM／輸出 HTML 的模組**，其餘都只是資料處理。
3. **模組間只有一條相依**（M1 → M4），其餘 6 個模組互相不知道彼此存在。
4. **`kind` 欄位是模組與 M8 之間的契約**：任何模組新增一種 Finding 的 `kind` 值，都必須同步在 M8 的 `FINDING_GUIDE` 字典裡新增對應文案，否則使用者只會看到技術證據、看不到白話說明。

## 分層邏輯（tier 1 / tier 2）

- **tier 1（高信心度發現）**：可從程式碼特徵直接判斷，誤判率低。例：已知格式金鑰、CSP 缺失、危險雜湊函式呼叫。
- **tier 2（建議人工複查）**：需理解程式邏輯意圖才能判斷，只能做「這裡看起來可疑」的提示。例：疑似 IDOR、疑似自訂密鑰變數、疑似內部端點。

**任何新規則加入時，第一個要決定的問題就是「這是 tier 1 還是 tier 2」**，這個判斷直接影響使用者會不會被工具的「未標記」誤導成「沒問題」。判斷原則見 `AI產出程式碼資安檢查器_專案報告.docx` 第 0、1 節。

## 語言涵蓋範圍的誠實邊界

- M1（已知金鑰格式）、M3（雜湊函式呼叫）：字面樣式比對，不受語言限制，任何語言都適用。
- M4（自訂變數猜測）、M6（IDOR）：規則設計主要針對 JavaScript/TypeScript 語法，對其他語言涵蓋有限。
- M7（language-detector）負責偵測貼上內容的語言特徵，動態產生「本次規則涵蓋範圍有限」的提示文字，附加在結果最下方。

## 現有 demo 與模組化版本的關係

`reference/index__1_.html` 是所有 8 個模組邏輯目前的「已驗證行為基準」。拆分時每個模組的行為必須與 demo 裡對應的那段程式碼完全一致（除非任務明確是要修改行為）。若拆分後行為跟 demo 不同，以 demo 現有行為為準，除非有明確指示要變更。
