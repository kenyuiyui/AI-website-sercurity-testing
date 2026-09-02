# M7 — language-detector

## 你的任務
判斷貼上的程式碼屬於哪種語言（Python／Java-Kotlin／Ruby／其他），並回傳一段對應的提示文字，說明本工具第二層規則對這個語言的涵蓋範圍有限。**這是唯一輸出型別不是 Finding[] 的模組**，請留意。

**你不需要看過這個專案的任何其他模組。這份文件是你需要的全部背景。**

## 函式簽名（注意：輸出型別跟其他模組不同）

```js
function languageDetector(code) {
  // code: string
  // 回傳: string | null   ← 不是 Finding[]!是一段提示文字,或沒有提示時回傳 null
}
```

## 為什麼需要這個模組

M4（secret-heuristics）與 M6（idor-detector）的規則主要針對 JavaScript/TypeScript 語法設計。如果使用者貼上 Python 或 Java 程式碼，這兩個模組的規則涵蓋率會顯著下降，但畫面上不會有任何警示——使用者可能誤以為「沒被標記 = 沒問題」。這個模組的職責就是在偵測到非 JS/TS 特徵時，動態附加誠實的範圍提示。

## 判斷邏輯

```js
function detectLanguageCaveat(code) {
  // 使用者常常只貼一段程式碼片段(不含檔案開頭的 import),
  // 所以判斷條件不能要求多個特徵同時出現,改成任一項強特徵即可命中
  const isPython = /\bdef\s+\w+\s*\(.*\)\s*:|\bself\.\w+|\bos\.(environ|getenv)\b|\bimport\s+\w+|\bfrom\s+\w+\s+import\b|\belif\b|^\s*@app\.route\(/m.test(code);
  const isJavaLike = /\bpublic\s+(class|static)\b|\bprivate\s+\w+\s+\w+\s*\(/.test(code);
  const isRubyLike = /\bdef\s+\w+[\s\S]*?\bend\b/.test(code) && /\brequire\s+['"]/.test(code);

  if (isPython) {
    return '本次貼上的內容含 Python 特徵（如 def／import 語法）。第二層的「自訂密鑰變數」與「疑似缺少擁有權驗證」規則主要針對 JavaScript／TypeScript 語法設計，對 Python 的涵蓋有限——例如 Flask／Django 常見的 @app.route 裝飾器路由、os.environ.get() 讀取模式，只有「環境變數讀取＋明文 fallback」這條規則有專門對應，其餘規則可能無法辨識 Python 特有的語法結構。';
  }
  if (isJavaLike) {
    return '本次貼上的內容含 Java／Kotlin 特徵。本工具的第二層規則（自訂密鑰、疑似缺少擁有權驗證）主要針對 JavaScript／TypeScript 語法設計，對 Java／Kotlin 的涵蓋非常有限，僅第一層已知格式金鑰比對與明文密鑰變數的基礎比對仍可能有效。';
  }
  if (isRubyLike) {
    return '本次貼上的內容含 Ruby 特徵。第二層規則主要針對 JavaScript／TypeScript 語法設計，對 Ruby（如 Rails 常見寫法）的涵蓋有限。';
  }
  return null;
}
```

判斷順序是 Python → Java/Kotlin → Ruby，第一個命中就回傳，不會疊加多個提示。

## 這個模組跟其他模組的關係要特別注意

M7 不需要知道 M1-M6 實際抓到了什麼，它只單純分析 `code` 本身的語言特徵。它的輸出（提示文字）最後會被 M8（finding-renderer）附加在結果畫面最下方，跟其他 Finding 分開處理。

**如果未來有人幫某個語言（例如 Python）新增了完整的 M4／M6 規則涵蓋**，這裡的提示文字必須同步更新，否則會出現「規則其實已經支援了，但畫面還在說涵蓋有限」的過時警語。這件事在 `docs/CHANGE_MAP.md` 的「多語言支援」章節有特別註記，交接時記得提醒對方。

## 明確不在你職責範圍內的東西

- 實際針對其他語言撰寫偵測規則 → 那屬於 M4 或 M6 的任務範圍
- 精準的程式語言辨識（本模組只做粗略特徵比對，不追求 100% 準確，這是刻意的取捨——過度複雜的語言辨識邏輯不值得，因為這只是輔助提示，不是核心偵測功能）

## 測試要求

1. **Python 案例**：含 `def foo():` 或 `import os` 的片段 → 回傳 Python 提示文字
2. **Java 案例**：含 `public class Foo` 或 `private String bar()` → 回傳 Java/Kotlin 提示文字
3. **Ruby 案例**：含 `def foo...end` 且含 `require 'xxx'` → 回傳 Ruby 提示文字
4. **JS/TS 案例（無提示）**：純 JavaScript 片段（例如 `function getOrder(req,res){...}`）→ 回傳 `null`
5. **判斷優先權**：若一段程式碼同時符合多種語言特徵（理論上少見但要測邊界），驗證回傳的是 Python → Java → Ruby 這個優先順序中第一個命中的
6. **空輸入**：`code = ''` 回傳 `null`

## 對照基準

`reference/index__1_.html` 搜尋 `detectLanguageCaveat`（約在 1081-1100 行），是本模組已驗證的行為基準。
