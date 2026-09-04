/**
 * M7 — language-detector
 * 詳細規格見 docs/modules/MODULE_07_language-detector.md
 *
 * 職責:判斷貼上內容的語言特徵,回傳規則涵蓋範圍的提示文字
 * 輸入: code (string)
 * 輸出: string | null  ← 注意!輸出型別跟其他模組不同,不是 Finding[]
 *
 * 這是純函式,不依賴任何其他模組,可完全獨立開發與測試。
 * 判斷順序: Python → Java/Kotlin → Ruby,第一個命中就回傳。
 *
 * ⚠️ 修正紀錄(2026,真實Lovable專案[filla-app]實測發現的嚴重誤判):
 * 原本 PYTHON_PATTERN 裡的 \bimport\s+\w+\b 這條子規則,目的是抓Python的
 * 裸import語句(如 import os),但寫法完全沒排除JavaScript/TypeScript的
 * ES Module import語法。實測發現:任何一份標準的TS/JS檔案,只要有
 * `import type { X } from "./y"`(TypeScript專屬語法)或
 * `import React from "react"`(一般default import)這類再正常不過的寫法,
 * 都會被誤判成「含Python特徵」,對使用者顯示一段誤導性的警告文字,
 * 說這份程式碼的規則涵蓋範圍有限——而它明明就是規則主要針對的
 * JavaScript/TypeScript語言本身。這是影響面極廣、幾乎必現的誤判
 * (幾乎所有現代TS/JS檔案都有import語句),比其他已知限制嚴重得多。
 *
 * 修法:改用能區分「Python裸import」與「JS/TS的ES Module import」的正則。
 * Python的裸import語句有明確特徵——整行只有 import 模組名(可加`as`別名、
 * 逗號分隔多個模組),不接大括號、不接from子句、不接字串路徑。JS/TS的
 * import則幾乎必然接 from "..." 或用大括號解構,兩者在「一整行的完整結構」
 * 層級上是可以區分的,不能只看「有沒有出現 import 這個單字後面接識別字」
 * 這種片段式判斷。
 */

const PYTHON_IMPORT_PATTERN = /^\s*import\s+[\w.]+(?:\s+as\s+\w+)?(?:\s*,\s*[\w.]+(?:\s+as\s+\w+)?)*\s*(?:#.*)?$/m;
const PYTHON_PATTERN = /\bdef\s+\w+\s*\(.*\)\s*:|\bself\.\w+|\bos\.(environ|getenv)\b|\bfrom\s+\w+\s+import\b|\belif\b|^\s*@app\.route\(/m;
const JAVA_LIKE_PATTERN = /\bpublic\s+(class|static)\b|\bprivate\s+\w+\s+\w+\s*\(/;
const RUBY_LIKE_END_PATTERN = /\bdef\s+\w+[\s\S]*?\bend\b/;
const RUBY_LIKE_REQUIRE_PATTERN = /\brequire\s+['"]/;

/**
 * @param {string} code
 * @returns {string|null}
 */
function languageDetector(code) {
  const isPython = PYTHON_PATTERN.test(code) || PYTHON_IMPORT_PATTERN.test(code);
  const isJavaLike = JAVA_LIKE_PATTERN.test(code);
  const isRubyLike = RUBY_LIKE_END_PATTERN.test(code) && RUBY_LIKE_REQUIRE_PATTERN.test(code);

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

// ── 環境相容匯出:Node.js(require)與瀏覽器(<script src>)共用同一份檔案 ──
// Node 測試環境: module 物件存在 → 走 module.exports,供 require() 使用
// 瀏覽器環境: module 不存在 → 略過這段,函式/常數已是全域作用域下的宣告,
//            可直接被 index.html 或其他 <script> 使用
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { languageDetector, PYTHON_PATTERN, PYTHON_IMPORT_PATTERN, JAVA_LIKE_PATTERN, RUBY_LIKE_END_PATTERN, RUBY_LIKE_REQUIRE_PATTERN };
}
