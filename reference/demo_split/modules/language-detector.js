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
 */

const PYTHON_PATTERN = /\bdef\s+\w+\s*\(.*\)\s*:|\bself\.\w+|\bos\.(environ|getenv)\b|\bimport\s+\w+|\bfrom\s+\w+\s+import\b|\belif\b|^\s*@app\.route\(/m;
const JAVA_LIKE_PATTERN = /\bpublic\s+(class|static)\b|\bprivate\s+\w+\s+\w+\s*\(/;
const RUBY_LIKE_END_PATTERN = /\bdef\s+\w+[\s\S]*?\bend\b/;
const RUBY_LIKE_REQUIRE_PATTERN = /\brequire\s+['"]/;

/**
 * @param {string} code
 * @returns {string|null}
 */
function languageDetector(code) {
  const isPython = PYTHON_PATTERN.test(code);
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
  module.exports = { languageDetector };
}
