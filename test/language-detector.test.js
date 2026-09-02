/**
 * 測試: M7 language-detector
 * 規格見 docs/modules/MODULE_07_language-detector.md
 * 執行方式: node test/language-detector.test.js
 *
 * 注意: 輸出型別是 string|null,不是 Finding[],跟其他模組不同。
 */

const { languageDetector } = require('../src/modules/language-detector');
const { assertEqual, assertTrue, report } = require('./_test-helpers');

const results = [];

// --- Python 案例 ---
results.push(assertTrue(
  'Python def 語法應觸發 Python 提示',
  languageDetector('def get_user(id):\n    return db.query(id)').includes('Python')
));

results.push(assertTrue(
  'Python import 語法應觸發 Python 提示',
  languageDetector('import os\nkey = os.environ.get("KEY")').includes('Python')
));

// --- Java/Kotlin 案例 ---
results.push(assertTrue(
  'Java public class 應觸發 Java/Kotlin 提示',
  languageDetector('public class UserController { private String getName() { return name; } }').includes('Java')
));

// --- Ruby 案例 ---
results.push(assertTrue(
  'Ruby def...end + require 應觸發 Ruby 提示',
  languageDetector("require 'sinatra'\ndef get_user\n  @id\nend").includes('Ruby')
));

// --- JS/TS 案例: 應回傳 null ---
results.push(assertEqual(
  '純 JavaScript 不應觸發任何語言提示',
  languageDetector('function getOrder(req, res) { const order = db.find(req.params.id); res.json(order); }'),
  null
));

// --- 空輸入 ---
results.push(assertEqual('空字串應回傳 null', languageDetector(''), null));

report('M7 language-detector', results);
