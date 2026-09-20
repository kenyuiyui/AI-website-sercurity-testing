/**
 * M9 — sql-injection-detector
 * 職責:偵測字串拼接組成SQL查詢的模式(相對於參數化查詢的不安全寫法)
 * 輸入: code (string)
 * 輸出: Finding[]
 *
 * 這是純函式,不依賴任何其他模組,可完全獨立開發與測試。
 *
 * 判斷邏輯:找出「含SQL關鍵字的字串」且緊接著有「字串拼接運算」(+ 號)、
 * 「模板字面值/f-string插值」或「Python % 格式化」的模式。這個做法與 M6(idor-detector)同源:
 * 字串拼接是可從語法特徵直接判斷的模式,相對可靠,誤判率低於IDOR這類
 * 需要理解程式邏輯意圖的判斷。
 *
 * 為什麼:字串拼接用限長寬鬆匹配 [\s\S]{0,120}?,不能用引號邊界(SQL 內常含單引號)。(背景見 docs/CHANGELOG.md)
 *
 * 為什麼:SQL 關鍵字需搭配第二關鍵字(FROM/INTO/SET…)才算語句,避免一般文字誤判(fp-26)。(背景見 docs/CHANGELOG.md)
 *
 * 為什麼:模板字面值／f-string 同樣要求第二關鍵字,否則 `...update(${id})...` 這種組 HTML 的寫法會誤報。(背景見 docs/CHANGELOG.md)
 *
 * 已知限制(誠實記錄):
 * - 無法判斷拼接進SQL字串的變數是否經過消毒(sanitize)處理,只要偵測到拼接
 *   模式就會標記,即使該變數其實是安全的固定值
 * - 只涵蓋常見的 SELECT/INSERT/UPDATE/DELETE 關鍵字,不涵蓋 DDL(CREATE/DROP等)
 * - 多行拼接(例如用 .concat() 方法、或分成多行變數再組合)偵測不到,
 *   目前逐行比對,只能看單一行內的拼接
 * - 若SQL語句的第二關鍵字(FROM/WHERE等)距離超過60字元(例如選取極多欄位的
 *   SELECT),可能導致漏判,這是為了限制正則掃描範圍、避免效能問題與跨語句
 *   誤配對而做的取捨
 */

const SQL_KEYWORD_PATTERN = '(SELECT|INSERT|UPDATE|DELETE)';
const SQL_SECOND_KEYWORD_PATTERN = '(FROM|INTO|WHERE|SET|VALUES)';

// 模式1: SQL關鍵字 + 第二關鍵字(構成真正的SQL語句結構) + 拼接運算(+號)。
// 要求兩個關鍵字都出現,是為了排除「只是提到SQL關鍵字的普通文字」這種誤判
// (見上方修正紀錄2)。用「限制長度的寬鬆匹配」而非嚴格引號邊界匹配,避免
// SQL字串內部自帶的引號(如 username='...')造成正則提早截斷、漏判真實寫法。
const CONCAT_PATTERN = new RegExp(
  `\\b${SQL_KEYWORD_PATTERN}\\b[\\s\\S]{0,60}?\\b${SQL_SECOND_KEYWORD_PATTERN}\\b[\\s\\S]{0,60}?["'\`]\\s*\\+|\\+\\s*["'\`][\\s\\S]{0,40}?\\b${SQL_KEYWORD_PATTERN}\\b[\\s\\S]{0,60}?\\b${SQL_SECOND_KEYWORD_PATTERN}\\b`,
  'i'
);

// 模式2: JS模板字面值插值 — `...SQL...${...}...`
// 兩個關鍵字都要出現(同模式1):單看 UPDATE/DELETE 會把 `onblur="X.update(${id})"`、
// 壓縮後的函式庫(含 delete 運算子)這類組 HTML／一般程式碼的模板字串當成 SQL。
const TEMPLATE_INTERP_PATTERN = new RegExp(
  `\`[^\`]*\\b${SQL_KEYWORD_PATTERN}\\b[^\`]{0,60}?\\b${SQL_SECOND_KEYWORD_PATTERN}\\b[^\`]*\\$\\{[^}]+\\}[^\`]*\`|\`[^\`]*\\$\\{[^}]+\\}[^\`]*\\b${SQL_KEYWORD_PATTERN}\\b[^\`]{0,60}?\\b${SQL_SECOND_KEYWORD_PATTERN}\\b[^\`]*\``,
  'i'
);

// 模式3: Python f-string — f"...SQL...{...}..."
const FSTRING_PATTERN = new RegExp(
  `f["'][^"']*\\b${SQL_KEYWORD_PATTERN}\\b[^"']{0,60}?\\b${SQL_SECOND_KEYWORD_PATTERN}\\b[^"']*\\{[^}]+\\}[^"']*["']|f["'][^"']*\\{[^}]+\\}[^"']*\\b${SQL_KEYWORD_PATTERN}\\b[^"']{0,60}?\\b${SQL_SECOND_KEYWORD_PATTERN}\\b[^"']*["']`,
  'i'
);

// 模式4: Python % 格式化 — "...SQL...%s..." % var (SecurityEval CWE-089_codeql_1)
// 同樣要求兩個SQL關鍵字都出現,避免誤判一般字串格式化("%d items found" % count)
// 或只提到SQL關鍵字的日誌訊息。引號後的 % 運算子必須接「變數名+結尾符號」或「(」,
// 才能區分字串外的格式化運算子與字串內的佔位符(例如 WHERE name = '%s' 的 '%s、
// LIKE '%foo%'),否則參數化查詢 execute("... '%s'", [x]) 也會被誤判。
const PERCENT_FORMAT_PATTERN = new RegExp(
  `\\b${SQL_KEYWORD_PATTERN}\\b[\\s\\S]{0,60}?\\b${SQL_SECOND_KEYWORD_PATTERN}\\b[\\s\\S]{0,80}?["']\\s*%\\s*(?:\\(|[A-Za-z_]\\w*\\s*(?:[),.\\[]|$))`,
  'i'
);

const SQL_INJECTION_RULES = [
  { name: 'SQL 查詢使用字串拼接組成（疑似 SQL Injection）', re: CONCAT_PATTERN },
  { name: 'SQL 查詢使用模板字面值插值組成（疑似 SQL Injection）', re: TEMPLATE_INTERP_PATTERN },
  { name: 'SQL 查詢使用 Python f-string 插值組成（疑似 SQL Injection）', re: FSTRING_PATTERN },
  { name: 'SQL 查詢使用 Python % 格式化字串組成（疑似 SQL Injection）', re: PERCENT_FORMAT_PATTERN },
];

/**
 * @param {string} code
 * @returns {Array<{tier:number, category:string, name:string, kind:string, evidence:string}>}
 */
function sqlInjectionDetector(code) {
  const findings = [];
  const lines = code.split('\n');
  const matchedRuleNames = new Set();

  lines.forEach(line => {
    SQL_INJECTION_RULES.forEach(rule => {
      // 避免同一行被多條規則各報一次(例如同時符合拼接與模板插值的邊界情況)
      const dedupeKey = line + '::' + rule.name;
      if (matchedRuleNames.has(dedupeKey)) return;

      if (rule.re.test(line)) {
        matchedRuleNames.add(dedupeKey);
        findings.push({
          tier: 2,
          category: '建議人工複查',
          name: rule.name,
          kind: 'possible_sql_injection',
          match: line,
          evidence: '偵測到 SQL 查詢字串疑似透過拼接方式組成，而非使用參數化查詢（如 ? 佔位符或 ORM 方法），建議改用參數化查詢避免 SQL Injection'
        });
      }
    });
  });

  return findings;
}

// ── 環境相容匯出:Node.js(require)與瀏覽器(<script src>)共用同一份檔案 ──
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { sqlInjectionDetector, SQL_INJECTION_RULES, CONCAT_PATTERN, TEMPLATE_INTERP_PATTERN, FSTRING_PATTERN, PERCENT_FORMAT_PATTERN };
}
