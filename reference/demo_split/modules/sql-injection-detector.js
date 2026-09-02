/**
 * M9 — sql-injection-detector
 * 職責:偵測字串拼接組成SQL查詢的模式(相對於參數化查詢的不安全寫法)
 * 輸入: code (string)
 * 輸出: Finding[]
 *
 * 這是純函式,不依賴任何其他模組,可完全獨立開發與測試。
 *
 * 判斷邏輯:找出「含SQL關鍵字的字串」且緊接著有「字串拼接運算」(+ 號)
 * 或「模板字面值/f-string插值」的模式。這個做法與 M6(idor-detector)同源:
 * 字串拼接是可從語法特徵直接判斷的模式,相對可靠,誤判率低於IDOR這類
 * 需要理解程式邏輯意圖的判斷。
 *
 * ⚠️ 修正紀錄(來自真實案例實測發現的bug):
 * 初版 CONCAT_PATTERN 用「排除引號字元的字元類別」([^"'`]) 來界定字串邊界,
 * 目的是避免比對跨越多個不同字串。但這個做法有嚴重副作用: SQL 查詢字串
 * 內部經常自己就包含單引號(例如 "...username='" + username + "'..."),
 * 正則在字串開頭遇到內部的單引號就會提早截斷比對,導致真正的字串拼接
 * 反而被漏判。改用「限制比對長度的寬鬆匹配」([\s\S]{0,120}?)取代嚴格
 * 的引號邊界匹配,犧牲一點點精確度換取不漏判真實案例中最常見的寫法。
 * (此問題是在拿真實世界案例實測時發現,原本的單元測試案例湊巧沒有
 * 觸發這個邊界,這正是「真實案例測試」相對於「手寫假案例測試」的價值所在)
 *
 * ⚠️ 修正紀錄2(誤判率驗證發現的問題,見 eval/FALSE_POSITIVE_REPORT.md fp-26):
 * 修正1解決了漏判問題,但換來另一個副作用:CONCAT_PATTERN 只要求「SQL關鍵字
 * 附近有拼接」,沒有要求這真的是一句完整的SQL語句,導致一般文字說明裡剛好
 * 提到SQL關鍵字(例如 "Use SELECT statements carefully" + userNote 這種
 * 提示文字或註解),也會被誤判為疑似SQL Injection。
 * 修正:要求SQL關鍵字後方(60字元內)還要出現對應的第二關鍵字
 * (SELECT/DELETE 對應 FROM,INSERT 對應 INTO,UPDATE 對應 SET,
 * 也接受 WHERE/VALUES 作為輔助判斷),兩者都出現才算是真正的SQL語句結構,
 * 而不只是「提到SQL關鍵字的普通文字」。用完整的既有測試集(true positive
 * 案例、eval/samples.js真實案例)驗證過,加上這個限制不會讓任何真實的
 * SQL Injection案例漏判,只排除了「關鍵字單獨出現、不構成完整語句結構」
 * 的情況。
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
const TEMPLATE_INTERP_PATTERN = new RegExp(
  `\`[^\`]*\\b${SQL_KEYWORD_PATTERN}\\b[^\`]*\\$\\{[^}]+\\}[^\`]*\``,
  'i'
);

// 模式3: Python f-string — f"...SQL...{...}..."
const FSTRING_PATTERN = new RegExp(
  `f["'][^"']*\\b${SQL_KEYWORD_PATTERN}\\b[^"']*\\{[^}]+\\}[^"']*["']`,
  'i'
);

const SQL_INJECTION_RULES = [
  { name: 'SQL 查詢使用字串拼接組成（疑似 SQL Injection）', re: CONCAT_PATTERN },
  { name: 'SQL 查詢使用模板字面值插值組成（疑似 SQL Injection）', re: TEMPLATE_INTERP_PATTERN },
  { name: 'SQL 查詢使用 Python f-string 插值組成（疑似 SQL Injection）', re: FSTRING_PATTERN },
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
          evidence: '偵測到 SQL 查詢字串疑似透過拼接方式組成，而非使用參數化查詢（如 ? 佔位符或 ORM 方法），建議改用參數化查詢避免 SQL Injection'
        });
      }
    });
  });

  return findings;
}

// ── 環境相容匯出:Node.js(require)與瀏覽器(<script src>)共用同一份檔案 ──
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { sqlInjectionDetector, SQL_INJECTION_RULES, CONCAT_PATTERN, TEMPLATE_INTERP_PATTERN, FSTRING_PATTERN };
}
