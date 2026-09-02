/**
 * M10 — insecure-deserialize-detector
 * 職責:偵測呼叫已知不安全的反序列化/動態執行函式(eval、pickle.loads、yaml.load未加safe等)
 * 輸入: code (string)
 * 輸出: Finding[]
 *
 * 這是純函式,不依賴任何其他模組,可完全獨立開發與測試。
 * 與 M3(hash-detector)同樣的設計思路:找已知危險函式呼叫的固定字面樣式,
 * 這類判斷可靠度高,誤判率低於需要理解程式邏輯意圖的判斷(如IDOR)。
 *
 * 已知限制(誠實記錄):
 * - 只能判斷「有沒有呼叫這個函式」,不能判斷傳入的資料是否真的來自不可信來源
 *   (例如 eval() 用在處理固定常數字串,技術上安全,但仍會被標記,因為
 *   無法從靜態文字判斷資料來源是否可信)
 * - exec/execSync 的偵測刻意排除「參數是固定字串常值」的情況(例如
 *   execSync("ls -la") 不會被標記),但如果字串常值裡包含拼接的變數
 *   (例如 execSync("ls " + userInput)),則會被標記,因為那才是真正的風險模式
 */

const INSECURE_DESERIALIZE_RULES = [
  { name: 'eval() 執行動態內容（疑似不安全反序列化/程式碼注入）', re: /\beval\s*\(/g, kind: 'insecure_eval' },
  { name: 'Python pickle.loads() 反序列化不可信資料', re: /\bpickle\.loads?\s*\(/g, kind: 'insecure_pickle' },
  { name: 'Python yaml.load() 未使用安全模式（應改用 yaml.safe_load 或指定 SafeLoader）', re: /\byaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)/g, kind: 'insecure_yaml_load' },
  { name: 'Node.js exec()/execSync() 執行動態組成的指令（疑似命令注入）', re: /\b(exec|execSync)\s*\(\s*[a-zA-Z_$][\w$]*/g, kind: 'insecure_exec' },
  { name: 'Function 建構子動態執行程式碼字串（等同 eval 的風險）', re: /new\s+Function\s*\(/g, kind: 'insecure_function_constructor' },
];

/**
 * @param {string} code
 * @returns {Array<{tier:number, category:string, name:string, kind:string, evidence:string}>}
 */
function insecureDeserializeDetector(code) {
  const findings = [];

  INSECURE_DESERIALIZE_RULES.forEach(rule => {
    const re = new RegExp(rule.re.source, rule.re.flags);
    const matches = code.match(re);
    if (matches) {
      matches.forEach(m => {
        findings.push({
          tier: 1,
          category: '不安全的反序列化/動態執行',
          name: rule.name,
          kind: rule.kind,
          evidence: m.length > 60 ? m.slice(0, 60) + '…' : m
        });
      });
    }
  });

  return findings;
}

// ── 環境相容匯出:Node.js(require)與瀏覽器(<script src>)共用同一份檔案 ──
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { insecureDeserializeDetector, INSECURE_DESERIALIZE_RULES };
}
