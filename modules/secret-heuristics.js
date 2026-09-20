/**
 * M4 — secret-heuristics
 *
 * 職責:一組猜測式的 tier2 規則 — 自訂密鑰變數、內部端點 URL、
 *       環境變數明文 fallback、.env 格式內容
 * 輸入: code (string), existingFindings (Finding[] — 來自 M1 key-detector,用於去重複)
 * 輸出: Finding[]
 *
 * ⚠️ 這是唯一有相依的模組:需要 M1 的輸出來避免重複回報同一段字串。
 *    測試時不需要真的跑 M1,手工造一組假的 existingFindings 即可,見規格文件範例。
 */

// 變數名稱看得出裝的是「給人看的文字」(錯誤訊息、標籤、輸入框類型)就不是密鑰。
// 為什麼:passwordError = "Password must be 8 to 18 characters"、passwordType = 'password'
//        這類寫法在真實專案裡很常見,名字裡有 password 不代表值是密碼。(背景見 docs/CHANGELOG.md)
const UI_STRING_NAME = /(error|message|msg|label|title|hint|placeholder|prompt|tooltip|caption|warning|notice|type|text)/i;

// 「等著被換掉」的佔位值。開頭關鍵字 + 結尾 here/_here 兩種寫法都很常見
// (範本專案的 .env 常寫 SECRET_KEY=changethis、cookieSecret: "..._secret_key_here")。
const PLACEHOLDER_PREFIX = /^(your|my|xxx|placeholder|example|test|todo|change[-_ ]?(me|this|it)|replace[-_ ]?(me|this)|set[-_ ]?me|fill[-_ ]?(me|in)|to[-_ ]?be[-_ ]?(set|filled)|insert[-_ ]?|<.*>|\{\{.*\}\}|\$\{.*\}|貼上|請輸入|輸入你|範例)/i;
const PLACEHOLDER_SUFFIX = /[-_ ]?here$|goes[-_ ]?here$/i;
const isPlaceholderValue = (val) => {
  const v = String(val == null ? '' : val).trim();
  return v === '' || PLACEHOLDER_PREFIX.test(v) || PLACEHOLDER_SUFFIX.test(v);
};

const CUSTOM_SECRET_RULES = [{
  name: '自訂密鑰／權杖變數含明文字串（疑似）',
  re: /\b((?:[a-zA-Z_$][a-zA-Z0-9_$]*)?(?:secret|token|apikey|api_key|password|passwd|credential)[a-zA-Z0-9_$]*)\s*[:=]\s*["']([^"'\n]{8,})["']/gi,
  isPlaceholder: isPlaceholderValue
}];

const ENDPOINT_URL_RULES = [
  { name: 'Google Apps Script 部署端點（疑似）', re: /https:\/\/script\.google\.com\/macros\/s\/[A-Za-z0-9_-]{20,}\/exec/g },
  { name: 'Webhook／內部 API 端點（疑似）', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/_-]{20,}/g },
];

const ENV_FALLBACK_RULES = [
  { name: '環境變數讀取帶明文 fallback（疑似，JavaScript）',
    re: /process\.env\.([A-Za-z_][A-Za-z0-9_]*)\s*\|\|\s*["']([^"'\n]{4,})["']/g },
  { name: '環境變數讀取帶明文 fallback（疑似，Python）',
    re: /os\.(?:environ\.get|getenv)\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*,\s*["']([^"'\n]{4,})["']\s*\)/g },
];

const ENV_FALLBACK_PLACEHOLDER = (val) =>
  isPlaceholderValue(val)
  || /^(localhost|127\.0\.0\.1)/i.test(String(val).trim())
  || /^\d+$/.test(String(val).trim()); // 純數字(連接埠號、逾時秒數等常見設定值)不可能是密鑰,誤判率評測(fp-8)發現的修正

// 為什麼:變數名不像密鑰、值又只是沒帳密的網址(SEO_URL、API_BASE 的預設值)——不是「備用密碼」。(背景見 docs/CHANGELOG.md)
const SECRET_LIKE_NAME = /(secret|token|key|password|passwd|pwd|credential|auth)/i;
const ENV_FALLBACK_BENIGN_URL = (varName, val) =>
  !SECRET_LIKE_NAME.test(varName) && /^https?:\/\/[^\s@]*$/i.test(val.trim());

/**
 * .env 格式內容逐行掃描(KEY=VALUE 格式,與程式碼賦值語法不同,需獨立處理)
 * 排除程式碼賦值語法(交給 4.3 ENV_FALLBACK_RULES 處理,避免同一行被兩條規則各報一次)、
 * 佔位字樣、以及短於 8 字元的值(太短不足以構成有意義的密鑰判斷)。
 * 同一個值已被 M1／M2 回報(明文金鑰、Supabase 公開金鑰…)就不再報一次,與 4.1 相同。
 * @param {string} code
 * @param {string[]} knownValues - M1／M2 回報過的原始片段
 * @returns {Array}
 */
function looksLikeEnvFile(code) {
  const lines = code.split('\n').map(l => l.trim()).filter(l => l && l.charAt(0) !== '#');
  if (!lines.length) return false;   // 使用者只貼一行 .env 也要算
  // 有這些才是程式碼/標記語言,不是 .env(export FOO=bar 是 .env 常見寫法,不算)
  if (lines.some(l => /^(import|from|const|let|var|function|class|def|package|using|require|return|if|for|while)\b/.test(l))) return false;
  if (/<\/?[a-z!]/i.test(code)) return false;
  const kv = lines.filter(l => /^(export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=/.test(l)).length;
  return kv / lines.length >= 0.6;
}

function scanEnvFormatLines(code, knownValues) {
  const findings = [];
  // 為什麼:這條規則原本對每個檔案逐行跑,結果 password=settings.X、foreign_key="user.id"、
  //        storageKey = "vite-ui-theme" 這類程式碼都被當成 .env 明文密鑰。
  //        .env 沒有程式語法,所以先確認「整份內容真的像 .env」再跑。(背景見 docs/CHANGELOG.md)
  if (!looksLikeEnvFile(code)) return findings;
  const lines = code.split('\n');
  const envLinePattern = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$/;
  const secretNamePattern = /(secret|token|key|password|passwd|credential)/i;
  // 程式碼賦值而非 .env 字面值:含括號、方法呼叫、箭頭函式、分號結尾,或讀取環境變數(environ[…]、getenv)
  const looksLikeCodeNotEnvValue = /[(){}]|\.\w+\(|=>|;\s*$|\benviron\s*\[|\bgetenv\b|process\.env/;

  lines.forEach(line => {
    const m = line.match(envLinePattern);
    if (!m) return;
    const varName = m[1];
    let val = m[2].replace(/^["']|["']$/g, '');
    if (!secretNamePattern.test(varName)) return;
    if (looksLikeCodeNotEnvValue.test(m[2])) return; // 這是程式碼賦值,不是 .env 字面值
    if (ENV_FALLBACK_PLACEHOLDER(val) || val.length < 8) return;
    if ((knownValues || []).some(v => val.includes(v) || v.includes(val))) return;
    findings.push({
      tier: 2,
      category: '建議人工複查',
      name: '.env 格式中疑似含明文密鑰／權杖（疑似）',
      kind: 'env_file_secret',
      match: line,
      evidence: '變數 "' + varName + '" 在 .env 格式內容中疑似含明文密鑰／權杖，若此檔案已提交進版本控制，建議立即撤銷並更換該金鑰'
    });
  });

  return findings;
}

/**
 * @param {string} code
 * @param {Array} existingFindings - M1(key-detector) 的輸出,用於去重複
 * @returns {Array<{tier:number, category:string, name:string, kind:string, evidence:string}>}
 */
function secretHeuristics(code, existingFindings) {
  const findings = [];
  existingFindings = existingFindings || [];

  // 4.1 自訂密鑰變數
  // 去重複:同一個值已被 M1 回報(明文金鑰、Firebase 設定、Line token)就不再報一次。
  // 用 M1 的原始片段 match 比對;evidence 已遮罩,不能拿來比對。
  const knownValues = existingFindings.map(f => f.match).filter(Boolean);

  CUSTOM_SECRET_RULES.forEach(rule => {
    let cm;
    const re = new RegExp(rule.re.source, rule.re.flags);
    while ((cm = re.exec(code)) !== null) {
      const varName = cm[1];
      const val = cm[2];
      if (rule.isPlaceholder(val)) continue;
      if (UI_STRING_NAME.test(varName)) continue;
      const alreadyFlagged = knownValues.some(v => val.includes(v) || v.includes(val));
      if (alreadyFlagged) continue;
      findings.push({
        tier: 2,
        category: '建議人工複查',
        name: rule.name,
        kind: 'custom_secret_var',
        index: cm.index,
        evidence: '變數 "' + varName + '" 疑似含明文密鑰／權杖，前端程式碼中不建議直接寫死此類值'
      });
    }
  });

  // 4.2 內部端點 URL
  ENDPOINT_URL_RULES.forEach(rule => {
    const matches = code.match(rule.re);
    if (matches) {
      matches.forEach(m => {
        findings.push({
          tier: 2,
          category: '建議人工複查',
          name: rule.name,
          kind: 'endpoint_url',
          match: m,
          evidence: '偵測到疑似內部服務端點 URL 寫死在原始碼中：' + maskMatch(m)
        });
      });
    }
  });

  // 4.3 環境變數明文 fallback
  ENV_FALLBACK_RULES.forEach(rule => {
    let em;
    const re = new RegExp(rule.re.source, rule.re.flags);
    while ((em = re.exec(code)) !== null) {
      const varName = em[1];
      const val = em[2];
      if (ENV_FALLBACK_PLACEHOLDER(val) || ENV_FALLBACK_BENIGN_URL(varName, val)) continue;
      findings.push({
        tier: 2,
        category: '建議人工複查',
        name: rule.name,
        kind: 'env_fallback',
        index: em.index,
        evidence: '變數 "' + varName + '" 讀取環境變數時帶有明文預設值，若部署時忘記設定對應環境變數，程式會直接使用這個明文值'
      });
    }
  });

  // 4.4 .env 格式內容
  findings.push(...scanEnvFormatLines(code, knownValues));

  return findings;
}

// ── 環境相容匯出:Node.js(require)與瀏覽器(<script src>)共用同一份檔案 ──
// Node 測試環境: module 物件存在 → 走 module.exports,供 require() 使用
// 瀏覽器環境: module 不存在 → 略過這段,函式/常數已是全域作用域下的宣告,
//            可直接被 index.html 或其他 <script> 使用
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
  secretHeuristics,
  scanEnvFormatLines,
  looksLikeEnvFile,
  isPlaceholderValue,
  CUSTOM_SECRET_RULES,
  ENDPOINT_URL_RULES,
  ENV_FALLBACK_RULES,
  ENV_FALLBACK_PLACEHOLDER
};
}
