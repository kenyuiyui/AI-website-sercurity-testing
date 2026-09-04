/**
 * M4 — secret-heuristics
 * 詳細規格見 docs/modules/MODULE_04_secret-heuristics.md
 *
 * 職責:一組猜測式的 tier2 規則 — 自訂密鑰變數、內部端點 URL、
 *       環境變數明文 fallback、.env 格式內容
 * 輸入: code (string), existingFindings (Finding[] — 來自 M1 key-detector,用於去重複)
 * 輸出: Finding[]
 *
 * ⚠️ 這是唯一有相依的模組:需要 M1 的輸出來避免重複回報同一段字串。
 *    測試時不需要真的跑 M1,手工造一組假的 existingFindings 即可,見規格文件範例。
 */

const CUSTOM_SECRET_RULES = [{
  name: '自訂密鑰／權杖變數含明文字串（疑似）',
  re: /\b((?:[a-zA-Z_$][a-zA-Z0-9_$]*)?(?:secret|token|apikey|api_key|password|passwd|credential)[a-zA-Z0-9_$]*)\s*[:=]\s*["']([^"'\n]{8,})["']/gi,
  isPlaceholder: (val) => /^(your|my|xxx|placeholder|example|test|todo|change[-_]?me|<.*>|\{\{.*\}\}|\$\{.*\}|貼上|請輸入|輸入你|範例)/i.test(val.trim()) || val.trim() === ''
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
  /^(your|my|xxx|placeholder|example|test|todo|change[-_]?me|<.*>|\{\{.*\}\}|\$\{.*\}|貼上|請輸入|輸入你|範例|localhost|127\.0\.0\.1)/i.test(val.trim())
  || val.trim() === ''
  || /^\d+$/.test(val.trim()); // 純數字(連接埠號、逾時秒數等常見設定值)不可能是密鑰,誤判率評測(fp-8)發現的修正

/**
 * .env 格式內容逐行掃描(KEY=VALUE 格式,與程式碼賦值語法不同,需獨立處理)
 * 排除程式碼賦值語法(交給 4.3 ENV_FALLBACK_RULES 處理,避免同一行被兩條規則各報一次)、
 * 佔位字樣、以及短於 8 字元的值(太短不足以構成有意義的密鑰判斷)。
 * @param {string} code
 * @returns {Array}
 */
function scanEnvFormatLines(code) {
  const findings = [];
  const lines = code.split('\n');
  const envLinePattern = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$/;
  const secretNamePattern = /(secret|token|key|password|passwd|credential)/i;
  const looksLikeCodeNotEnvValue = /[(){}]|\.\w+\(|=>|;\s*$/;

  lines.forEach(line => {
    const m = line.match(envLinePattern);
    if (!m) return;
    const varName = m[1];
    let val = m[2].replace(/^["']|["']$/g, '');
    if (!secretNamePattern.test(varName)) return;
    if (looksLikeCodeNotEnvValue.test(m[2])) return; // 這是程式碼賦值,不是 .env 字面值
    if (ENV_FALLBACK_PLACEHOLDER(val) || val.length < 8) return;
    findings.push({
      tier: 2,
      category: '建議人工複查',
      name: '.env 格式中疑似含明文密鑰／權杖（疑似）',
      kind: 'env_file_secret',
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
  const tier1Evidences = existingFindings
    .filter(f => f.tier === 1 && f.category === '明文金鑰')
    .map(f => f.evidence);

  CUSTOM_SECRET_RULES.forEach(rule => {
    let cm;
    const re = new RegExp(rule.re.source, rule.re.flags);
    while ((cm = re.exec(code)) !== null) {
      const varName = cm[1];
      const val = cm[2];
      if (rule.isPlaceholder(val)) continue;
      const alreadyFlagged = tier1Evidences.some(ev => ev.includes(val.slice(0, 8)));
      if (alreadyFlagged) continue;
      findings.push({
        tier: 2,
        category: '建議人工複查',
        name: rule.name,
        kind: 'custom_secret_var',
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
      if (ENV_FALLBACK_PLACEHOLDER(val)) continue;
      findings.push({
        tier: 2,
        category: '建議人工複查',
        name: rule.name,
        kind: 'env_fallback',
        evidence: '變數 "' + varName + '" 讀取環境變數時帶有明文預設值，若部署時忘記設定對應環境變數，程式會直接使用這個明文值'
      });
    }
  });

  // 4.4 .env 格式內容
  findings.push(...scanEnvFormatLines(code));

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
  CUSTOM_SECRET_RULES,
  ENDPOINT_URL_RULES,
  ENV_FALLBACK_RULES,
  ENV_FALLBACK_PLACEHOLDER
};
}
