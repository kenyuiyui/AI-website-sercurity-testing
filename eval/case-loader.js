/**
 * case-loader.js — 讀取 eval/cases/ 資料夾內所有 .txt 案例檔案,解析成結構化物件。
 *
 * 檔名開頭是底線(_)的檔案會被跳過(用於範例/草稿,不計入正式統計)。
 * 格式規格見 eval/CASE_FORMAT.md。
 */

const fs = require('fs');
const path = require('path');

const VALID_KINDS = new Set([
  'plain_key', 'firebase_config_exposed', 'line_bot_token_suspected',
  'custom_secret_var', 'endpoint_url', 'env_fallback', 'env_file_secret',
  'supabase_service_role', 'supabase_anon', 'jwt_unknown_role',
  'weak_hash',
  'no_csp_html', 'no_csp_config',
  'possible_idor',
  'possible_sql_injection', 'insecure_eval', 'insecure_exec',
  'insecure_function_constructor', 'insecure_pickle', 'insecure_yaml_load',
  'route_missing_rate_limit', 'route_uses_default_rate_limit',
  'inconsistent_field_masking'
]);

/**
 * 解析單一案例檔案的文字內容。
 * @param {string} raw
 * @param {string} filename - 僅用於錯誤訊息,方便定位是哪個檔案有問題
 * @returns {{source: string, category: string, expected: string[], code: string}}
 */
function parseCaseFile(raw, filename) {
  const sections = { SOURCE: '', CATEGORY: '', EXPECTED: '', CODE: '' };
  const markers = ['SOURCE', 'CATEGORY', 'EXPECTED', 'CODE'];

  // 找出每個 ===XXX=== 標記在原文中的位置
  const positions = [];
  markers.forEach(m => {
    const marker = `===${m}===`;
    const idx = raw.indexOf(marker);
    if (idx === -1) {
      throw new Error(`[${filename}] 缺少 ${marker} 區塊`);
    }
    positions.push({ name: m, start: idx, markerLen: marker.length });
  });
  positions.sort((a, b) => a.start - b.start);

  positions.forEach((p, i) => {
    const contentStart = p.start + p.markerLen;
    const contentEnd = i + 1 < positions.length ? positions[i + 1].start : raw.length;
    sections[p.name] = raw.slice(contentStart, contentEnd).trim();
  });

  const expectedRaw = sections.EXPECTED.split('\n').map(s => s.trim()).filter(Boolean);
  let expected;
  if (expectedRaw.length === 1 && expectedRaw[0].toUpperCase() === 'NONE') {
    expected = [];
  } else {
    expected = expectedRaw;
    expected.forEach(kind => {
      if (!VALID_KINDS.has(kind)) {
        throw new Error(`[${filename}] EXPECTED 區塊含未知的 kind 值: "${kind}"(檢查 CASE_FORMAT.md 的合法清單,或是否為 NONE 誤寫成其他字)`);
      }
    });
  }

  if (!sections.CODE) {
    throw new Error(`[${filename}] CODE 區塊是空的`);
  }

  return {
    filename,
    source: sections.SOURCE,
    category: sections.CATEGORY,
    expected,
    code: sections.CODE
  };
}

/**
 * 讀取 casesDir 底下所有非底線開頭的 .txt 檔案,回傳解析後的案例陣列。
 * @param {string} casesDir
 * @returns {Array<{filename: string, source: string, category: string, expected: string[], code: string}>}
 */
function loadCases(casesDir) {
  if (!fs.existsSync(casesDir)) {
    throw new Error(`案例資料夾不存在: ${casesDir}`);
  }
  const files = fs.readdirSync(casesDir)
    .filter(f => f.endsWith('.txt') && !f.startsWith('_'))
    .sort();

  const cases = [];
  const errors = [];

  files.forEach(f => {
    const fullPath = path.join(casesDir, f);
    const raw = fs.readFileSync(fullPath, 'utf-8');
    try {
      cases.push(parseCaseFile(raw, f));
    } catch (e) {
      errors.push(e.message);
    }
  });

  if (errors.length > 0) {
    throw new Error('以下案例檔案格式有誤,請修正後再執行:\n  ' + errors.join('\n  '));
  }

  return cases;
}

module.exports = { loadCases, parseCaseFile, VALID_KINDS };
