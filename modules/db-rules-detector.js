/**
 * M15 — db-rules-detector
 *
 * 職責:判斷「資料庫權限規則」有沒有把資料整個對外打開
 *   - Firebase Security Rules(firestore.rules、storage.rules)
 *   - Realtime Database 規則(database.rules.json)
 *   - Postgres／Supabase 的 Row Level Security policy(.sql)
 * 輸入: code (string), ctx?: { filename?, language? }
 * 輸出: Finding[]
 *
 * 這是純函式,不依賴任何其他模組,可完全獨立開發與測試。
 *
 * 為什麼:用 Supabase／Firebase 做的網站,瀏覽器是直接連資料庫的——
 *        擋住別人看到你資料的唯一一道牆就是這些規則檔,金鑰可公開正是建立在這個前提上。
 *        本工具原本會說「這是可公開的金鑰，但要確認資料表權限」然後就停住,
 *        把最關鍵的判斷丟回給看不懂的人。(背景見 docs/CHANGELOG.md)
 *
 * 能力邊界:只看得懂寫在檔案裡的規則。在 Firebase／Supabase 後台手動改過的設定看不到;
 *          規則裡呼叫自訂函式(allow read: if isOwner())時,追不進函式內容,一律不報。
 */

// 這個檔案是不是「資料庫權限規則」——不是的話整個模組不跑,避免對一般程式碼誤報
const DB_RULES_FILE = /(^|\/)(firestore|storage|database)\.rules(\.json)?$|\.sql$/i;
const FIREBASE_HINT = /\brules_version\s*=|service\s+(cloud\.firestore|firebase\.storage)|^\s*match\s+\//mi;
const RTDB_HINT = /"\s*\.(read|write)\s*"\s*:/;
const SQL_HINT = /\bcreate\s+policy\b|\brow\s+level\s+security\b|\bcreate\s+table\b|\bgrant\s+/i;

/** @returns {'firebase'|'rtdb'|'sql'|null} */
function dbRulesKind(code, filename) {
  const name = String(filename || '');
  if (/(^|\/)database\.rules\.json$/i.test(name) || (!name && RTDB_HINT.test(code) && !FIREBASE_HINT.test(code))) return 'rtdb';
  if (/(^|\/)(firestore|storage)\.rules$/i.test(name) || FIREBASE_HINT.test(code)) return 'firebase';
  if (/\.sql$/i.test(name) || SQL_HINT.test(code)) return 'sql';
  if (RTDB_HINT.test(code)) return 'rtdb';
  return null;
}

// 只開放「讀」和開放「寫」的嚴重度差很多:商品目錄、公告這類表本來就該公開讀,
// 但任何人都能寫入就是另一回事。為什麼:官方的 Supabase 範本就有一條
// 「for select using (true)」的商品表政策,一律報「需要處理」等於對正確的寫法亂叫。(背景見 docs/CHANGELOG.md)
const OPEN = { tier: 1, category: '資料庫權限', kind: 'db_rules_public' };
const OPEN_READ = { tier: 2, category: '建議人工複查', kind: 'db_rules_public' };
const TESTMODE = { tier: 1, category: '資料庫權限', kind: 'db_rules_test_mode' };
const ANYUSER = { tier: 2, category: '建議人工複查', kind: 'db_rules_any_user' };

/** 註解裡的規則不算數(官方範本就把「進階寫法」註解在檔案最上面);換成等長空白,行號才不會跑掉 */
function blankComments(code, lineMark) {
  const blank = m => m.replace(/[^\n]/g, ' ');
  return code
    .replace(/\/\*[\s\S]*?\*\//g, blank)
    .replace(new RegExp(lineMark + '[^\n]*', 'g'), blank);
}

function add(findings, meta, name, evidence, index, match) {
  findings.push(Object.assign({}, meta, { name, evidence, index, match }));
}

/** 條件式裡有沒有「比對這筆資料屬於誰」——有就不是單純的登入檢查 */
function hasOwnerCheck(cond) {
  // 條件裡有呼叫函式(自訂的 isOwner()、unchanged()、get()…)就追不進去,一律當作「有再判斷」不報
  return /request\.auth\.uid\s*(==|in)|\buid\s*==|resource\.data|request\.resource\.data|[A-Za-z_][\w.]*\s*\(/i.test(cond);
}

function scanFirebase(code, findings) {
  // allow read, write: if <條件>;  以及沒有條件的 allow read;(等同 if true)
  const re = /\ballow\s+([a-z,\s]+?)\s*(?::\s*if\s+([^;{}]+))?;/gi;
  let m;
  while ((m = re.exec(code))) {
    const ops = m[1].replace(/\s+/g, ' ').trim();
    if (!/^(read|write|get|list|create|update|delete)(\s*,\s*(read|write|get|list|create|update|delete))*$/i.test(ops)) continue;
    const cond = (m[2] || 'true').replace(/\s+/g, ' ').trim();
    const writes = /write|create|update|delete/i.test(ops);
    if (/^true$/i.test(cond)) {
      add(findings, writes ? OPEN : OPEN_READ,
        writes ? 'Firebase 規則允許任何人讀寫（if true）' : 'Firebase 規則允許任何人讀取（if true）',
        writes
          ? `規則寫著 ${m[0].trim()} —— 任何人只要知道你的專案網址，就能讀取、修改甚至刪除這裡的全部資料，不需要登入`
          : `規則寫著 ${m[0].trim()} —— 這裡的資料對所有人公開讀取，不需要登入。如果是公告、商品這類本來就要公開的內容就沒問題；請確認裡面沒有個人資料或不該外流的欄位`,
        m.index, m[0]);
      continue;
    }
    if (/request\.time\s*<\s*timestamp\.date/i.test(cond)) {
      add(findings, TESTMODE, 'Firebase 規則還停在「測試模式」',
        `規則寫著 allow ${ops}: if request.time < timestamp.date(…) —— 這是建立資料庫時選「測試模式」留下的預設值：在那個日期之前，任何人都能讀寫你的全部資料；過了那天則全部被擋，網站會壞掉`,
        m.index, m[0]);
      continue;
    }
    // 只有 create 的「登入就能新增」是正常設計(留言、評論),不報;危險的是讀取與修改別人的資料
    const onlyCreate = /^(create)(\s*,\s*create)*$/i.test(ops);
    if (!onlyCreate && /request\.auth\s*!=\s*null|request\.auth\.uid\s*!=\s*null|request\.auth\s*is\s*not\s*null/i.test(cond) && !hasOwnerCheck(cond)) {
      add(findings, ANYUSER, 'Firebase 規則只檢查有沒有登入',
        `規則寫著 allow ${ops}: if ${cond} —— 只確認「有登入」，沒有比對「這筆資料是不是他的」。任何人註冊一個帳號，就能${writes ? '讀取並修改' : '讀取'}所有使用者的資料`,
        m.index, m[0]);
    }
  }
}

function scanRtdb(code, findings) {
  const re = /"\s*\.(read|write)\s*"\s*:\s*(true|"[^"]*")/gi;
  let m;
  while ((m = re.exec(code))) {
    const op = m[1].toLowerCase();
    const val = m[2];
    if (/^true$/i.test(val)) {
      add(findings, op === 'write' ? OPEN : OPEN_READ,
        op === 'write' ? 'Realtime Database 規則允許任何人寫入' : 'Realtime Database 規則允許任何人讀取',
        op === 'write'
          ? '規則寫著 ".write": true —— 任何人只要知道你的資料庫網址，就能修改或刪除這裡的全部資料，不需要登入'
          : '規則寫著 ".read": true —— 這裡的資料對所有人公開讀取，不需要登入。確認裡面沒有個人資料或不該外流的欄位',
        m.index, m[0]);
      continue;
    }
    const cond = val.slice(1, -1).replace(/\s+/g, ' ').trim();
    if (/^auth\s*!==?\s*null$/i.test(cond)) {
      add(findings, ANYUSER, 'Realtime Database 規則只檢查有沒有登入',
        `規則寫著 ".${op}": "auth != null" —— 只確認「有登入」，沒有比對資料屬於誰。任何人註冊一個帳號就能${op === 'write' ? '修改' : '讀取'}所有人的資料`,
        m.index, m[0]);
    }
  }
}

function scanSql(code, findings) {
  // 明確關掉 RLS:等於把整張表對外打開
  let m;
  const off = /alter\s+table\s+(?:if\s+exists\s+)?([\w."]+)\s+disable\s+row\s+level\s+security/gi;
  while ((m = off.exec(code))) {
    add(findings, OPEN, 'SQL 明確關閉了資料表的列級權限（RLS）',
      `${m[1]} 這張表寫著 DISABLE ROW LEVEL SECURITY —— 關掉之後，拿得到公開金鑰的人就能讀取這張表的全部資料`,
      m.index, m[0]);
  }
  // GRANT … TO anon／public:把權限直接發給未登入身分
  const grant = /grant\s+([\w\s,]+?)\s+on\s+([^\s;]+(?:\s+[^\s;]+)*?)\s+to\s+(anon|public)\b/gi;
  while ((m = grant.exec(code))) {
    add(findings, OPEN, 'SQL 把資料表權限直接給了未登入身分',
      `寫著 GRANT ${m[1].replace(/\s+/g, ' ').trim()} … TO ${m[3]} —— ${m[3] === 'anon' ? 'anon 是「沒有登入的訪客」' : 'public 是「所有人」'}，等於把這張表對外公開`,
      m.index, m[0]);
  }
  // CREATE POLICY:看它的條件式
  const pol = /create\s+policy\s+("[^"]+"|'[^']+'|[\w]+)([\s\S]{0,600}?)(?=;|create\s+policy|$)/gi;
  while ((m = pol.exec(code))) {
    const body = m[2].replace(/\s+/g, ' ');
    const conds = [];
    let c;
    const condRe = /(using|with\s+check)\s*\(([\s\S]*?)\)\s*(?=$|using|with\s+check|;)/gi;
    while ((c = condRe.exec(body))) conds.push(c[2].trim());
    if (!conds.length) continue;
    const roleAnon = /\bto\s+(anon|public)\b/i.test(body);
    const forOp = (body.match(/\bfor\s+(select|insert|update|delete|all)\b/i) || [])[1];
    const readOnly = forOp && forOp.toLowerCase() === 'select'; // 沒寫 for 時預設是 ALL
    const allTrue = conds.every(x => /^true$/i.test(x));
    if (allTrue) {
      add(findings, readOnly ? OPEN_READ : OPEN,
        readOnly ? 'SQL 的政策讓這張表對所有人公開讀取' : 'SQL 的權限規則條件永遠成立（USING (true)）',
        readOnly
          ? `政策 ${m[1]} 是 for select 而條件寫著 true —— 這張表對所有人公開讀取${roleAnon ? '（包含未登入的訪客）' : ''}。商品、公告這類本來就要公開的內容沒問題；請確認裡面沒有個人資料或不該外流的欄位`
          : `政策 ${m[1]} 的條件寫著 true —— 條件永遠成立，等於沒有限制${roleAnon ? '，而且對象是未登入的訪客' : ''}。拿得到公開金鑰的人就能${forOp ? '對' : '讀取、修改甚至刪除'}這張表${forOp ? '做 ' + forOp.toLowerCase() : '的全部資料'}`,
        m.index, ('create policy ' + m[1]));
      continue;
    }
    const onlyLoggedIn = conds.every(x => /auth\.role\s*\(\s*\)\s*=\s*'authenticated'|auth\.uid\s*\(\s*\)\s+is\s+not\s+null/i.test(x))
      && !conds.some(x => /auth\.uid\s*\(\s*\)\s*=|=\s*auth\.uid\s*\(\s*\)|auth\.uid\s*\(\s*\)\s*(in|::)/i.test(x));
    if (onlyLoggedIn) {
      add(findings, ANYUSER, 'SQL 的權限規則只檢查有沒有登入',
        `政策 ${m[1]} 只確認「有登入」，沒有比對 auth.uid() 與資料的擁有者欄位。任何人註冊一個帳號，就能看到所有使用者在這張表裡的資料`,
        m.index, ('create policy ' + m[1]));
    }
  }
}

/**
 * @param {string} code
 * @param {{filename?: string}} [ctx]
 * @returns {Array<{tier:number, category:string, name:string, kind:string, evidence:string}>}
 */
function dbRulesDetector(code, ctx) {
  code = code || '';
  const filename = ctx && ctx.filename;
  // 有檔名時以檔名為準:.js 裡出現 "allow read" 之類的字樣不該被當成規則檔
  if (filename && !DB_RULES_FILE.test(filename)) return [];
  const kind = dbRulesKind(code, filename);
  if (!kind) return [];
  const findings = [];
  if (kind === 'firebase') scanFirebase(blankComments(code, '\\/\\/'), findings);
  else if (kind === 'rtdb') scanRtdb(code, findings);
  else scanSql(blankComments(code, '--'), findings);
  return findings;
}

// ── 跨檔案:建了資料表卻沒開 RLS ──
// 只在「瀏覽器直接連資料庫」的專案才有意義(Supabase 這種)。
// 一般後端自己連資料庫時,擋在中間的是伺服器程式,沒開 RLS 不是問題。
const SUPABASE_SIGNAL = /@supabase\/|createClient\s*\(|supabase\.from\s*\(|SUPABASE_URL|supabase\.co/i;
const CREATE_TABLE_RE = /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?("?[\w]+"?)/gi;
const ENABLE_RLS_RE = /alter\s+table\s+(?:if\s+exists\s+)?(?:public\.)?("?[\w]+"?)\s+enable\s+row\s+level\s+security/gi;

/**
 * @param {Array<{filename: string, code: string}>} files
 * @returns {Array} 每張「有建表但整批檔案裡都沒開 RLS」的資料表一筆
 */
function dbRlsCoverage(files) {
  files = files || [];
  if (!files.some(f => SUPABASE_SIGNAL.test(f.code || ''))) return [];
  const created = new Map(); // 表名 → { filename, index }
  const enabled = new Set();
  files.forEach(f => {
    if (!/\.sql$/i.test(f.filename || '')) return;
    const code = f.code || '';
    let m;
    const ct = new RegExp(CREATE_TABLE_RE.source, CREATE_TABLE_RE.flags);
    while ((m = ct.exec(code))) {
      const t = m[1].replace(/"/g, '').toLowerCase();
      if (!created.has(t)) created.set(t, { filename: f.filename, index: m.index, match: m[0] });
    }
    const en = new RegExp(ENABLE_RLS_RE.source, ENABLE_RLS_RE.flags);
    while ((m = en.exec(code))) enabled.add(m[1].replace(/"/g, '').toLowerCase());
  });
  const missing = [...created.keys()].filter(t => !enabled.has(t));
  // 一張表都沒開過 RLS,和「開了一部分、漏了幾張」都要報;完全沒有建表就不報
  if (!missing.length) return [];
  return missing.map(t => Object.assign({
    tier: 2,
    category: '建議人工複查',
    name: '資料表沒有開啟列級權限（RLS）',
    kind: 'db_rls_missing',
    evidence: `資料表 ${t} 有 CREATE TABLE，但整批檔案裡找不到對應的 ENABLE ROW LEVEL SECURITY。這個專案的瀏覽器會直接連資料庫，沒開 RLS 等於拿得到公開金鑰的人就能讀取這張表的全部資料`
  }, { filename: created.get(t).filename, index: created.get(t).index, match: created.get(t).match }));
}

// ── 環境相容匯出:Node.js(require)與瀏覽器(<script src>)共用同一份檔案 ──
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { dbRulesDetector, dbRlsCoverage, dbRulesKind };
}
