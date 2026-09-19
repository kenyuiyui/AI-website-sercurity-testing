/**
 * source-mask — 分辨原始碼中哪些位置是「真正的程式碼」,哪些是字串、註解、正則字面值
 *
 * 用途:「執行程式碼」類規則(eval、exec、new Function、pickle、yaml、弱雜湊)只該對真正的呼叫報警,
 * 不該對說明文字、註解、規則定義、測試資料裡「提到」這些函式的地方報警。
 * 金鑰與 SQL 規則刻意不使用本模組——金鑰與 SQL 本來就寫在字串裡。
 *
 * 這是輕量的字元掃描,不是完整語法分析。已知限制:
 * - 除號與正則字面值 `/` 靠前一個有效字元判斷,極少數寫法可能判斷錯
 * - HTML 只分析 <script> 區塊內部;區塊外(含 onclick="…" 屬性)一律視為程式碼,寧可多報不漏報
 * - 未閉合的字串或註解不會吞掉後面的程式碼(字串到行尾為止、未閉合的反引號／區塊註解視為程式碼)
 *
 * 輸出:Uint8Array,與原始碼等長;0 = 程式碼、1 = 字串、2 = 註解、3 = 正則字面值
 */

const MASK_CODE = 0;
const MASK_STRING = 1;
const MASK_COMMENT = 2;
const MASK_REGEX = 3;

const REGEX_PRECEDING_CHARS = '(,=:[!&|?{};+-*%<>~^';
const REGEX_PRECEDING_WORDS = /(?:^|[^\w$])(return|typeof|case|do|else|in|of|new|delete|void|throw|yield|await)$/;

/**
 * @param {string} code
 * @param {{python?: boolean}} [opts] - python:true 時 # 視為註解、支援三引號字串
 * @returns {Uint8Array}
 */
function buildJsMask(code, opts) {
  const python = !!(opts && opts.python);
  const n = code.length;
  const mask = new Uint8Array(n);
  let i = 0;
  let lastSignificant = ''; // 前一個非空白、非註解的字元(判斷 / 是除號還是正則)
  let lastWordEnd = 0;

  const fill = (from, to, kind) => { for (let k = from; k < to && k < n; k++) mask[k] = kind; };

  // 樣板字串 `...${ code }...` 的巢狀狀態
  const templateStack = []; // 每層記錄 { braceDepth }

  while (i < n) {
    const ch = code[i];
    const next = code[i + 1];

    // 樣板字串內的 ${ } 程式碼區段結束
    if (templateStack.length && ch === '}') {
      const top = templateStack[templateStack.length - 1];
      if (top.braceDepth === 0) {
        templateStack.pop();
        const end = scanTemplateBody(i + 1);
        if (end < 0) { i++; continue; }
        i = end;
        lastSignificant = '`';
        continue;
      }
      top.braceDepth--;
    } else if (templateStack.length && ch === '{') {
      templateStack[templateStack.length - 1].braceDepth++;
    }

    // 空白
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') { i++; continue; }

    // 註解
    if (!python && ch === '/' && next === '/') { const e = lineEnd(i); fill(i, e, MASK_COMMENT); i = e; continue; }
    if (!python && ch === '/' && next === '*') {
      const close = code.indexOf('*/', i + 2);
      if (close < 0) { i += 2; continue; } // 未閉合:不吞掉後面的程式碼
      fill(i, close + 2, MASK_COMMENT); i = close + 2; continue;
    }
    if (python && ch === '#') { const e = lineEnd(i); fill(i, e, MASK_COMMENT); i = e; continue; }

    // Python 三引號字串
    if (python && (ch === '"' || ch === "'") && next === ch && code[i + 2] === ch) {
      const q = ch + ch + ch;
      const close = code.indexOf(q, i + 3);
      if (close < 0) { i += 3; continue; }
      fill(i, close + 3, MASK_STRING); i = close + 3; lastSignificant = ch; continue;
    }

    // 一般字串(到行尾為止)
    if (ch === '"' || ch === "'") {
      let j = i + 1;
      while (j < n && code[j] !== ch && code[j] !== '\n') { j += code[j] === '\\' ? 2 : 1; }
      const end = j < n && code[j] === ch ? j + 1 : j;
      fill(i, end, MASK_STRING); i = end; lastSignificant = ch; continue;
    }

    // 樣板字串
    if (!python && ch === '`') {
      const end = scanTemplateBody(i + 1, i);
      if (end < 0) { i++; lastSignificant = ch; continue; } // 未閉合:視為程式碼
      i = end; lastSignificant = '`'; continue;
    }

    // 正則字面值
    if (!python && ch === '/' && regexAllowed()) {
      const end = scanRegex(i);
      if (end > 0) { fill(i, end, MASK_REGEX); i = end; lastSignificant = '/'; continue; }
    }

    if (/[\w$]/.test(ch)) {
      let j = i;
      while (j < n && /[\w$]/.test(code[j])) j++;
      lastSignificant = code[j - 1];
      lastWordEnd = j;
      i = j;
      continue;
    }
    lastSignificant = ch;
    i++;
  }
  return mask;

  function lineEnd(from) { const e = code.indexOf('\n', from); return e < 0 ? n : e; }

  function regexAllowed() {
    if (!lastSignificant) return true;
    if (REGEX_PRECEDING_CHARS.indexOf(lastSignificant) >= 0) return true;
    if (/[\w$]/.test(lastSignificant)) return REGEX_PRECEDING_WORDS.test(code.slice(Math.max(0, lastWordEnd - 12), lastWordEnd));
    return false;
  }

  function scanRegex(start) {
    let j = start + 1;
    let inClass = false;
    while (j < n) {
      const c = code[j];
      if (c === '\n') return -1;
      if (c === '\\') { j += 2; continue; }
      if (c === '[') inClass = true;
      else if (c === ']') inClass = false;
      else if (c === '/' && !inClass) {
        j++;
        while (j < n && /[a-z]/i.test(code[j])) j++;
        return j;
      }
      j++;
    }
    return -1;
  }

  // 從反引號之後(或 ${ } 結束之後)掃描樣板字串本體;遇到 ${ 進入程式碼區段。
  // 回傳下一個要掃描的位置;樣板字串未閉合時回傳 -1(並還原為程式碼)。
  function scanTemplateBody(from, openIdx) {
    let j = from;
    while (j < n) {
      const c = code[j];
      if (c === '\\') { j += 2; continue; }
      if (c === '`') {
        fill(openIdx !== undefined ? openIdx : from - 1, j + 1, MASK_STRING);
        if (openIdx === undefined) mask[from - 1] = MASK_CODE; // 從 } 接續時,} 本身是程式碼
        return j + 1;
      }
      if (c === '$' && code[j + 1] === '{') {
        fill(openIdx !== undefined ? openIdx : from, j + 2, MASK_STRING);
        templateStack.push({ braceDepth: 0 });
        return j + 2;
      }
      j++;
    }
    return -1;
  }
}

/**
 * 依內容型態建立遮罩:HTML 只分析 <script> 區塊;其他視為 JS/TS,Python 另外處理。
 * @param {string} code
 * @param {{language?: 'js'|'python'|'html'|null}} [opts]
 * @returns {Uint8Array}
 */
function buildCodeMask(code, opts) {
  code = code || '';
  const language = (opts && opts.language) || guessMaskLanguage(code);
  if (language === 'python') return buildJsMask(code, { python: true });
  if (language !== 'html') return buildJsMask(code);

  // HTML:<script> 區塊以外視為程式碼(包含 on* 屬性),區塊內部照 JS 規則分析
  const mask = new Uint8Array(code.length);
  const re = /<script\b[^>]*>([\s\S]*?)<\/script\s*>/gi;
  let m;
  while ((m = re.exec(code)) !== null) {
    const bodyStart = m.index + m[0].indexOf('>') + 1;
    const inner = buildJsMask(m[1]);
    mask.set(inner, bodyStart);
  }
  // HTML 註解
  // 以字串組合,避免原始碼出現 HTML 註解開頭序列(單檔版內嵌 <script> 時會出問題)
  const commentRe = new RegExp('<' + '!--[\\s\\S]*?--' + '>', 'g');
  while ((m = commentRe.exec(code)) !== null) {
    for (let k = m.index; k < m.index + m[0].length; k++) mask[k] = MASK_COMMENT;
  }
  return mask;
}

function guessMaskLanguage(code) {
  if (/<!DOCTYPE\s+html|<html[\s>]/i.test(code) || (/<script[\s>]/i.test(code) && /<\/script>/i.test(code) && /<(head|body|div|p|button)[\s>]/i.test(code))) return 'html';
  const py = /^\s*(def\s+\w+\s*\(.*\)\s*:|import\s+[\w.]+\s*$|from\s+[\w.]+\s+import\s)/m.test(code) && !/\b(const|let|function)\s+\w|=>/.test(code);
  return py ? 'python' : 'js';
}

/** 副檔名 → 遮罩用語言;不認得的副檔名回傳 null(改用內容猜測) */
function languageFromFilename(filename) {
  if (!filename) return null;
  const ext = String(filename).toLowerCase().match(/\.([a-z0-9]+)$/);
  if (!ext) return null;
  if (ext[1] === 'py') return 'python';
  if (['html', 'htm'].indexOf(ext[1]) >= 0) return 'html';
  if (['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'vue', 'svelte', 'astro'].indexOf(ext[1]) >= 0) return 'js';
  return null;
}

/**
 * 取得遮罩:scan-orchestrator 會預先建好放在 ctx.mask(同一份程式碼只建一次);
 * 偵測模組被單獨呼叫(例如 Node 測試)時才自己建。
 */
function resolveCodeMask(code, ctx) {
  if (ctx && ctx.mask) return ctx.mask;
  return buildCodeMask(code, { language: ctx && ctx.language });
}

/**
 * 把註解、正則、較長的字串(超過 minStringLength 字元,通常是說明文字或範例程式碼)換成空白,
 * 保留長度與換行;較短的字串(物件鍵名、一般參數)保留。給需要「看程式結構」的跨檔案規則使用。
 */
function blankNonCode(code, mask, minStringLength) {
  if (!mask) return code;
  const min = minStringLength || 40;
  const out = code.split('');
  let i = 0;
  while (i < out.length) {
    if (mask[i] === MASK_CODE) { i++; continue; }
    let j = i;
    while (j < out.length && mask[j] === mask[i]) j++;
    if (mask[i] !== MASK_STRING || j - i > min) {
      for (let k = i; k < j; k++) if (out[k] !== '\n') out[k] = ' ';
    }
    i = j;
  }
  return out.join('');
}

/** 判斷 index 位置是否為真正的程式碼 */
function isCodeAt(mask, index) {
  return !mask || index < 0 || index >= mask.length || mask[index] === MASK_CODE;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { blankNonCode, resolveCodeMask, buildCodeMask, buildJsMask, isCodeAt, languageFromFilename, guessMaskLanguage, MASK_CODE, MASK_STRING, MASK_COMMENT, MASK_REGEX };
}
