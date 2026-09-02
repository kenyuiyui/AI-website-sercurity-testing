/**
 * 測試: M5 csp-detector
 * 規格見 docs/modules/MODULE_05_csp-detector.md
 * 執行方式: node test/csp-detector.test.js
 */

const { cspDetector } = require('../src/modules/csp-detector');
const { assertEqual, assertTrue, report } = require('./_test-helpers');

const results = [];

// --- HTML 情境: True positive ---
results.push(assertTrue(
  'HTML 無 CSP 應被偵測(tier1/no_csp_html)',
  cspDetector('<!DOCTYPE html><html><head></head></html>').some(f => f.kind === 'no_csp_html' && f.tier === 1)
));

// --- HTML 情境: True negative ---
results.push(assertEqual(
  'HTML 有 CSP meta 標籤不應被偵測',
  cspDetector('<!DOCTYPE html><html><head><meta http-equiv="Content-Security-Policy" content="default-src \'self\'"></head></html>').length,
  0
));

// --- 框架設定檔情境: True positive ---
results.push(assertTrue(
  'Next.js 設定檔無 CSP 應被偵測(tier2/no_csp_config)',
  cspDetector('/** @type {import("next").NextConfig} */\nmodule.exports = { reactStrictMode: true };')
    .some(f => f.kind === 'no_csp_config' && f.tier === 2)
));

// --- 防呆: 既非HTML也非框架設定檔,不該誤報 ---
results.push(assertEqual(
  '普通函式不應觸發任何 CSP Finding',
  cspDetector('function getOrder(req, res) { return db.find(req.params.id); }').length,
  0
));

// --- 空輸入 ---
results.push(assertEqual('空字串應回傳空陣列', cspDetector('').length, 0));

report('M5 csp-detector', results);
