/**
 * eval-orchestrator.js — 驗證腳本的薄包裝層
 *
 * 掃描流程本體在 ../modules/scan-orchestrator.js,與上線版(assets/app.js)呼叫的是同一份,
 * 這裡只補上 html 欄位,維持 run_*.js 既有的 runScan / runMultiFileScan 介面。
 */

const path = require('path');
const { scanCode, scanFiles, IDOR_AST_DEGRADED_NOTICE } = require(path.join(__dirname, '..', 'modules', 'scan-orchestrator'));
const { findingRenderer } = require(path.join(__dirname, '..', 'modules', 'finding-renderer'));

function runScan(code) {
  const { findings, languageCaveat } = scanCode(code);
  return { findings, languageCaveat, html: findingRenderer(findings, languageCaveat) };
}

function runMultiFileScan(files) {
  const { findings, languageCaveat } = scanFiles(files);
  return { findings, languageCaveat, html: findingRenderer(findings, languageCaveat) };
}

module.exports = { runScan, runMultiFileScan, IDOR_AST_DEGRADED_NOTICE };
