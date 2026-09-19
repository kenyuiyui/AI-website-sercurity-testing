/**
 * load-ast.js — 讓 Node 驗證腳本使用「與瀏覽器完全相同」的語法分析函式庫(vendor/ 內的檔案)
 * 用法:在任何驗證腳本前 require('./load-ast'),即切換為 AST 版(含 JSX 支援)。
 * 不 require 這個檔案 = 正則保底版(模擬語法分析無法使用的情況)。
 */
const path = require('path');
global.acorn = require(path.join(__dirname, '..', 'vendor', 'acorn.min.js'));
require(path.join(__dirname, '..', 'vendor', 'acorn-jsx.min.js')); // 會設定 globalThis.acornJsx
