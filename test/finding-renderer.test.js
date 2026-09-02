/**
 * 測試: M8 finding-renderer
 * 規格見 docs/modules/MODULE_08_finding-renderer.md
 * 執行方式: node test/finding-renderer.test.js
 *
 * ⚠️ XSS 防護測試是本模組最重要的測試,不可省略。
 */

const { findingRenderer, buildAttackDemoHtml, buildKeyImpactHtml, buildKeyCapabilityHtml, buildCardBody } = require('../src/modules/finding-renderer');
const { assertTrue, assertEqual, report } = require('./_test-helpers');

const results = [];

// --- 空結果 ---
results.push(assertTrue(
  '空結果應顯示「未發現」訊息',
  findingRenderer([], null).includes('未發現已知格式的明文金鑰或基礎設定缺漏')
));

// --- 只有 tier1 ---
results.push((() => {
  const findings = [{ tier: 1, category: '明文金鑰', name: 'OpenAI API Key', kind: 'plain_key', evidence: 'sk-p...cdef [MASKED]' }];
  const html = findingRenderer(findings, null);
  return assertTrue('tier1 結果應顯示「發現」標籤且包含摘要數字', html.includes('高信心度發現 1 項') && html.includes('發現'));
})());

// --- tier1 + tier2 混合 ---
results.push((() => {
  const findings = [
    { tier: 1, category: '明文金鑰', name: 'OpenAI API Key', kind: 'plain_key', evidence: 'sk-p...cdef [MASKED]' },
    { tier: 2, category: '建議人工複查', name: '疑似缺少擁有權驗證', kind: 'possible_idor', evidence: '此函式用參數查詢資料' }
  ];
  const html = findingRenderer(findings, null);
  return assertTrue('混合結果應同時顯示兩種標籤且數量正確', html.includes('高信心度發現 1 項') && html.includes('建議複查 1 項'));
})());

// --- languageCaveat 應顯示 ---
results.push((() => {
  const html = findingRenderer([], '本次貼上的內容含 Python 特徵');
  return assertTrue('languageCaveat 應出現在輸出中', html.includes('Python 特徵'));
})());

// --- ⚠️ XSS 防護測試(重要,不可省略) ---
results.push((() => {
  const maliciousFindings = [{
    tier: 1,
    category: '明文金鑰',
    name: 'OpenAI API Key',
    kind: 'plain_key',
    evidence: '<script>alert(1)</script>'
  }];
  const html = findingRenderer(maliciousFindings, null);
  const containsRawScript = html.includes('<script>alert(1)</script>');
  return assertTrue('evidence 中的 <script> 標籤必須被跳脫,不可原樣出現在輸出 HTML 中', !containsRawScript);
})());

results.push((() => {
  const maliciousFindings = [{
    tier: 2,
    category: '建議人工複查',
    name: '<img src=x onerror=alert(1)>',
    kind: 'possible_idor',
    evidence: 'test'
  }];
  const html = findingRenderer(maliciousFindings, null);
  return assertTrue('name 欄位中的惡意 HTML 屬性必須被跳脫', !html.includes('<img src=x onerror=alert(1)>'));
})());

// --- 未知 kind 值不應拋出例外 ---
results.push((() => {
  const findings = [{ tier: 1, category: '測試', name: '未知種類', kind: 'some_unknown_kind_xyz', evidence: 'test evidence' }];
  let threw = false;
  let html = '';
  try {
    html = findingRenderer(findings, null);
  } catch (e) {
    threw = true;
  }
  return assertTrue('未知 kind 值不應拋出例外,且 evidence 仍應顯示', !threw && html.includes('test evidence'));
})());

// ── buildAttackDemoHtml 專項測試(IDOR攻擊示範視覺化,選用展示,分層fallback) ──

results.push((() => {
  // 有真實 visualData 時,應顯示真實變數名(idParamName、dbCall.object)而非通用文字
  const f = {
    tier: 2, category: '建議人工複查', name: '疑似缺少擁有權驗證', kind: 'possible_idor',
    evidence: 'test',
    visualData: { functionName: 'getOrder', idParamName: 'orderId', dbCall: { object: 'db', method: 'find' } }
  };
  const html = buildAttackDemoHtml(f);
  return assertTrue(
    '有真實visualData時應顯示真實參數名(orderId)與物件名(db)',
    html.includes('orderId') && html.includes('db') && html.includes('查看攻擊示範')
  );
})());

results.push((() => {
  // 沒有 visualData(正則保底版情境)時,應 fallback 成通用抽象示意,不能開天窗
  const f = {
    tier: 2, category: '建議人工複查', name: '疑似缺少擁有權驗證', kind: 'possible_idor',
    evidence: 'test'
    // 沒有 visualData 欄位
  };
  const html = buildAttackDemoHtml(f);
  return assertTrue(
    '無visualData時應fallback為抽象示意(仍要有內容,不能開天窗)',
    html.includes('查看攻擊示範') && html.includes('隨便猜一個編號') && html.includes('自己的資料編號')
  );
})());

results.push((() => {
  // visualData 存在但欄位都是 null(AST版部分抓取失敗的情境),同樣要 fallback
  const f = {
    tier: 2, category: '建議人工複查', name: '疑似缺少擁有權驗證', kind: 'possible_idor',
    evidence: 'test',
    visualData: { functionName: null, idParamName: null, dbCall: null }
  };
  const html = buildAttackDemoHtml(f);
  return assertTrue(
    'visualData欄位全為null時應fallback為抽象示意',
    html.includes('隨便猜一個編號')
  );
})());

results.push((() => {
  // 非 IDOR 的 kind 不應產生攻擊示範區塊(這個視覺化目前限定 possible_idor)
  const f = { tier: 1, category: '明文金鑰', name: 'OpenAI API Key', kind: 'plain_key', evidence: 'test' };
  return assertEqual('非IDOR的kind不應產生攻擊示範內容', buildAttackDemoHtml(f), '');
})());

results.push((() => {
  // XSS防護: visualData裡的欄位名如果帶有惡意內容,必須被escape
  const f = {
    tier: 2, category: '建議人工複查', name: '疑似缺少擁有權驗證', kind: 'possible_idor',
    evidence: 'test',
    visualData: { functionName: 'x', idParamName: '<script>alert(1)</script>', dbCall: { object: 'db', method: 'find' } }
  };
  const html = buildAttackDemoHtml(f);
  return assertTrue(
    'visualData的欄位值含惡意內容時必須被escape,不可原樣出現',
    !html.includes('<script>alert(1)</script>')
  );
})());

results.push((() => {
  // 整合測試: buildCardBody 應該把攻擊示範接進完整卡片內文,且順序在白話說明之後、技術細節之前
  const f = {
    tier: 2, category: '建議人工複查', name: '疑似缺少擁有權驗證', kind: 'possible_idor',
    evidence: 'test evidence content',
    visualData: { functionName: 'getOrder', idParamName: 'id', dbCall: { object: 'db', method: 'find' } }
  };
  const body = buildCardBody(f);
  const plainIdx = body.indexOf('rc-plain');
  const attackIdx = body.indexOf('查看攻擊示範');
  const techIdx = body.indexOf('技術細節');
  return assertTrue(
    'buildCardBody應包含攻擊示範,且順序為: 白話說明 → 攻擊示範 → 技術細節',
    plainIdx >= 0 && attackIdx > plainIdx && techIdx > attackIdx
  );
})());


// ── buildKeyImpactHtml 專項測試(JWT/Supabase金鑰影響範圍視覺化) ──

results.push((() => {
  // service_role: 有 projectRef 時應顯示真實專案名
  const f = {
    tier: 1, category: '明文金鑰', name: 'Supabase service_role', kind: 'supabase_service_role',
    evidence: 'test', visualData: { projectRef: 'xyzcompany', issuer: 'supabase' }
  };
  const html = buildKeyImpactHtml(f);
  return assertTrue(
    'service_role有projectRef時應顯示真實專案名稱',
    html.includes('xyzcompany') && html.includes('查看這組金鑰能做的事') && html.includes('Row Level Security')
  );
})());

results.push((() => {
  // service_role: 沒有 visualData(舊資料/未提供)時應fallback為通用文字,不能開天窗
  const f = { tier: 1, category: '明文金鑰', name: 'Supabase service_role', kind: 'supabase_service_role', evidence: 'test' };
  const html = buildKeyImpactHtml(f);
  return assertTrue(
    'service_role無visualData時應fallback為通用文字仍要有內容',
    html.includes('這個 Supabase 專案') && html.includes('查看這組金鑰能做的事')
  );
})());

results.push((() => {
  // anon: 應顯示「有RLS vs 無RLS」條件對比,而非固定危險論述
  const f = {
    tier: 2, category: '建議人工複查', name: 'Supabase anon', kind: 'supabase_anon',
    evidence: 'test', visualData: { projectRef: 'myproject', issuer: 'supabase' }
  };
  const html = buildKeyImpactHtml(f);
  return assertTrue(
    'anon應顯示RLS條件對比,且含真實專案名',
    html.includes('myproject') && html.includes('已正確設定 RLS') && html.includes('未設定或設定錯誤')
  );
})());

results.push((() => {
  // 非適用kind(如plain_key)不應產生任何內容
  const f = { tier: 1, category: '明文金鑰', name: 'OpenAI API Key', kind: 'plain_key', evidence: 'test' };
  return assertEqual('非supabase相關kind不應產生金鑰影響範圍視覺化', buildKeyImpactHtml(f), '');
})());

results.push((() => {
  // jwt_unknown_role也不應產生(角色都判斷不出來,不該硬做視覺化)
  const f = { tier: 2, category: '建議人工複查', name: '角色未知', kind: 'jwt_unknown_role', evidence: 'test' };
  return assertEqual('jwt_unknown_role不應產生金鑰影響範圍視覺化(角色未知,無法判斷該顯示哪種)', buildKeyImpactHtml(f), '');
})());

results.push((() => {
  // XSS防護: projectRef若含惡意內容必須被escape
  const f = {
    tier: 1, category: '明文金鑰', name: 'x', kind: 'supabase_service_role',
    evidence: 'test', visualData: { projectRef: '<img src=x onerror=alert(1)>', issuer: null }
  };
  const html = buildKeyImpactHtml(f);
  return assertTrue('projectRef含惡意內容時必須被escape', !html.includes('<img src=x onerror=alert(1)>'));
})());

results.push((() => {
  // 整合測試: buildCardBody應正確串接service_role的金鑰影響範圍區塊
  const f = {
    tier: 1, category: '明文金鑰', name: 'Supabase service_role', kind: 'supabase_service_role',
    evidence: 'test', visualData: { projectRef: 'test-proj', issuer: 'supabase' }
  };
  const body = buildCardBody(f);
  return assertTrue('buildCardBody應包含金鑰影響範圍展示', body.includes('查看這組金鑰能做的事'));
})());


// ── buildKeyCapabilityHtml 專項測試(M1一般金鑰能力清單視覺化,純知識庫查表fallback) ──

results.push((() => {
  const f = { tier: 1, category: '明文金鑰', name: 'OpenAI API Key', kind: 'plain_key', evidence: 'test', visualData: { vendor: 'openai' } };
  const html = buildKeyCapabilityHtml(f);
  return assertTrue(
    'OpenAI廠商應顯示對應的能力清單',
    html.includes('查看這組金鑰能做的事') && html.includes('OpenAI') && html.includes('帳戶額度') === false && html.includes('帳戶')
  );
})());

results.push((() => {
  // AWS特殊情況:應顯示條件式措辭,不給固定清單當成確定事實
  const f = { tier: 1, category: '明文金鑰', name: 'AWS Access Key ID', kind: 'plain_key', evidence: 'test', visualData: { vendor: 'aws' } };
  const html = buildKeyCapabilityHtml(f);
  return assertTrue(
    'AWS應顯示條件式措辭(權限取決於IAM policy),且附加額外提醒',
    html.includes('IAM') && html.includes('這組金鑰的實際風險範圍需要另外查證')
  );
})());

results.push((() => {
  // vendor不在知識庫裡(例如未來新增了廠商但還沒補knowledge base)時,不應硬湊內容
  const f = { tier: 1, category: '明文金鑰', name: 'x', kind: 'plain_key', evidence: 'test', visualData: { vendor: 'unknown_vendor_xyz' } };
  return assertEqual('知識庫查無對應廠商時不應硬湊內容,應回傳空字串', buildKeyCapabilityHtml(f), '');
})());

results.push((() => {
  // 沒有visualData(理論上M1一定會附加,但防禦性測試)時不應拋例外
  const f = { tier: 1, category: '明文金鑰', name: 'x', kind: 'plain_key', evidence: 'test' };
  let threw = false;
  let html = '';
  try { html = buildKeyCapabilityHtml(f); } catch (e) { threw = true; }
  return assertTrue('無visualData時不應拋例外,應優雅回傳空字串', !threw && html === '');
})());

results.push((() => {
  // 非plain_key的kind不應產生內容(例如Firebase的firebase_config_exposed)
  const f = { tier: 2, category: '建議人工複查', name: 'Firebase', kind: 'firebase_config_exposed', evidence: 'test' };
  return assertEqual('非plain_key的kind不應產生金鑰能力清單', buildKeyCapabilityHtml(f), '');
})());

results.push((() => {
  // 不應提及具體金額數字(依你的要求,只列權限不估金額)
  const f = { tier: 1, category: '明文金鑰', name: 'x', kind: 'plain_key', evidence: 'test', visualData: { vendor: 'openai' } };
  const html = buildKeyCapabilityHtml(f);
  const hasCurrencyAmount = /[\$＄]\s*\d|NT\$\s*\d|\d+\s*元/.test(html);
  return assertTrue('不應包含具體金額數字宣稱', !hasCurrencyAmount);
})());

results.push((() => {
  // 整合測試:buildCardBody應正確串接plain_key的能力清單
  const f = { tier: 1, category: '明文金鑰', name: 'Anthropic API Key', kind: 'plain_key', evidence: 'test', visualData: { vendor: 'anthropic' } };
  const body = buildCardBody(f);
  return assertTrue('buildCardBody應包含金鑰能力清單展示', body.includes('查看這組金鑰能做的事') && body.includes('Anthropic'));
})());


report('M8 finding-renderer', results);
