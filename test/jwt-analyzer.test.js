/**
 * 測試: M2 jwt-analyzer
 * 規格見 docs/modules/MODULE_02_jwt-analyzer.md
 * 執行方式: node test/jwt-analyzer.test.js
 */

const { jwtAnalyzer } = require('../src/modules/jwt-analyzer');
const { assertEqual, assertTrue, report } = require('./_test-helpers');

function makeFakeJwt(payloadObj) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString('base64url');
  return `${header}.${payload}.fakesignature1234567890abcdefgh`;
}

const results = [];

// --- service_role 應為 tier 1 ---
results.push((() => {
  const jwt = makeFakeJwt({ role: 'service_role' });
  const findings = jwtAnalyzer(`const key = "${jwt}";`);
  const f = findings.find(x => x.kind === 'supabase_service_role');
  return assertTrue('service_role JWT 應產生 tier1/supabase_service_role', !!f && f.tier === 1);
})());

// --- anon 應為 tier 2 ---
results.push((() => {
  const jwt = makeFakeJwt({ role: 'anon' });
  const findings = jwtAnalyzer(`const key = "${jwt}";`);
  const f = findings.find(x => x.kind === 'supabase_anon');
  return assertTrue('anon JWT 應產生 tier2/supabase_anon', !!f && f.tier === 2);
})());

// --- 角色未知應為 tier 2,不可拋出例外 ---
results.push((() => {
  const jwt = makeFakeJwt({ sub: 'user123' }); // 無 role 欄位
  let threw = false;
  let findings = [];
  try {
    findings = jwtAnalyzer(`const key = "${jwt}";`);
  } catch (e) {
    threw = true;
  }
  const f = findings.find(x => x.kind === 'jwt_unknown_role');
  return assertTrue('無 role 欄位應產生 tier2/jwt_unknown_role 且不拋例外', !threw && !!f && f.tier === 2);
})());

// --- 無 JWT 應回傳空陣列 ---
results.push(assertEqual('無 JWT 字串應回傳空陣列', jwtAnalyzer('const x = 1;').length, 0));

// --- evidence 不應含完整明文 JWT ---
results.push((() => {
  const jwt = makeFakeJwt({ role: 'anon' });
  const f = jwtAnalyzer(`const key = "${jwt}";`)[0];
  return assertTrue('evidence 不應包含完整明文 JWT', !f.evidence.includes(jwt));
})());

results.push((() => {
  const jwt = makeFakeJwt({ role: 'service_role', ref: 'xyzcompany', iss: 'supabase' });
  const f = jwtAnalyzer(`const key = "${jwt}";`)[0];
  return assertTrue(
    'service_role帶ref欄位時,visualData應正確萃取projectRef',
    f.visualData && f.visualData.projectRef === 'xyzcompany'
  );
})());

results.push((() => {
  const jwt = makeFakeJwt({ role: 'anon', ref: 'myproject' });
  const f = jwtAnalyzer(`const key = "${jwt}";`)[0];
  return assertTrue(
    'anon角色也應附加visualData',
    f.visualData && f.visualData.projectRef === 'myproject'
  );
})());

results.push((() => {
  const jwt = makeFakeJwt({ role: 'service_role' }); // 沒有ref欄位
  const f = jwtAnalyzer(`const key = "${jwt}";`)[0];
  return assertTrue(
    '沒有ref欄位時,visualData.projectRef應為null(不硬猜)',
    f.visualData && f.visualData.projectRef === null
  );
})());

results.push((() => {
  const jwt = makeFakeJwt({ sub: 'user123' }); // 無role欄位,走jwt_unknown_role分支
  const f = jwtAnalyzer(`const key = "${jwt}";`)[0];
  return assertTrue(
    'jwt_unknown_role不應帶visualData(角色都判斷不出來,不該硬做視覺化)',
    f.visualData === undefined
  );
})());


report('M2 jwt-analyzer', results);
