/**
 * 測試: M10 insecure-deserialize-detector
 * 執行方式: node test/insecure-deserialize-detector.test.js
 */

const { insecureDeserializeDetector } = require('../src/modules/insecure-deserialize-detector');
const { assertEqual, assertTrue, report } = require('./_test-helpers');

const results = [];

// --- True positive ---
results.push(assertTrue(
  'eval()呼叫應被偵測到',
  insecureDeserializeDetector('const result = eval(userInput);').some(f => f.kind === 'insecure_eval')
));

results.push(assertTrue(
  'pickle.loads()應被偵測到',
  insecureDeserializeDetector('data = pickle.loads(request.body)').some(f => f.kind === 'insecure_pickle')
));

results.push(assertTrue(
  'yaml.load()未加safe應被偵測到',
  insecureDeserializeDetector('config = yaml.load(userFile)').some(f => f.kind === 'insecure_yaml_load')
));

results.push(assertTrue(
  'exec()動態指令應被偵測到',
  insecureDeserializeDetector('exec(userCommand, callback);').some(f => f.kind === 'insecure_exec')
));

results.push(assertTrue(
  'new Function()應被偵測到',
  insecureDeserializeDetector('const fn = new Function(userCode);').some(f => f.kind === 'insecure_function_constructor')
));

// --- True negative ---
results.push(assertEqual(
  'yaml.load()有加SafeLoader不應被偵測到',
  insecureDeserializeDetector('config = yaml.load(userFile, Loader=yaml.SafeLoader)').filter(f => f.kind === 'insecure_yaml_load').length,
  0
));

results.push(assertEqual(
  'yaml.safe_load()不應被偵測到(方法名不同)',
  insecureDeserializeDetector('config = yaml.safe_load(userFile)').filter(f => f.kind === 'insecure_yaml_load').length,
  0
));

results.push(assertEqual(
  'JSON.parse()不應被偵測到',
  insecureDeserializeDetector('const data = JSON.parse(responseText);').length,
  0
));

results.push(assertEqual(
  'execSync()搭配固定字串常值不應被偵測到',
  insecureDeserializeDetector('execSync("ls -la");').filter(f => f.kind === 'insecure_exec').length,
  0
));

// --- tier正確性 ---
results.push((() => {
  const f = insecureDeserializeDetector('const result = eval(userInput);')[0];
  return assertEqual('偵測到的結果 tier 應為 1(高信心度,固定字面樣式比對)', f.tier, 1);
})());

// --- evidence不應過長 ---
results.push((() => {
  const f = insecureDeserializeDetector('const result = eval(userInput);')[0];
  return assertTrue('evidence長度應控制在合理範圍內', f.evidence.length <= 63);
})());

// --- 空輸入 ---
results.push(assertEqual('空字串應回傳空陣列', insecureDeserializeDetector('').length, 0));

report('M10 insecure-deserialize-detector', results);
