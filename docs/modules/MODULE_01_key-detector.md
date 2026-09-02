# M1 — key-detector

## 你的任務
實作一個純函式，掃描一段程式碼文字，找出已知格式的明文 API 金鑰（OpenAI、Anthropic、Google/Gemini、Line、AWS 等），回傳結構化的發現清單。**Firebase 設定值不在這個範圍內**，見下方「重要：Firebase 為什麼獨立出去」。

**你不需要看過這個專案的任何其他模組。這份文件是你需要的全部背景。**

## ⚠️ 重要：Firebase 為什麼獨立出去（2026 查證公開文件後的修正）

原本 Firebase 的 `apiKey` 也在 `KEY_RULES` 裡，跟 OpenAI/AWS 等金鑰共用同一套 tier1「明文金鑰外洩」邏輯與文案。**這是不準確的**：Firebase 官方文件明確說明 `apiKey` 只是識別「這是哪個 Firebase 專案」的識別碼，設計上就是要出現在前端程式碼裡，本身外洩不構成風險——真正控制資料存取的是 Firebase Security Rules。

如果把它當成「機密外洩」處理（tier1、要求撤銷重新產生），這個修復指令本身就是錯的、對安全性毫無幫助。因此 Firebase 已經抽出成獨立的 `firebaseConfigDetector` 函式，產生 tier2、`kind: 'firebase_config_exposed'` 的**提醒性質**結果（本身非機密，但要去確認 Security Rules），不再跟真正的機密金鑰混在一起。

**如果你要新增別種金鑰規則，先確認它是不是像 Firebase 這樣「設計上就該公開」的識別碼，不是每種看起來像 API Key 格式的字串都代表機密外洩。**

## 函式簽名

```js
function keyDetector(code) {
  // code: string — 使用者貼上的原始程式碼文字
  // 回傳: Finding[]  (包含真正機密金鑰的結果 + firebaseConfigDetector 的結果)
}

function firebaseConfigDetector(code) {
  // code: string
  // 回傳: Finding[]  (獨立函式,也可單獨呼叫)
}
```

## Finding 物件格式 — 真正機密金鑰（KEY_RULES 命中）

```js
{
  tier: 1,                    // 固定為 1,已知格式的真正機密金鑰屬於高信心度發現
  category: '明文金鑰',
  name: 'OpenAI API Key',     // 依實際比對到的規則名稱而定
  kind: 'plain_key',          // 固定字串,不要自創新值
  evidence: 'sk-p...3456 [MASKED]',   // 見下方「遮罩規則」
  visualData: { vendor: 'openai' }    // 供 M8 視覺化展示查知識庫用,見下方說明
}
```

## Finding 物件格式 — Firebase 設定值（獨立處理）

```js
{
  tier: 2,                            // 固定為 2,提醒性質,不是機密外洩
  category: '建議人工複查',
  name: 'Firebase 設定值（本身非機密，但請確認 Security Rules）',
  kind: 'firebase_config_exposed',    // 固定字串,不與 plain_key 共用
  evidence: '"api…PQR" [MASKED]　— ...'
  // 注意:Firebase 的 Finding 不附加 visualData,M8 沒有對應的視覺化展示
}
```

## 已知規則（真正的機密金鑰）

```js
// vendor 是給 M8 查對應「這組金鑰能做什麼」知識庫用的識別碼(純正則沒有能力
// 從程式碼萃取更多結構化資訊,這是視覺化展示唯一能提供的真實資料)
const KEY_RULES = [
  { name: 'OpenAI API Key', vendor: 'openai', re: /sk-proj-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,}/g },
  { name: 'Anthropic API Key', vendor: 'anthropic', re: /sk-ant-[A-Za-z0-9_-]{20,}/g },
  { name: 'Google / Gemini API Key', vendor: 'google_gemini', re: /AIzaSy[A-Za-z0-9_-]{33}/g },
  { name: 'Line Bot Access Token', vendor: 'line_bot', re: /[A-Za-z0-9+/=]{100,}/g },
  { name: 'AWS Access Key ID', vendor: 'aws', re: /AKIA[0-9A-Z]{16}/g },
];
```

對每一條規則：用 `code.match(rule.re)`，每個 match 都各自產生一個 Finding，並附加 `visualData: { vendor: rule.vendor }`。

## Firebase 規則（獨立）

```js
const FIREBASE_CONFIG_RULE = { name: 'Firebase 設定值', re: /"apiKey"\s*:\s*"[A-Za-z0-9_-]{20,}"/g };
```

## visualData.vendor：供 M8 查詢「這組金鑰能做什麼」知識庫

`vendor` 只是一個識別碼字串（`openai`/`anthropic`/`google_gemini`/`line_bot`/`aws`），實際的「這組金鑰能做的事」內容**不在這個模組裡**，是 M8 的 `KEY_CAPABILITY_KB` 知識庫依這個 vendor 查表產生的固定文字。

**這是 M1 跟 M6(IDOR)/M2(JWT) 視覺化設計上的根本差異**：M1 是純正則，沒有 AST，天生無法從程式碼萃取任何結構化資訊（不像 M6 能解析出函式名/參數名，不像 M2 能解碼 JWT payload）。因此 M1 提供給視覺化的資料，永遠只有「這是哪個廠商」這一項，其餘內容 100% 來自工具內建的知識庫查表，不是從程式碼解析出來的。新增金鑰規則時，如果想要有視覺化效果，要記得：(1) 幫新規則加上 `vendor` 欄位，(2) 到 M8 的 `KEY_CAPABILITY_KB` 補上對應廠商的能力清單，兩邊要同步。

## 遮罩規則（evidence 欄位絕對不可包含完整明文金鑰）

```js
function maskMatch(str) {
  if (str.length <= 8) return '[MASKED]';
  return str.slice(0, 4) + '…' + str.slice(-4) + ' [MASKED]';
}
```

這條規則不可省略——即使是 demo／測試環境，也不能讓完整金鑰字串出現在畫面或任何輸出裡。

## 明確不在你職責範圍內的東西

- JWT 格式的金鑰（Supabase 等）→ 屬於 M2 jwt-analyzer，不要在這裡處理
- 自訂命名猜測式的「疑似密鑰變數」（例如變數名叫 `secretToken` 但格式不固定）→ 屬於 M4 secret-heuristics
- 畫面呈現、白話說明文字、「這組金鑰能做什麼」的具體內容 → 屬於 M8 finding-renderer，你只管偵測、回傳資料、附上 vendor 識別碼

## 測試要求

至少涵蓋：
1. **True positive**：每一種規則都至少一個能命中的範例字串
2. **True negative（防呆）**：常見的佔位字樣不該被抓到，例如 `"your-api-key-here"`、`"sk-xxxxxxxxxxxxxxxxx"`（全部同字元）——目前規則庫**沒有**排除佔位字樣的機制，這是已知限制，寫測試時如果發現誤判，記錄下來但不要擅自加防呆邏輯，回報給負責 orchestrator 的人決定是否要加
3. **邊界情況**：同一段程式碼裡出現多個不同種類的金鑰，應該每個都各自產生一筆 Finding，不遺漏也不重複
4. **Firebase 獨立性**：驗證 Firebase 產生的是 tier2/`firebase_config_exposed`，不是 tier1/`plain_key`，且 category 是「建議人工複查」不是「明文金鑰」
5. **visualData.vendor 正確性**：每種真正機密金鑰的 Finding 都應附上對應的 `vendor` 值
6. **空輸入**：`code = ''` 應回傳空陣列 `[]`

## 對照基準

`reference/index__1_.html` 裡的 `KEY_RULES` 陣列（舊版，Firebase 尚未抽出）已經**不是**目前的行為基準——那份是修正前的版本，僅供歷史對照。目前的正確行為以 `src/modules/key-detector.js` 本身與這份文件為準。
