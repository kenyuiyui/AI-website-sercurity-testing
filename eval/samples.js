/**
 * 真實世界案例集:模擬 AI 助手(Claude/ChatGPT/Copilot 等)常見產出的問題程式碼樣式,
 * 依據 2026 GenAI Code Security Report、Georgia Tech Vibe Security Radar、
 * Lovable IDOR 事件等公開報告中描述的常見問題類型改寫而成的代表性範例
 * (非真實外洩程式碼逐字複製,是還原該類問題典型寫法的教學範例)
 */

const samples = [
  {
    id: 1,
    category: '硬編碼金鑰(Hardcoded Secrets)',
    description: 'AI生成的Next.js專案,直接在client端元件寫死OpenAI金鑰(常見於快速原型)',
    code: `
'use client';
import { useState } from 'react';

const OPENAI_API_KEY = "sk-proj-a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0";

export default function ChatWidget() {
  const [message, setMessage] = useState('');

  async function sendMessage() {
    const res = await fetch('https://api.openai.com/v1/chat/completions', {
      headers: { Authorization: \`Bearer \${OPENAI_API_KEY}\` },
      method: 'POST',
      body: JSON.stringify({ messages: [{ role: 'user', content: message }] })
    });
    return res.json();
  }

  return <button onClick={sendMessage}>Send</button>;
}
`,
    expectedFindings: ['plain_key']
  },
  {
    id: 2,
    category: 'Broken Access Control / IDOR',
    description: '參照Lovable真實外洩事件模式:任何使用者可讀取他人專案資料,只檢查登入而非擁有權',
    code: `
export async function getProjectData(req, res) {
  const { projectId } = req.params;
  const project = await db.projects.findOne({ id: projectId });
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  res.json(project);
}
`,
    expectedFindings: ['possible_idor']
  },
  {
    id: 3,
    category: 'Broken Access Control / IDOR(箭頭函式版)',
    description: 'AI常用的Express箭頭函式寫法,同樣缺少擁有權驗證',
    code: `
const deleteOrder = async (req, res) => {
  const order = await db.orders.get(req.params.orderId);
  await db.orders.delete(req.params.orderId);
  res.json({ success: true });
};
`,
    expectedFindings: ['possible_idor']
  },
  {
    id: 4,
    category: 'SQL Injection',
    description: 'AI生成的登入功能,常見的字串拼接查詢寫法',
    code: `
function login(username, password) {
  const query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
  return db.query(query);
}
`,
    expectedFindings: ['possible_sql_injection']
  },
  {
    id: 5,
    category: 'SQL Injection(Python版)',
    description: 'Python Flask常見的f-string拼接SQL',
    code: `
@app.route('/user/<user_id>')
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id={user_id}"
    cursor.execute(query)
    return cursor.fetchone()
`,
    expectedFindings: ['possible_sql_injection']
  },
  {
    id: 6,
    category: '弱雜湊演算法',
    description: 'AI生成的密碼儲存邏輯,常見使用MD5(訓練資料裡大量舊教學都這樣寫)',
    code: `
const crypto = require('crypto');

function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

function registerUser(username, password) {
  const hashed = md5(password);
  db.users.insert({ username, password: hashed });
}
`,
    expectedFindings: ['weak_hash']
  },
  {
    id: 7,
    category: 'Supabase service_role金鑰外洩',
    description: 'AI常見誤把service_role金鑰放進前端環境變數的錯誤示範',
    code: `
import { createClient } from '@supabase/supabase-js';

const supabaseUrl = 'https://xyzcompany.supabase.co';
const supabaseKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNjE2MjM5MDIyfQ.abcdefghijklmnopqrstuvwxyz1234567890";

export const supabase = createClient(supabaseUrl, supabaseKey);
`,
    expectedFindings: ['supabase_service_role']
  },
  {
    id: 8,
    category: '不安全反序列化',
    description: 'AI生成的動態配置載入功能,常見用eval處理JSON-like字串',
    code: `
function loadUserPreferences(prefString) {
  const prefs = eval('(' + prefString + ')');
  return prefs;
}
`,
    expectedFindings: ['insecure_eval']
  },
  {
    id: 9,
    category: 'CSP缺失',
    description: 'AI生成的基礎HTML模板,完全沒有安全標頭設定',
    code: `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>My App</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
  <div id="app"></div>
</body>
</html>
`,
    expectedFindings: ['no_csp_html']
  },
  {
    id: 10,
    category: '過度寬鬆權限(IAM/角色) — 刻意放入的「工具涵蓋範圍外」對照組',
    description: 'AI生成的AWS Lambda IAM policy,常見給予過寬的萬用字元權限。這是JSON設定檔,不是程式碼,目前工具完全不涵蓋這類雲端IAM設定檢查,放進來是為了誠實驗證「這類問題工具真的抓不到」,而非遺漏測試',
    code: `
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
`,
    expectedFindings: []
  }
];

module.exports = { samples };
