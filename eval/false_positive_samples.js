/**
 * 誤判率驗證測試集(False Positive Test Set)
 *
 * 目的:這批案例全部都是「真的安全、正確使用防護措施」的程式碼,
 * 用來驗證工具會不會對安全的程式碼誤報。跟 eval/samples.js(驗證有沒有
 * 抓到該抓的問題)是相反方向的驗證,兩者互補才是完整的準確度評估。
 *
 * 設計原則:每個案例都刻意寫得「表面上容易觸發規則」,但實際上是安全的,
 * 這樣才能真正測出規則的邊界夠不夠精確,而不是找一些明顯不會觸發規則的
 * 案例交差(那樣測了等於沒測)。
 */

const falsePositiveSamples = [
  // ── M1: key-detector ──
  {
    id: 'fp-1',
    module: 'M1 key-detector',
    description: '金鑰從環境變數讀取(正確做法),不是寫死的明文字串',
    code: `
const OPENAI_KEY = process.env.OPENAI_API_KEY;
const client = new OpenAI({ apiKey: OPENAI_KEY });
`,
    shouldNotTrigger: ['plain_key']
  },
  {
    id: 'fp-2',
    module: 'M1 key-detector',
    description: '文件/註解裡提到金鑰格式範例,但不是真的金鑰(教學文字)',
    code: `
// 範例:金鑰格式通常是 sk-開頭,請自行到後台申請並填入 .env 檔案
// 例如: OPENAI_API_KEY=sk-your-actual-key-here
console.log('請先設定環境變數');
`,
    shouldNotTrigger: ['plain_key']
  },

  // ── M2: jwt-analyzer ──
  {
    id: 'fp-3',
    module: 'M2 jwt-analyzer',
    description: 'JWT從環境變數讀取,不是寫死的明文字串(格式判斷不受影響,但這是常見安全寫法)',
    code: `
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);
`,
    shouldNotTrigger: ['supabase_service_role', 'supabase_anon', 'jwt_unknown_role']
  },
  {
    id: 'fp-4',
    module: 'M2 jwt-analyzer',
    description: '一段長字串但不是JWT格式(不含兩個點分隔的三段式結構)',
    code: `
const sessionToken = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOP";
`,
    shouldNotTrigger: ['supabase_service_role', 'supabase_anon', 'jwt_unknown_role']
  },

  // ── M3: hash-detector ──
  {
    id: 'fp-5',
    module: 'M3 hash-detector',
    description: '正確使用bcrypt雜湊密碼,不是MD5/SHA1',
    code: `
const bcrypt = require('bcrypt');
async function hashPassword(password) {
  return await bcrypt.hash(password, 12);
}
`,
    shouldNotTrigger: ['weak_hash']
  },
  {
    id: 'fp-6',
    module: 'M3 hash-detector',
    description: 'MD5用於非密碼用途(檔案完整性校驗,這是MD5的合理使用場景)',
    code: `
const crypto = require('crypto');
function getFileChecksum(fileBuffer) {
  return crypto.createHash('md5').update(fileBuffer).digest('hex');
}
`,
    shouldNotTrigger: ['weak_hash']
  },

  // ── M4: secret-heuristics ──
  {
    id: 'fp-7',
    module: 'M4 secret-heuristics',
    description: '變數名含token但值是佔位字樣,不是真的密鑰',
    code: `
const apiToken = "your-token-here";
const secretKey = "<REPLACE_ME>";
`,
    shouldNotTrigger: ['custom_secret_var']
  },
  {
    id: 'fp-8',
    module: 'M4 secret-heuristics',
    description: '環境變數讀取的fallback是合理的預設值(localhost),不是密鑰',
    code: `
const dbHost = process.env.DB_HOST || "localhost";
const dbPort = process.env.DB_PORT || "5432";
`,
    shouldNotTrigger: ['env_fallback']
  },

  // ── M5: csp-detector ──
  {
    id: 'fp-9',
    module: 'M5 csp-detector',
    description: 'HTML頁面已正確設定CSP meta標籤',
    code: `
<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https://cdn.example.com">
  <title>My App</title>
</head>
<body></body>
</html>
`,
    shouldNotTrigger: ['no_csp_html', 'no_csp_config']
  },
  {
    id: 'fp-10',
    module: 'M5 csp-detector',
    description: '單純的JS函式片段,既不是HTML也不是框架設定檔,不該被誤判為缺少CSP',
    code: `
function calculateTotal(items) {
  return items.reduce((sum, item) => sum + item.price, 0);
}
`,
    shouldNotTrigger: ['no_csp_html', 'no_csp_config']
  },

  // ── M6: idor-detector ──
  {
    id: 'fp-11',
    module: 'M6 idor-detector',
    description: '正確做了擁有權比較檢查(owner !== user.id)',
    code: `
async function getOrder(req, res) {
  const order = await db.orders.find(req.params.id);
  if (order.owner !== req.user.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.json(order);
}
`,
    shouldNotTrigger: ['possible_idor']
  },
  {
    id: 'fp-12',
    module: 'M6 idor-detector',
    description: '箭頭函式版本,同樣正確做了擁有權比較(測試AST版邏輯是否也正確放行)',
    code: `
const deleteOrder = async (req, res) => {
  const order = await db.orders.get(req.params.orderId);
  if (order.userId !== req.session.userId) {
    return res.status(403).end();
  }
  await db.orders.delete(req.params.orderId);
  res.json({ success: true });
};
`,
    shouldNotTrigger: ['possible_idor']
  },

  // ── M9: sql-injection-detector ──
  {
    id: 'fp-13',
    module: 'M9 sql-injection-detector',
    description: '正確使用參數化查詢(?佔位符),不是字串拼接',
    code: `
function getUser(userId) {
  return db.query('SELECT * FROM users WHERE id = ?', [userId]);
}
`,
    shouldNotTrigger: ['possible_sql_injection']
  },
  {
    id: 'fp-14',
    module: 'M9 sql-injection-detector',
    description: '使用ORM方法查詢,完全不是手寫SQL字串',
    code: `
async function getUserOrders(userId) {
  return await Order.findAll({ where: { userId: userId } });
}
`,
    shouldNotTrigger: ['possible_sql_injection']
  },

  // ── M10: insecure-deserialize-detector ──
  {
    id: 'fp-15',
    module: 'M10 insecure-deserialize-detector',
    description: '正確使用JSON.parse處理資料,不是eval',
    code: `
function parseUserData(jsonString) {
  return JSON.parse(jsonString);
}
`,
    shouldNotTrigger: ['insecure_eval', 'insecure_pickle', 'insecure_yaml_load', 'insecure_exec', 'insecure_function_constructor']
  },
  {
    id: 'fp-16',
    module: 'M10 insecure-deserialize-detector',
    description: 'Python正確使用yaml.safe_load,不是不安全的yaml.load',
    code: `
import yaml
def load_config(file_path):
    with open(file_path) as f:
        return yaml.safe_load(f)
`,
    shouldNotTrigger: ['insecure_yaml_load']
  },

  // ── 額外邊界案例:同時涉及多個模組的複合正常程式碼 ──
  {
    id: 'fp-17',
    module: '複合案例',
    description: '一段完整的、多處都做對防護措施的典型後端路由程式碼',
    code: `
const bcrypt = require('bcrypt');

async function getUserProfile(req, res) {
  const apiKey = process.env.INTERNAL_API_KEY;
  const profile = await db.query('SELECT * FROM profiles WHERE id = ?', [req.params.id]);
  if (profile.ownerId !== req.user.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.json(profile);
}

async function registerUser(username, password) {
  const hashed = await bcrypt.hash(password, 12);
  return db.users.insert({ username, password: hashed });
}
`,
    shouldNotTrigger: ['plain_key', 'weak_hash', 'possible_sql_injection', 'possible_idor', 'custom_secret_var', 'env_fallback']
  },

  // ── 補強:Python/Django/Flask 真實慣用寫法(依官方文件查證,見 FALSE_POSITIVE_REPORT.md) ──
  {
    id: 'fp-18',
    module: 'M9 sql-injection-detector (Python/Django)',
    description: 'Django官方標準寫法:Model.objects.raw()搭配%s佔位符與params陣列(依Django官方文件查證)',
    code: `
from django.contrib.auth.models import User

def search_users(request):
    last_name = request.GET.get('last_name')
    users = User.objects.raw('SELECT * FROM auth_user WHERE last_name = %s', [last_name])
    return users
`,
    shouldNotTrigger: ['possible_sql_injection']
  },
  {
    id: 'fp-19',
    module: 'M9 sql-injection-detector (Python/cursor)',
    description: 'Django connection.cursor()搭配%s佔位符的參數化查詢(官方推薦的安全寫法)',
    code: `
from django.db import connection

def get_book_price_above(threshold):
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM library_book WHERE price > %s", [threshold])
        return cursor.fetchall()
`,
    shouldNotTrigger: ['possible_sql_injection']
  },
  {
    id: 'fp-20',
    module: 'M1/M4 (Python/Flask)',
    description: 'Flask官方推薦寫法:os.environ.get()讀取SECRET_KEY,無明文fallback(依python-dotenv官方教學查證)',
    code: `
from dotenv import load_dotenv
import os

load_dotenv()
SECRET_KEY = os.environ.get('SECRET_KEY')
DATABASE_URL = os.environ.get('DATABASE_URL')
`,
    shouldNotTrigger: ['plain_key', 'custom_secret_var', 'env_fallback']
  },
  {
    id: 'fp-21',
    module: 'M1 key-detector (Python)',
    description: 'Python用os.environ[...]的强制讀取寫法(缺少值會直接丟例外,這是官方文件建議的"fail fast"作法,不是明文金鑰)',
    code: `
from os import environ
SECRET_KEY = environ["SECRET_KEY"]
SQLALCHEMY_DATABASE_URI = environ["DATABASE_URL"]
`,
    shouldNotTrigger: ['plain_key', 'custom_secret_var']
  },
  {
    id: 'fp-22',
    module: 'M10 insecure-deserialize-detector (Python)',
    description: 'Python正確使用json.loads處理資料,不是pickle或eval',
    code: `
import json

def parse_webhook_payload(raw_body):
    data = json.loads(raw_body)
    return data.get('event_type')
`,
    shouldNotTrigger: ['insecure_eval', 'insecure_pickle', 'insecure_yaml_load']
  },
  {
    id: 'fp-23',
    module: 'M6 idor-detector (Python/Flask)',
    description: 'Flask路由正確做了擁有權比較檢查(Python語法,雖然M6規則主要針對JS設計,測試是否會對Python程式碼誤判)',
    code: `
@app.route('/orders/<order_id>')
def get_order(order_id):
    order = db.orders.find(order_id)
    if order.owner_id != current_user.id:
        abort(403)
    return jsonify(order)
`,
    shouldNotTrigger: ['possible_idor']
  },

  // ── 補強:邊界值測試(規則設計最容易出錯的地方,原本完全沒有涵蓋) ──
  {
    id: 'fp-24',
    module: 'M4 secret-heuristics (邊界值:長度剛好8字元)',
    description: '自訂密鑰變數規則要求值至少8字元,測試剛好卡在門檻的合理短字串是否被錯誤放行判斷影響(這裡故意用不像密鑰的普通字串測試邊界)',
    code: `
const passwordHint = "8888888";
`,
    shouldNotTrigger: ['custom_secret_var']
  },
  {
    id: 'fp-25',
    module: 'M3 hash-detector (邊界值:大小寫混合)',
    description: 'MD5/SHA1規則對大小寫不敏感,測試在安全情境下(不含password/pwd等關鍵字的變數名)是否仍會誤判',
    code: `
const crypto = require('crypto');
function getEtag(content) {
  return crypto.createHash('MD5').update(content).digest('hex');
}
`,
    shouldNotTrigger: ['weak_hash']
  },
  {
    id: 'fp-26',
    module: 'M9 sql-injection-detector (邊界值:SQL關鍵字出現在字串但非查詢語句)',
    description: 'SQL關鍵字(SELECT)出現在一般文字說明字串裡,不是真正的查詢語句拼接',
    code: `
const helpText = "Use SELECT statements carefully" + userNote;
`,
    shouldNotTrigger: ['possible_sql_injection']
  },
  {
    id: 'fp-27',
    module: 'M6 idor-detector (邊界值:函式名與參數名稱不含常見id樣式)',
    description: '函式參數與變數命名不遵循id/userId慣例,但邏輯上仍正確做了擁有權檢查,測試規則命名假設是否過度嚴格導致漏判被誤記成別的問題',
    code: `
function fetchResource(request, response) {
  const item = db.find(request.params.identifier);
  if (item.belongsTo !== request.user.id) {
    return response.status(403).end();
  }
  response.json(item);
}
`,
    shouldNotTrigger: ['possible_idor']
  },
  {
    id: 'fp-28',
    module: 'M4 secret-heuristics (邊界值:URL含token字樣但非密鑰端點)',
    description: '一般公開API文件連結裡含token字樣,不是內部端點URL外洩',
    code: `
const docsLink = "https://api.example.com/docs/how-to-get-a-token";
`,
    shouldNotTrigger: ['endpoint_url', 'custom_secret_var']
  },
  {
    id: 'fp-29',
    module: 'M5 csp-detector (邊界值:含script標籤但非完整HTML文件)',
    description: 'JSX/React元件片段裡出現script字樣相關的變數名,不是完整HTML頁面,不該被CSP規則誤判',
    code: `
function ScriptLoader({ scriptSrc }) {
  return <div data-script={scriptSrc}>Loading...</div>;
}
`,
    shouldNotTrigger: ['no_csp_html', 'no_csp_config']
  },
];

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { falsePositiveSamples };
}
