/* ============================================================
   Ashiana Sheffield Form Submissions Backend
   ============================================================
   Single-file Express server.
   - Receives Compliments / Comments / Complaints form POSTs
   - Stores each in a SQLite database (one file: ashiana.db)
   - Admin login (bcrypt-hashed password, HTTP-only cookie session)
   - Admin dashboard at /admin (login page) and /dashboard.html
   - CSV export per form
   ============================================================ */

const express      = require('express');
const cookieParser = require('cookie-parser');
const cors         = require('cors');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const Database     = require('better-sqlite3');
const path         = require('path');
const fs           = require('fs');
let   Anthropic    = null;
try   { Anthropic   = require('@anthropic-ai/sdk').default || require('@anthropic-ai/sdk').Anthropic; }
catch { /* SDK absent: /api/ask returns a friendly error */ }

const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-to-a-long-random-string';
const DB_PATH    = process.env.DB_PATH || path.join(__dirname, 'ashiana.db');
const ALLOWED    = (process.env.ALLOWED_ORIGINS || '').split(',').filter(Boolean);
const COOKIE_NAME = 'ashiana_admin';
const ONE_WEEK_MS = 7 * 24 * 60 * 60 * 1000;

// ---------- DB setup ----------
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    form_type TEXT NOT NULL,           -- 'compliment' | 'comment' | 'complaint'
    submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    name TEXT,
    email TEXT,
    telephone TEXT,
    position TEXT,
    stage TEXT,
    message TEXT,
    outcome TEXT,
    ip TEXT,
    user_agent TEXT,
    is_read INTEGER DEFAULT 0,
    is_archived INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS news_posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    linkedin_url TEXT,
    author_name TEXT DEFAULT 'Daljit Kaur',
    author_role TEXT DEFAULT 'Ashiana Chair & Non-Executive Chief Officer (NECO)',
    published_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_published INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_news_posts_published_at ON news_posts(published_at);

  CREATE INDEX IF NOT EXISTS idx_submissions_form_type ON submissions(form_type);
  CREATE INDEX IF NOT EXISTS idx_submissions_submitted_at ON submissions(submitted_at);
`);

// Seed default admin if no admins exist
const adminCount = db.prepare('SELECT COUNT(*) AS n FROM admins').get().n;
if (adminCount === 0) {
  const defaultUser = process.env.ADMIN_USERNAME || 'admin';
  const defaultPass = process.env.ADMIN_PASSWORD || 'changeme123';
  const hash = bcrypt.hashSync(defaultPass, 12);
  db.prepare('INSERT INTO admins (username, password_hash, full_name) VALUES (?, ?, ?)')
    .run(defaultUser, hash, 'Ashiana Admin');
  console.log(`Seeded default admin -> username: ${defaultUser}  password: ${defaultPass}`);
  console.log('CHANGE THE PASSWORD AFTER FIRST LOGIN.');
}

// ---------- App setup ----------
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '200kb' }));
app.use(express.urlencoded({ extended: true, limit: '200kb' }));
app.use(cookieParser());

// CORS for cross-origin form posts from the public website
app.use(cors({
  origin: function (origin, cb) {
    if (!origin) return cb(null, true); // same-origin (admin dashboard)
    if (ALLOWED.length === 0) return cb(null, true);
    if (ALLOWED.includes(origin)) return cb(null, true);
    return cb(new Error('Origin not allowed by CORS: ' + origin));
  },
  credentials: true,
}));

// Static (admin login + dashboard pages)
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Helpers ----------
function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
      || req.socket.remoteAddress || '';
}
function signSession(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}
function requireAuth(req, res, next) {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return res.status(401).json({ ok:false, error:'Not authenticated' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    return next();
  } catch (e) {
    return res.status(401).json({ ok:false, error:'Session expired, please sign in again' });
  }
}
const VALID_FORMS = new Set(['compliment','comment','complaint']);

// ---------- Notification email (via FormSubmit) ----------
// Sends a short notification to the three named recipients each time a new
// submission arrives. We send via FormSubmit so no SMTP credentials are needed.
// PRIMARY is already FormSubmit-confirmed; the other two arrive as CC.
const NOTIFY_PRIMARY = process.env.NOTIFY_PRIMARY || 'D.Kaur@ashianasheffield.org';
const NOTIFY_CC = process.env.NOTIFY_CC || 'nb@icocoassociates.co.uk,sm@icocoassociates.co.uk';
const ADMIN_URL = process.env.ADMIN_URL || 'https://ashiana-backend.onrender.com/admin.html';

const FORM_LABEL = {
  compliment: { article: 'a',  word: 'compliment' },
  comment:    { article: 'a',  word: 'comment'    },
  complaint:  { article: 'a',  word: 'complaint'  },
};

async function notifyByEmail(formType, data) {
  try {
    const lbl = FORM_LABEL[formType] || { article: 'a', word: 'submission' };
    const subject = `New ${lbl.word} received on Ashiana website`;
    const payload = {
      _subject: subject,
      _template: 'table',
      _captcha: 'false',
      _cc: NOTIFY_CC,
      'Form type':     formType,
      'Submitted at':  new Date().toISOString(),
      'Name':          data.name      || '(not given)',
      'Email':         data.email     || '(not given)',
      'Telephone':     data.telephone || '(not given)',
      'Position':      data.position  || '',
      'Stage':         data.stage     || '',
      'Message':       data.message   || '',
      'Outcome wanted':data.outcome   || '',
      'Admin panel':   ADMIN_URL,
      'Action':        `You have received ${lbl.article} new ${lbl.word} on the Ashiana website. Please log in to the admin panel above to view the full submission and respond.`,
    };
    const url = 'https://formsubmit.co/ajax/' + encodeURIComponent(NOTIFY_PRIMARY);
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!r.ok) {
      console.warn('Notification email returned non-OK:', r.status);
    }
  } catch (e) {
    console.error('notifyByEmail failed:', e.message);
  }
}

// ---------- Public endpoints ----------

// POST /api/submit  (called by the website forms)
// Body: form_type, name, email, telephone, position|stage, message, outcome
app.post('/api/submit', (req, res) => {
  const body = req.body || {};
  const formType = (body.form_type || '').toLowerCase();
  if (!VALID_FORMS.has(formType)) {
    return res.status(400).json({ ok:false, error:'Unknown form_type' });
  }
  // Honeypot: any value in _honey means bot submission, silently accept and drop
  if (body._honey) return res.json({ ok:true });

  // Light validation
  if (!body.name || !body.message) {
    return res.status(400).json({ ok:false, error:'Name and message are required' });
  }

  const stmt = db.prepare(`
    INSERT INTO submissions
      (form_type, name, email, telephone, position, stage, message, outcome, ip, user_agent)
    VALUES
      (@form_type, @name, @email, @telephone, @position, @stage, @message, @outcome, @ip, @ua)
  `);
  const info = stmt.run({
    form_type: formType,
    name:      String(body.name      || '').slice(0, 200),
    email:     String(body.email     || '').slice(0, 200),
    telephone: String(body.telephone || '').slice(0, 50),
    position:  String(body.position  || '').slice(0, 100),
    stage:     String(body.stage     || '').slice(0, 100),
    message:   String(body.message   || '').slice(0, 8000),
    outcome:   String(body.outcome   || '').slice(0, 4000),
    ip:        getClientIp(req).slice(0, 64),
    ua:        String(req.headers['user-agent'] || '').slice(0, 400),
  });

  // Fire-and-forget email notification. The visitor's response is not delayed
  // by the FormSubmit round-trip; even if FormSubmit is slow or down, the
  // submission is still safely stored in the database.
  notifyByEmail(formType, body).catch(() => {});

  return res.json({ ok:true, id: info.lastInsertRowid });
});

// ---------- Admin auth ----------

app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ ok:false, error:'Username and password required' });
  }
  const row = db.prepare('SELECT id, username, password_hash, full_name FROM admins WHERE username = ?').get(username);
  if (!row) return res.status(401).json({ ok:false, error:'Invalid credentials' });

  const ok = bcrypt.compareSync(password, row.password_hash);
  if (!ok)  return res.status(401).json({ ok:false, error:'Invalid credentials' });

  const token = signSession({ id: row.id, username: row.username });
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: ONE_WEEK_MS,
  });
  return res.json({ ok:true, username: row.username, fullName: row.full_name });
});

app.post('/api/admin/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  return res.json({ ok:true });
});

app.get('/api/admin/me', requireAuth, (req, res) => {
  res.json({ ok:true, admin: req.admin });
});

app.post('/api/admin/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword || newPassword.length < 8) {
    return res.status(400).json({ ok:false, error:'New password must be at least 8 characters' });
  }
  const row = db.prepare('SELECT password_hash FROM admins WHERE id = ?').get(req.admin.id);
  if (!row) return res.status(404).json({ ok:false, error:'Admin not found' });
  if (!bcrypt.compareSync(currentPassword, row.password_hash)) {
    return res.status(401).json({ ok:false, error:'Current password is incorrect' });
  }
  const newHash = bcrypt.hashSync(newPassword, 12);
  db.prepare('UPDATE admins SET password_hash = ? WHERE id = ?').run(newHash, req.admin.id);
  return res.json({ ok:true });
});

// ---------- Admin: list submissions ----------

// GET /api/admin/submissions?form_type=compliment&q=&page=1&pageSize=25
app.get('/api/admin/submissions', requireAuth, (req, res) => {
  const formType = (req.query.form_type || '').toLowerCase();
  if (!VALID_FORMS.has(formType)) {
    return res.status(400).json({ ok:false, error:'form_type required (compliment|comment|complaint)' });
  }
  const q = (req.query.q || '').trim();
  const page = Math.max(1, parseInt(req.query.page || '1', 10));
  const pageSize = Math.min(100, Math.max(5, parseInt(req.query.pageSize || '25', 10)));
  const offset = (page - 1) * pageSize;

  const where = ['form_type = ?', 'is_archived = 0'];
  const params = [formType];
  if (q) {
    where.push('(name LIKE ? OR email LIKE ? OR telephone LIKE ? OR message LIKE ? OR outcome LIKE ?)');
    const like = '%' + q + '%';
    params.push(like, like, like, like, like);
  }
  const whereSql = 'WHERE ' + where.join(' AND ');

  const total = db.prepare(`SELECT COUNT(*) AS n FROM submissions ${whereSql}`).get(...params).n;
  const rows = db.prepare(`
    SELECT id, form_type, submitted_at, name, email, telephone, position, stage,
           message, outcome, is_read
    FROM submissions
    ${whereSql}
    ORDER BY submitted_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, pageSize, offset);

  return res.json({ ok:true, total, page, pageSize, rows });
});

// Counts for tabs
app.get('/api/admin/counts', requireAuth, (req, res) => {
  const counts = {};
  for (const t of VALID_FORMS) {
    counts[t] = {
      total:  db.prepare("SELECT COUNT(*) AS n FROM submissions WHERE form_type = ? AND is_archived = 0").get(t).n,
      unread: db.prepare("SELECT COUNT(*) AS n FROM submissions WHERE form_type = ? AND is_archived = 0 AND is_read = 0").get(t).n,
    };
  }
  return res.json({ ok:true, counts });
});

// Mark read / archive
app.post('/api/admin/submissions/:id/read',    requireAuth, (req, res) => {
  db.prepare('UPDATE submissions SET is_read = 1 WHERE id = ?').run(req.params.id);
  res.json({ ok:true });
});
app.post('/api/admin/submissions/:id/unread',  requireAuth, (req, res) => {
  db.prepare('UPDATE submissions SET is_read = 0 WHERE id = ?').run(req.params.id);
  res.json({ ok:true });
});
app.post('/api/admin/submissions/:id/archive', requireAuth, (req, res) => {
  db.prepare('UPDATE submissions SET is_archived = 1 WHERE id = ?').run(req.params.id);
  res.json({ ok:true });
});
app.delete('/api/admin/submissions/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM submissions WHERE id = ?').run(req.params.id);
  res.json({ ok:true });
});

// CSV export
app.get('/api/admin/export.csv', requireAuth, (req, res) => {
  const formType = (req.query.form_type || '').toLowerCase();
  if (!VALID_FORMS.has(formType)) {
    return res.status(400).send('form_type required');
  }
  const rows = db.prepare(`
    SELECT id, submitted_at, name, email, telephone, position, stage, message, outcome
    FROM submissions
    WHERE form_type = ? AND is_archived = 0
    ORDER BY submitted_at DESC
  `).all(formType);

  const headers = ['id','submitted_at','name','email','telephone','position','stage','message','outcome'];
  function escapeCsv(v) {
    if (v == null) return '';
    const s = String(v);
    if (s.search(/[",\n]/) === -1) return s;
    return '"' + s.replace(/"/g, '""') + '"';
  }
  const lines = [headers.join(',')];
  for (const row of rows) {
    lines.push(headers.map(h => escapeCsv(row[h])).join(','));
  }
  const csv = '﻿' + lines.join('\n'); // BOM so Excel detects UTF-8

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition',
    `attachment; filename="ashiana-${formType}s-${new Date().toISOString().slice(0,10)}.csv"`);
  return res.send(csv);
});

// ---------- Ask Ashiana: AI chatbot with web search (Anthropic Claude) ----------
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const anthropic = (Anthropic && ANTHROPIC_API_KEY) ? new Anthropic({ apiKey: ANTHROPIC_API_KEY }) : null;

const ASHIANA_SYSTEM_PROMPT = `You are "Ask Ashiana", a friendly assistant on the Ashiana Sheffield website.
Ashiana Sheffield is a UK charity (Registered Charity 1120401) that supports BAMER (Black, Asian, Minority Ethnic, Refugee) women and girls experiencing domestic abuse, forced marriage, FGM, honour-based violence, and human trafficking.

Your job:
1. Answer questions about what Ashiana is currently doing: events, campaigns, services, news, partnerships, fundraising, training, and ongoing work.
2. ALWAYS use the web_search tool to get current information before answering. Search for "Ashiana Sheffield <topic>" or include their site domain.
3. Cite the sources you used at the end of your answer ("Sources:" line with URL list).

SAFEGUARDING RULES (NON-NEGOTIABLE):
- If anyone describes being in immediate danger or unsafe right now, your FIRST line must be:
  "If you are in immediate danger, please call 999 now. If it is not safe to speak, dial 999 and press 55."
- Always include the National Domestic Abuse Helpline (0808 2000 247, free, 24/7) when discussing crisis support.
- Always include Ashiana's helpline (0114 255 5740, Monday to Friday 9am to 5pm) when relevant.
- DO NOT give tactical advice on "how to leave an abuser", financial planning, immigration, or legal action. Direct the person to a specialist worker by submitting the Get Help form on this website, or by calling the helplines.
- DO NOT speculate. If the web search returns nothing relevant, say so honestly and recommend the visitor contact Ashiana directly.
- Never share personal data, addresses of refuges, or any information that could compromise a survivor's safety.

Style:
- Warm, plain English, short paragraphs.
- 150 words maximum unless asked for more detail.
- Never use em dashes.`;

const ASK_PROMPT_MAX_LEN = 800;

// very small per-IP rate limit to protect the API budget
const askBuckets = new Map(); // ip -> { count, resetAt }
function rateLimited(ip) {
  const now = Date.now();
  const WINDOW_MS = 60 * 60 * 1000;     // 1 hour window
  const MAX_PER_WINDOW = 12;            // 12 questions per IP per hour
  const b = askBuckets.get(ip);
  if (!b || b.resetAt < now) { askBuckets.set(ip, { count: 1, resetAt: now + WINDOW_MS }); return false; }
  if (b.count >= MAX_PER_WINDOW) return true;
  b.count += 1;
  return false;
}

app.post('/api/ask', async (req, res) => {
  if (!anthropic) {
    return res.status(503).json({ ok:false, error:'AI service is not configured on this server yet.' });
  }
  const ip = getClientIp(req);
  if (rateLimited(ip)) {
    return res.status(429).json({ ok:false, error:'Too many questions in a short time. Please try again later, or call the Ashiana helpline on 0114 255 5740.' });
  }

  const question = String((req.body && req.body.question) || '').trim().slice(0, ASK_PROMPT_MAX_LEN);
  if (!question) return res.status(400).json({ ok:false, error:'Please type a question.' });

  try {
    const response = await anthropic.messages.create({
      model: process.env.ANTHROPIC_MODEL || 'claude-haiku-4-5-20251001',
      max_tokens: 1024,
      system: ASHIANA_SYSTEM_PROMPT,
      messages: [{ role: 'user', content: question }],
      tools: [{
        type: 'web_search_20250305',
        name: 'web_search',
        max_uses: 3,
      }],
    });

    // Concatenate text blocks, collect citations
    let answer = '';
    const citations = [];
    for (const block of (response.content || [])) {
      if (block.type === 'text') answer += block.text;
      if (block.citations) {
        for (const c of block.citations) {
          if (c.url && !citations.find(x => x.url === c.url)) {
            citations.push({ url: c.url, title: c.title || c.url });
          }
        }
      }
    }
    answer = answer.trim();
    return res.json({ ok:true, answer, citations });
  } catch (err) {
    console.error("Ask endpoint error:", err.message);
    return res.status(500).json({ ok:false, error:"AI is unavailable right now. Please call 0114 255 5740." });
  }
});

// ---------- Public news feed (admin-curated, from DB) ----------
app.get('/api/news', (req, res) => {
  try {
    const rows = db.prepare(
      "SELECT id, title, content, linkedin_url, author_name, author_role, published_at " +
      "FROM news_posts WHERE is_published = 1 ORDER BY published_at DESC LIMIT 6"
    ).all();
    const posts = rows.map(r => ({
      title: r.title,
      link: r.linkedin_url || '',
      pubDate: r.published_at,
      summary: (r.content || '').slice(0, 280),
      content: r.content,
      author: { name: r.author_name, role: r.author_role },
    }));
    return res.json({ ok:true, posts });
  } catch (e) {
    console.error('news fetch failed:', e.message);
    return res.status(500).json({ ok:false, error:'Could not load news.' });
  }
});

// ---------- Admin: news posts CRUD ----------
app.get('/api/admin/news', requireAuth, (req, res) => {
  const rows = db.prepare("SELECT id, title, content, linkedin_url, author_name, author_role, published_at, is_published FROM news_posts ORDER BY published_at DESC").all();
  res.json({ ok:true, posts: rows });
});
app.post('/api/admin/news', requireAuth, (req, res) => {
  const b = req.body || {};
  if (!b.title || !b.content) return res.status(400).json({ ok:false, error:'Title and content are required' });
  const info = db.prepare(
    "INSERT INTO news_posts (title, content, linkedin_url, author_name, author_role, is_published) VALUES (?, ?, ?, ?, ?, ?)"
  ).run(
    String(b.title).slice(0, 300),
    String(b.content).slice(0, 12000),
    String(b.linkedin_url || '').slice(0, 600),
    String(b.author_name || 'Daljit Kaur').slice(0, 120),
    String(b.author_role || 'Ashiana Chair & Non-Executive Chief Officer (NECO)').slice(0, 200),
    b.is_published === false ? 0 : 1
  );
  res.json({ ok:true, id: info.lastInsertRowid });
});
app.put('/api/admin/news/:id', requireAuth, (req, res) => {
  const b = req.body || {};
  if (!b.title || !b.content) return res.status(400).json({ ok:false, error:'Title and content are required' });
  db.prepare(
    "UPDATE news_posts SET title = ?, content = ?, linkedin_url = ?, author_name = ?, author_role = ?, is_published = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
  ).run(
    String(b.title).slice(0, 300),
    String(b.content).slice(0, 12000),
    String(b.linkedin_url || '').slice(0, 600),
    String(b.author_name || 'Daljit Kaur').slice(0, 120),
    String(b.author_role || 'Ashiana Chair & Non-Executive Chief Officer (NECO)').slice(0, 200),
    b.is_published === false ? 0 : 1,
    req.params.id
  );
  res.json({ ok:true });
});
app.delete('/api/admin/news/:id', requireAuth, (req, res) => {
  db.prepare("DELETE FROM news_posts WHERE id = ?").run(req.params.id);
  res.json({ ok:true });
});

// Health check
app.get('/api/health', (req, res) => res.json({ ok:true, time: new Date().toISOString() }));

// Root serves admin login page
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

app.listen(PORT, () => {
  console.log('Ashiana backend listening on port', PORT);
  console.log('DB file:', DB_PATH);
  if (ALLOWED.length) console.log('CORS allowed origins:', ALLOWED);
});
