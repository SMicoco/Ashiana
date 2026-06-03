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

// Health check
app.get('/api/health', (req, res) => res.json({ ok:true, time: new Date().toISOString() }));

// Root: serve admin login page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`Ashiana backend listening on http://localhost:${PORT}`);
  console.log(`DB file: ${DB_PATH}`);
  if (ALLOWED.length) console.log('CORS allowed origins:', ALLOWED);
});
