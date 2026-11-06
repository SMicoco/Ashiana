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
const crypto       = require('crypto');
let   helmet       = null;
try   { helmet       = require('helmet'); } catch { /* headers middleware absent: fallback below */ }
let   rateLimit    = null;
try   { rateLimit    = require('express-rate-limit').rateLimit; } catch { /* rate limiting absent: fallback below */ }
let   Anthropic    = null;
try   { Anthropic   = require('@anthropic-ai/sdk').default || require('@anthropic-ai/sdk').Anthropic; }
catch { /* SDK absent: /api/ask returns a friendly error */ }
let   multer       = null;
try   { multer       = require('multer'); }
catch { /* multer absent: CV uploads will be skipped, text-only career forms still work */ }
let   Resend       = null;
try   { Resend       = require('resend').Resend; }
catch { /* SDK absent: notifications will fall back to FormSubmit */ }

const PORT       = process.env.PORT || 3000;
// Never run with a guessable session secret. If none is configured, generate a
// strong random one for this process (sessions reset on restart) and say so.
const JWT_SECRET = (process.env.JWT_SECRET && process.env.JWT_SECRET.length >= 32)
  ? process.env.JWT_SECRET
  : (console.warn('SECURITY: JWT_SECRET missing or too short; using a random per-process secret'), crypto.randomBytes(48).toString('hex'));
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

  CREATE TABLE IF NOT EXISTS donate_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT NOT NULL,              -- 'donate_view' | 'donate_click' | 'give_redirect'
    page TEXT,
    referrer TEXT,
    ip_hash TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_donate_events_created ON donate_events(created_at);

  CREATE INDEX IF NOT EXISTS idx_submissions_form_type ON submissions(form_type);
  CREATE INDEX IF NOT EXISTS idx_submissions_submitted_at ON submissions(submitted_at);
`);

// ---- Career-route migration: ensure career columns exist (safe on re-run) ----
function ensureColumn(table, name, type){
  try {
    const cols = db.prepare("PRAGMA table_info(" + table + ")").all().map(c => c.name);
    if (!cols.includes(name)) {
      db.exec("ALTER TABLE " + table + " ADD COLUMN " + name + " " + type);
    }
  } catch(e) { console.warn('migration skipped for', name, e.message); }
}
ensureColumn('submissions', 'role_applied',   'TEXT');
ensureColumn('submissions', 'organisation',   'TEXT');
ensureColumn('submissions', 'availability',   'TEXT');
ensureColumn('submissions', 'right_to_work',  'TEXT');
ensureColumn('submissions', 'references_text','TEXT');
ensureColumn('submissions', 'where_heard',    'TEXT');
ensureColumn('submissions', 'institution',    'TEXT');
ensureColumn('submissions', 'course',         'TEXT');
ensureColumn('submissions', 'year_of_study',  'TEXT');
ensureColumn('submissions', 'placement_dates','TEXT');
ensureColumn('submissions', 'why_volunteer',  'TEXT');
ensureColumn('submissions', 'skills',         'TEXT');
ensureColumn('submissions', 'linkedin_url',   'TEXT');
ensureColumn('submissions', 'cv_link',        'TEXT');
ensureColumn('submissions', 'cv_filename',    'TEXT');
ensureColumn('submissions', 'cv_storedname',  'TEXT');
ensureColumn('news_posts', 'images', 'TEXT'); // JSON array of {filename, storedname}


// Seed default admin if no admins exist
const adminCount = db.prepare('SELECT COUNT(*) AS n FROM admins').get().n;
if (adminCount === 0) {
  const defaultUser = process.env.ADMIN_USERNAME || 'admin';
  // No weak fallback password: if none is configured, generate one and log it once.
  const defaultPass = process.env.ADMIN_PASSWORD || (function(){
    const p = crypto.randomBytes(12).toString('base64url');
    console.warn('SECURITY: ADMIN_PASSWORD not set; generated initial admin password:', p);
    return p;
  })();
  const hash = bcrypt.hashSync(defaultPass, 12);
  db.prepare('INSERT INTO admins (username, password_hash, full_name) VALUES (?, ?, ?)')
    .run(defaultUser, hash, 'Ashiana Admin');
  console.log(`Seeded default admin -> username: ${defaultUser}  password: ${defaultPass}`);
  console.log('CHANGE THE PASSWORD AFTER FIRST LOGIN.');
}

// ---------- App setup ----------
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

// ---------- Security headers ----------
// The admin pages use inline scripts/styles, so CSP allows 'unsafe-inline' for
// those but blocks everything else: no third-party scripts, no framing, no
// mixed content, no plugins.
const CSP = {
  "default-src": ["'self'"],
  "script-src": ["'self'", "'unsafe-inline'"],
  "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
  "font-src": ["'self'", "https://fonts.gstatic.com", "data:"],
  "img-src": ["'self'", "data:", "blob:"],
  "connect-src": ["'self'"],
  "frame-ancestors": ["'none'"],
  "form-action": ["'self'"],
  "base-uri": ["'self'"],
  "object-src": ["'none'"],
  "upgrade-insecure-requests": [],
};
if (helmet) {
  app.use(helmet({
    contentSecurityPolicy: { directives: CSP },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: 'cross-origin' }, // news images are shown on the public site
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    frameguard: { action: 'deny' },
  }));
} else {
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
  });
}
app.use((req, res, next) => { res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()'); next(); });

// ---------- Rate limiting ----------
// Generous global ceiling per IP, tighter limits on anything that writes or
// authenticates. Limits are per IP (trust proxy is set, so the real client IP
// is used behind Render's load balancer).
function makeLimiter(windowMs, max, message) {
  if (rateLimit) return rateLimit({ windowMs, max, standardHeaders: 'draft-7', legacyHeaders: false, message: { ok:false, error: message } });
  const hits = new Map();
  return (req, res, next) => {
    const ip = getClientIp(req); const now = Date.now();
    const b = hits.get(ip);
    if (!b || b.resetAt < now) { hits.set(ip, { count: 1, resetAt: now + windowMs }); return next(); }
    if (++b.count > max) return res.status(429).json({ ok:false, error: message });
    next();
  };
}
app.use('/api/', makeLimiter(15 * 60 * 1000, 600, 'Too many requests, please try again shortly.'));
const loginLimiter  = makeLimiter(15 * 60 * 1000, 10, 'Too many sign-in attempts. Please wait 15 minutes.');
const submitLimiter = makeLimiter(60 * 60 * 1000, 15, 'Too many submissions from this connection. Please try again later.');
const adminWriteLimiter = makeLimiter(15 * 60 * 1000, 120, 'Too many changes in a short time.');

// ---------- Input hygiene ----------
// Strip control characters and trim; keeps letters in every script intact.
function clean(v, max) {
  return String(v == null ? '' : v).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim().slice(0, max);
}
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;
function looksLikeSpam(text) {
  const links = (String(text || '').match(/https?:\/\//gi) || []).length;
  return links > 3;
}
app.use(express.json({ limit: '200kb' }));
app.use(express.urlencoded({ extended: true, limit: '200kb' }));
app.use(cookieParser());

// CORS for cross-origin form posts from the public website.
// The live site (ashianasheffield.org and any subdomain) and the Netlify
// deployment are always allowed; ALLOWED_ORIGINS can add further origins.
const ALWAYS_ALLOWED_RE = /^https?:\/\/([a-z0-9-]+\.)*(ashianasheffield\.org|ashianasheffield\.netlify\.app|ashiana-backend\.onrender\.com)$/i;
app.use(cors({
  origin: function (origin, cb) {
    if (!origin) return cb(null, true); // same-origin (admin dashboard)
    if (ALLOWED.length === 0) return cb(null, true);
    if (ALLOWED.includes(origin)) return cb(null, true);
    if (ALWAYS_ALLOWED_RE.test(origin)) return cb(null, true);
    // Disallowed origin: respond without CORS headers (browser blocks it)
    // instead of throwing, which previously produced an HTML 500 page.
    console.warn('CORS: origin not allowed:', origin);
    return cb(null, false);
  },
  credentials: true,
}));

// Static (admin login + dashboard pages)
app.use(express.static(path.join(__dirname, 'public')));


// ---- CV uploads setup ----
const UPLOAD_DIR = process.env.UPLOAD_DIR || (DB_PATH.endsWith('.db') ? path.dirname(DB_PATH) + '/cv_uploads' : path.join(__dirname, 'cv_uploads'));
try { fs.mkdirSync(UPLOAD_DIR, { recursive: true }); } catch(e) { console.warn('Could not create UPLOAD_DIR:', e.message); }

const cvUploader = multer ? multer({
  storage: multer.diskStorage({
    destination: function (req, file, cb){ cb(null, UPLOAD_DIR); },
    filename: function (req, file, cb){
      const safe = (file.originalname || 'cv').replace(/[^\w.\-]+/g, '_').slice(-80);
      cb(null, Date.now() + '_' + Math.random().toString(36).slice(2,8) + '_' + safe);
    }
  }),
  limits: { fileSize: 8 * 1024 * 1024 }, // 8 MB max
  fileFilter: function (req, file, cb){
    const ok = /\.(pdf|doc|docx|odt|rtf|txt)$/i.test(file.originalname || '');
    cb(ok ? null : new Error('Unsupported file type'), ok);
  }
}) : null;

// Verify an uploaded file really is what its extension claims (magic bytes),
// so a renamed executable or script can never be stored.
function sniffOk(filePath, kind) {
  let fd; try {
    fd = fs.openSync(filePath, 'r'); const b = Buffer.alloc(12); fs.readSync(fd, b, 0, 12, 0);
    const hex = b.toString('hex');
    if (kind === 'image') return hex.startsWith('ffd8ff') || hex.startsWith('89504e47') || hex.startsWith('47494638') || (hex.startsWith('52494646') && b.toString('ascii', 8, 12) === 'WEBP');
    if (kind === 'doc')   return hex.startsWith('25504446') /*pdf*/ || hex.startsWith('504b0304') /*docx/odt*/ || hex.startsWith('d0cf11e0') /*doc*/ || hex.startsWith('7b5c7274') /*rtf*/;
    return false;
  } catch (e) { return false; } finally { if (fd !== undefined) fs.closeSync(fd); }
}
function rejectBadUpload(file, kind) {
  if (!file) return false;
  const isTxt = /\.txt$/i.test(file.originalname || '');
  if (!isTxt && !sniffOk(file.path, kind)) { try { fs.unlinkSync(file.path); } catch(_){} return true; }
  return false;
}

// ---- News post image uploads ----
const NEWS_IMG_DIR = process.env.NEWS_IMG_DIR || (DB_PATH.endsWith('.db') ? path.dirname(DB_PATH) + '/news_images' : path.join(__dirname, 'news_images'));
try { fs.mkdirSync(NEWS_IMG_DIR, { recursive: true }); } catch(e) { console.warn('Could not create NEWS_IMG_DIR:', e.message); }

const newsImageUploader = multer ? multer({
  storage: multer.diskStorage({
    destination: function (req, file, cb){ cb(null, NEWS_IMG_DIR); },
    filename: function (req, file, cb){
      const safe = (file.originalname || 'img').replace(/[^\w.\-]+/g, '_').slice(-60);
      cb(null, Date.now() + '_' + Math.random().toString(36).slice(2,8) + '_' + safe);
    }
  }),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB max per image
  fileFilter: function (req, file, cb){
    const ok = /\.(jpg|jpeg|png|webp|gif)$/i.test(file.originalname || '');
    cb(ok ? null : new Error('Unsupported image type'), ok);
  }
}) : null;

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
const VALID_FORMS = new Set(['compliment','comment','complaint','career','volunteer','student','training']);

// ---------- Notification email (via FormSubmit) ----------
// Sends a short notification to the three named recipients each time a new
// submission arrives. We send via FormSubmit so no SMTP credentials are needed.
// PRIMARY is already FormSubmit-confirmed; the other two arrive as CC.
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const RESEND_FROM    = process.env.RESEND_FROM    || 'Ashiana Website <onboarding@resend.dev>';
const NOTIFY_RECIPIENTS = (process.env.NOTIFY_RECIPIENTS || 'D.Kaur@ashianasheffield.org,nb@icocoassociates.co.uk,sm@icocoassociates.co.uk').split(',').map(s => s.trim()).filter(Boolean);
const resendClient = (Resend && RESEND_API_KEY) ? new Resend(RESEND_API_KEY) : null;
const NOTIFY_PRIMARY = process.env.NOTIFY_PRIMARY || 'D.Kaur@ashianasheffield.org';
const NOTIFY_CC = process.env.NOTIFY_CC || 'nb@icocoassociates.co.uk,sm@icocoassociates.co.uk';
const ADMIN_URL = process.env.ADMIN_URL || 'https://ashiana-backend.onrender.com/admin.html';

const FORM_LABEL = {
  compliment: { article: 'a',  word: 'compliment' },
  comment:    { article: 'a',  word: 'comment'    },
  complaint:  { article: 'a',  word: 'complaint'  },
  career:     { article: 'a',  word: 'job application' },
  volunteer:  { article: 'a',  word: 'volunteer enquiry' },
  student:    { article: 'a',  word: 'student placement enquiry' },
  training:   { article: 'a',  word: 'training enquiry' },
};

async function notifyByEmail(formType, data) {
  const lbl = FORM_LABEL[formType] || { article: 'a', word: 'submission' };
  const subject = `New ${lbl.word} received on Ashiana website`;

  // Plain text body shared by both transports
  const text = [
    `A new ${lbl.word} was just submitted on the Ashiana Sheffield website.`,
    ``,
    `Name:      ${data.name      || '(not given)'}`,
    `Email:     ${data.email     || '(not given)'}`,
    `Telephone: ${data.telephone || data.phone || '(not given)'}`,
    data.position      ? `Position:  ${data.position}`      : '',
    data.stage         ? `Stage:     ${data.stage}`         : '',
    data.role_applied || data.role || data.role_interest || data.placement_type ? `Role:      ${data.role_applied || data.role || data.role_interest || data.placement_type}` : '',
    data.institution || data.university ? `Institution: ${data.institution || data.university}` : '',
    data.course ? `Course:    ${data.course}` : '',
    data.linkedin_url || data.linkedin ? `LinkedIn:  ${data.linkedin_url || data.linkedin}` : '',
    ``,
    `Message:`,
    `${data.message || data.supporting_statement || data.motivation || data.why_volunteer || '(none)'}`,
    ``,
    `Please log in to the admin panel to view the full submission and respond:`,
    `${ADMIN_URL}`
  ].filter(Boolean).join('\n');

  // Tiny HTML version
  const esc = (v) => String(v == null ? '' : v).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
  const html = `
    <div style="font-family:Inter,Segoe UI,sans-serif;max-width:560px;margin:0 auto;color:#211B1F;line-height:1.55">
      <h2 style="font-family:'Cormorant Garamond',Georgia,serif;color:#7a4f8e;font-weight:500">New ${esc(lbl.word)} received</h2>
      <p>A new ${esc(lbl.word)} has just landed on the Ashiana Sheffield website.</p>
      <table style="border-collapse:collapse;width:100%;font-size:14px;background:#faf6fc;border-radius:10px;overflow:hidden">
        <tr><td style="padding:8px 12px;color:#555;width:120px">Name</td><td style="padding:8px 12px;font-weight:600">${esc(data.name || '(not given)')}</td></tr>
        <tr><td style="padding:8px 12px;color:#555">Email</td><td style="padding:8px 12px">${esc(data.email || '(not given)')}</td></tr>
        <tr><td style="padding:8px 12px;color:#555">Telephone</td><td style="padding:8px 12px">${esc(data.telephone || data.phone || '(not given)')}</td></tr>
        ${data.position ? `<tr><td style="padding:8px 12px;color:#555">Position</td><td style="padding:8px 12px">${esc(data.position)}</td></tr>` : ''}
        ${data.role_applied || data.role || data.role_interest || data.placement_type ? `<tr><td style="padding:8px 12px;color:#555">Role</td><td style="padding:8px 12px">${esc(data.role_applied || data.role || data.role_interest || data.placement_type)}</td></tr>` : ''}
        ${data.linkedin_url || data.linkedin ? `<tr><td style="padding:8px 12px;color:#555">LinkedIn</td><td style="padding:8px 12px"><a href="${esc(data.linkedin_url || data.linkedin)}">${esc(data.linkedin_url || data.linkedin)}</a></td></tr>` : ''}
      </table>
      <h3 style="font-family:'Cormorant Garamond',Georgia,serif;font-weight:500;color:#211B1F;margin-top:24px">Message</h3>
      <div style="white-space:pre-wrap;background:#fff;border:1px solid #E7DEE3;padding:14px 16px;border-radius:10px">${esc(data.message || data.supporting_statement || data.motivation || data.why_volunteer || '(none)')}</div>
      <p style="margin-top:24px"><a href="${esc(ADMIN_URL)}" style="background:#7a4f8e;color:#fff;text-decoration:none;padding:12px 22px;border-radius:10px;font-weight:600;display:inline-block">Open admin dashboard &rarr;</a></p>
      <p style="font-size:.85em;color:#888;margin-top:24px">Sent by the Ashiana Sheffield website backend. Reply directly to the visitor at ${esc(data.email || data.telephone || 'their contact details above')}.</p>
    </div>
  `;

  // Primary path: Resend
  if (resendClient) {
    try {
      const r = await resendClient.emails.send({
        from: RESEND_FROM,
        to: NOTIFY_RECIPIENTS,
        subject,
        text,
        html,
        reply_to: data.email || undefined,
      });
      if (r && r.error) {
        console.warn('Resend returned error:', r.error.message || r.error);
      } else {
        return;
      }
    } catch (e) {
      console.error('Resend send failed:', e.message);
    }
  }

  // Fallback path: FormSubmit (only fires if Resend is not configured or failed)
  try {
    const url = 'https://formsubmit.co/ajax/' + encodeURIComponent(NOTIFY_PRIMARY);
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({
        _subject: subject,
        _template: 'table',
        _captcha: 'false',
        _cc: NOTIFY_CC,
        'Form type':     formType,
        'Submitted at':  new Date().toISOString(),
        'Name':          data.name      || '(not given)',
        'Email':         data.email     || '(not given)',
        'Telephone':     data.telephone || data.phone || '(not given)',
        'Message':       data.message || data.supporting_statement || data.motivation || data.why_volunteer || '',
        'Admin panel':   ADMIN_URL,
      }),
    });
    if (!r.ok) console.warn('FormSubmit fallback returned non-OK:', r.status);
  } catch (e) {
    console.error('FormSubmit fallback also failed:', e.message);
  }
}

// ---------- Public endpoints ----------

// POST /api/submit  (called by the website forms)
// Body: form_type, name, email, telephone, position|stage, message, outcome
app.post('/api/submit', submitLimiter, (req, res) => {
  const body = req.body || {};
  const formType = (body.form_type || '').toLowerCase();
  if (!VALID_FORMS.has(formType)) {
    return res.status(400).json({ ok:false, error:'Unknown form_type' });
  }
  // Honeypot: any value in _honey means bot submission, silently accept and drop
  if (body._honey) return res.json({ ok:true });

  // Validation
  if (!clean(body.name, 200) || !clean(body.message, 8000)) {
    return res.status(400).json({ ok:false, error:'Name and message are required' });
  }
  if (body.email && !EMAIL_RE.test(clean(body.email, 200))) {
    return res.status(400).json({ ok:false, error:'Please enter a valid email address' });
  }
  if (looksLikeSpam(body.message)) return res.json({ ok:true }); // silently drop link-stuffed spam

  const stmt = db.prepare(`
    INSERT INTO submissions
      (form_type, name, email, telephone, position, stage, message, outcome, ip, user_agent)
    VALUES
      (@form_type, @name, @email, @telephone, @position, @stage, @message, @outcome, @ip, @ua)
  `);
  const info = stmt.run({
    form_type: formType,
    name:      clean(body.name, 200),
    email:     clean(body.email, 200),
    telephone: clean(body.telephone, 50),
    position:  clean(body.position, 100),
    stage:     clean(body.stage, 100),
    message:   clean(body.message, 8000),
    outcome:   clean(body.outcome, 4000),
    ip:        getClientIp(req).slice(0, 64),
    ua:        String(req.headers['user-agent'] || '').slice(0, 400),
  });

  // Fire-and-forget email notification. The visitor's response is not delayed
  // by the FormSubmit round-trip; even if FormSubmit is slow or down, the
  // submission is still safely stored in the database.
  notifyByEmail(formType, body).catch(() => {});

  return res.json({ ok:true, id: info.lastInsertRowid });
});


// ---- Career/Volunteer/Student form submit (multipart, with optional CV) ----
const CAREER_FORMS = new Set(['career','volunteer','student']);
const careerSubmitMiddleware = cvUploader ? cvUploader.single('cv') : (req,res,next) => next();

app.post('/api/submit/career', submitLimiter, careerSubmitMiddleware, (req, res) => {
  try {
    const body = req.body || {};
    // Multer turns duplicate field names into arrays; coerce to a single string.
    const rawType = Array.isArray(body.form_type) ? body.form_type[0] : body.form_type;
    const formType = String(rawType || '').toLowerCase();
    if (!CAREER_FORMS.has(formType)) return res.status(400).json({ ok:false, error:'Invalid form_type for this endpoint' });
    if (body._honey) return res.json({ ok:true });
    if (!body.name) return res.status(400).json({ ok:false, error:'Name is required' });

    const file = req.file || null;
    if (rejectBadUpload(file, 'doc')) return res.status(400).json({ ok:false, error:'The uploaded file does not appear to be a valid document.' });
    // Combine experience/languages/hours into the skills column so nothing is dropped
    const skillsParts = [];
    if (body.skills)      skillsParts.push(String(body.skills));
    if (body.experience)  skillsParts.push('Experience:\n' + body.experience);
    if (body.languages)   skillsParts.push('Languages: ' + body.languages);
    if (body.hours)       skillsParts.push('Hours per week: ' + body.hours);
    if (body.placement_type) skillsParts.push('Placement type: ' + body.placement_type);

    const info = db.prepare(`
      INSERT INTO submissions
        (form_type, name, email, telephone, position, stage, message, outcome,
         role_applied, organisation, availability, right_to_work, references_text,
         where_heard, institution, course, year_of_study, placement_dates,
         why_volunteer, skills, linkedin_url, cv_link, cv_filename, cv_storedname,
         ip, user_agent)
      VALUES
        (@form_type, @name, @email, @telephone, @position, @stage, @message, @outcome,
         @role_applied, @organisation, @availability, @right_to_work, @references_text,
         @where_heard, @institution, @course, @year_of_study, @placement_dates,
         @why_volunteer, @skills, @linkedin_url, @cv_link, @cv_filename, @cv_storedname,
         @ip, @ua)
    `).run({
      form_type:     formType,
      name:          String(body.name      || '').slice(0,200),
      email:         String(body.email     || '').slice(0,200),
      telephone:     String(body.telephone || body.phone || '').slice(0,50),
      position:      String(body.position  || '').slice(0,100),
      stage:         String(body.stage     || '').slice(0,100),
      message:       String(body.message   || body.supporting_statement || '').slice(0,8000),
      outcome:       String(body.outcome   || '').slice(0,4000),
      role_applied:  String(body.role_applied || body.role || body.role_interest || body.placement_type || '').slice(0,200),
      organisation:  String(body.organisation || '').slice(0,200),
      availability:  String(body.availability || '').slice(0,200),
      right_to_work: String(body.right_to_work || '').slice(0,40),
      references_text: String(body.references_text || body.references || '').slice(0,2000),
      where_heard:   String(body.where_heard || '').slice(0,200),
      institution:   String(body.institution || body.university || '').slice(0,200),
      course:        String(body.course || '').slice(0,200),
      year_of_study: String(body.year_of_study || '').slice(0,40),
      placement_dates: String(body.placement_dates || body.dates || body.hours_dates || '').slice(0,200),
      why_volunteer: String(body.why_volunteer || body.motivation || '').slice(0,4000),
      skills:        skillsParts.join('\n\n').slice(0,4000),
      linkedin_url:  String(body.linkedin_url || body.linkedin || '').slice(0,400),
      cv_link:       String(body.cv_link || body.cv_url || '').slice(0,600),
      cv_filename:   file ? String(file.originalname).slice(0,200) : '',
      cv_storedname: file ? String(file.filename).slice(0,200) : '',
      ip:            getClientIp(req).slice(0,64),
      ua:            String(req.headers['user-agent'] || '').slice(0,400),
    });

    notifyByEmail(formType, { ...body, name: body.name, message: body.message || body.supporting_statement || body.why_volunteer || '' }).catch(()=>{});
    return res.json({ ok:true, id: info.lastInsertRowid });
  } catch (e) {
    console.error('career submit error:', e.message);
    return res.status(500).json({ ok:false, error:'Could not save your application: ' + e.message });
  }
});

// ---- Admin: download a stored CV ----
app.get('/api/admin/submissions/:id/cv', requireAuth, (req, res) => {
  const row = db.prepare('SELECT cv_filename, cv_storedname FROM submissions WHERE id = ?').get(req.params.id);
  if (!row || !row.cv_storedname) return res.status(404).send('No CV stored for this submission');
  if (!/^[\w.\-]+$/.test(row.cv_storedname)) return res.status(400).send('Bad file reference');
  const filePath = path.join(UPLOAD_DIR, row.cv_storedname);
  if (!filePath.startsWith(UPLOAD_DIR) || !fs.existsSync(filePath)) return res.status(404).send('CV file is missing on disk');
  res.download(filePath, row.cv_filename || row.cv_storedname);
});


// ---------- Admin auth ----------

// Account lockout: 5 failed attempts on a username locks it for 15 minutes,
// independent of IP, so credential-stuffing from many addresses is also stopped.
const loginFailures = new Map(); // username -> { count, lockedUntil }
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), 12);
app.post('/api/admin/login', loginLimiter, (req, res) => {
  const username = clean((req.body || {}).username, 100);
  const password = String((req.body || {}).password || '');
  if (!username || !password || password.length > 200) {
    return res.status(400).json({ ok:false, error:'Username and password required' });
  }
  const f = loginFailures.get(username);
  if (f && f.lockedUntil > Date.now()) {
    return res.status(429).json({ ok:false, error:'Account temporarily locked after repeated failed sign-ins. Try again in 15 minutes.' });
  }
  const row = db.prepare('SELECT id, username, password_hash, full_name FROM admins WHERE username = ?').get(username);
  // Always run a bcrypt comparison so a missing user takes as long as a wrong password.
  const ok = bcrypt.compareSync(password, row ? row.password_hash : DUMMY_HASH) && !!row;
  if (!ok) {
    const rec = loginFailures.get(username) || { count: 0, lockedUntil: 0 };
    rec.count += 1;
    if (rec.count >= 5) { rec.lockedUntil = Date.now() + 15 * 60 * 1000; rec.count = 0; }
    loginFailures.set(username, rec);
    console.warn('AUTH: failed sign-in for', JSON.stringify(username), 'from', getClientIp(req));
    return res.status(401).json({ ok:false, error:'Invalid credentials' });
  }
  loginFailures.delete(username);

  const token = signSession({ id: row.id, username: row.username });
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV !== 'development',
    sameSite: 'strict',
    maxAge: ONE_WEEK_MS,
    path: '/',
  });
  return res.json({ ok:true, username: row.username, fullName: row.full_name });
});

app.post('/api/admin/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME, { path: '/' });
  return res.json({ ok:true });
});

app.get('/api/admin/me', requireAuth, (req, res) => {
  res.json({ ok:true, admin: req.admin });
});

app.post('/api/admin/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword || newPassword.length < 12 || newPassword.length > 200
      || !/[a-z]/.test(newPassword) || !/[A-Z0-9]/.test(newPassword)) {
    return res.status(400).json({ ok:false, error:'New password must be at least 12 characters and mix lower-case with upper-case letters or numbers' });
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
           message, outcome, is_read,
           role_applied, organisation, availability, right_to_work, references_text,
           where_heard, institution, course, year_of_study, placement_dates,
           why_volunteer, skills, linkedin_url, cv_link, cv_filename, cv_storedname
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
    SELECT id, submitted_at, name, email, telephone, position, stage, message, outcome,
           role_applied, organisation, availability, right_to_work, references_text,
           where_heard, institution, course, year_of_study, placement_dates,
           why_volunteer, skills, linkedin_url, cv_link, cv_filename
    FROM submissions
    WHERE form_type = ? AND is_archived = 0
    ORDER BY submitted_at DESC
  `).all(formType);

  const headers = ['id','submitted_at','name','email','telephone','position','stage','message','outcome','role_applied','organisation','availability','right_to_work','references_text','where_heard','institution','course','year_of_study','placement_dates','why_volunteer','skills','linkedin_url','cv_link','cv_filename'];
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

// ---------- Public news feed (admin-curated, from DB; falls back to live web news) ----------

// In-memory cache for the external news fallback so we don't hammer Google News on every request.
let _fallbackNewsCache = { time: 0, items: [] };
const _FALLBACK_CACHE_MS = 15 * 60 * 1000; // 15 minutes
// Neutral, topic-relevant search queries. Rotates each cache cycle so the page stays fresh.
const _FALLBACK_QUERIES = [
  'domestic abuse UK refuge',
  'forced marriage UK',
  'female genital mutilation UK',
  'human trafficking UK women',
  'honour based violence UK',
  'BAMER women UK support',
];

function _stripHtml(s){ return String(s||'').replace(/<[^>]+>/g, '').trim(); }
function _decodeEntities(s){
  s = String(s||'').replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1');
  // Google News double-encodes entities (e.g. "&amp;nbsp;"). Run two passes so the
  // second pass sees freshly-revealed &nbsp; / &lt; etc after &amp; is decoded.
  for (var i = 0; i < 2; i++) {
    s = s
      .replace(/&amp;/g, '&')
      .replace(/&nbsp;/g, ' ')
      .replace(/&hellip;/g, '...')
      .replace(/&mdash;/g, '-')
      .replace(/&ndash;/g, '-')
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&apos;/g, "'")
      .replace(/&#(\d+);/g, function(_, n){ return String.fromCharCode(parseInt(n, 10)); });
  }
  return s.replace(/\s{2,}/g, ' ').trim();
}

async function _fetchGoogleNews(q, maxItems){
  const url = 'https://news.google.com/rss/search?q=' + encodeURIComponent(q) + '&hl=en-GB&gl=GB&ceid=GB:en';
  const res = await fetch(url, { headers: { 'User-Agent': 'AshianaNewsBot/1.0' } });
  if (!res.ok) throw new Error('upstream ' + res.status);
  const xml = await res.text();
  const items = [];
  const itemRegex = /<item>([\s\S]*?)<\/item>/g;
  let m;
  while ((m = itemRegex.exec(xml)) !== null && items.length < maxItems) {
    const block = m[1];
    const titleM = block.match(/<title>([\s\S]*?)<\/title>/);
    const linkM = block.match(/<link>([\s\S]*?)<\/link>/);
    const dateM = block.match(/<pubDate>([\s\S]*?)<\/pubDate>/);
    const descM = block.match(/<description>([\s\S]*?)<\/description>/);
    if (!titleM || !linkM) continue;
    items.push({
      title: _decodeEntities(titleM[1]).slice(0, 200),
      link: _decodeEntities(linkM[1]).trim(),
      pubDate: dateM ? dateM[1].trim() : '',
      summary: _stripHtml(_decodeEntities(descM ? descM[1] : '')).slice(0, 240),
      content: '',
      author: null,
      images: [],
    });
  }
  return items;
}

async function fetchFallbackNews(){
  if (Date.now() - _fallbackNewsCache.time < _FALLBACK_CACHE_MS && _fallbackNewsCache.items.length) {
    return _fallbackNewsCache.items;
  }
  try {
    // Query every topic for RECENT coverage (Google News "when:" operator), merge,
    // de-duplicate and keep the newest six. Falls back to a wider window if the
    // last fortnight is quiet.
    const windows = ['14d', '60d'];
    let merged = [];
    for (const w of windows) {
      const results = await Promise.allSettled(_FALLBACK_QUERIES.map(q => _fetchGoogleNews(q + ' when:' + w, 20)));
      merged = [];
      for (const r of results) if (r.status === 'fulfilled') merged.push(...r.value);
      const seen = new Set();
      merged = merged.filter(it => { const k = it.title.toLowerCase().replace(/\s+/g,' ').slice(0, 80); if (seen.has(k)) return false; seen.add(k); return true; });
      merged = merged.filter(it => Date.parse(it.pubDate));
      // Keep only stories clearly about Ashiana's areas of work.
      const REL = /(domestic (abuse|violence)|abus(e|ive|er)|refuge|forced marriage|female genital|fgm|honou?r[- ]based|trafficking|traffick(ed|ers?)|modern slavery|violence against women|coercive control|survivor|women's aid|safeguarding|asylum|refugee women|bame|bamer|minority ethnic)/i;
      const OFF = /(tate|south sudan|church|football|celebrity|film|tv series|netflix|cricket|rugby)/i;
      merged = merged.filter(it => REL.test(it.title + ' ' + it.summary) && !OFF.test(it.title));
      merged.sort((a, b) => Date.parse(b.pubDate) - Date.parse(a.pubDate));
      if (merged.length >= 6) break;
    }
    const items = merged.slice(0, 6).map((it, i) => Object.assign({ id: 'g' + i }, it));
    if (items.length) _fallbackNewsCache = { time: Date.now(), items };
    return items.length ? items : (_fallbackNewsCache.items || []);
  } catch (e) {
    console.warn('Fallback news fetch failed:', e.message);
    return _fallbackNewsCache.items || [];
  }
}

app.get('/api/news', async (req, res) => {
  try {
    const rows = db.prepare(
      "SELECT id, title, content, linkedin_url, author_name, author_role, published_at, images " +
      "FROM news_posts WHERE is_published = 1 ORDER BY published_at DESC LIMIT 6"
    ).all();
    const posts = rows.map(r => ({
      id: r.id,
      title: r.title,
      link: r.linkedin_url || '',
      pubDate: r.published_at,
      summary: (r.content || '').slice(0, 280),
      content: r.content,
      author: { name: r.author_name, role: r.author_role },
      images: (function(){
        try { return JSON.parse(r.images || '[]').map(im => '/api/news-image/' + im.storedname); }
        catch(e){ return []; }
      })(),
    }));
    if (posts.length === 0) {
      // No admin posts — fall back to live web news, neutral search, cached 30 min.
      const fallback = await fetchFallbackNews();
      return res.json({ ok:true, posts: fallback, source: 'web' });
    }
    return res.json({ ok:true, posts, source: 'admin' });
  } catch (e) {
    console.error('news fetch failed:', e.message);
    return res.status(500).json({ ok:false, error:'Could not load news.' });
  }
});

// Serve news images (public)
app.get('/api/news-image/:name', (req, res) => {
  const name = req.params.name;
  if (!/^[a-z0-9_.\-]+$/i.test(name)) return res.status(400).send('Bad name');
  const filePath = path.join(NEWS_IMG_DIR, name);
  if (!fs.existsSync(filePath)) return res.status(404).send('Not found');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Disposition', 'inline');
  res.sendFile(filePath);
});

// ---------- Admin: news posts CRUD ----------
app.get('/api/admin/news', requireAuth, (req, res) => {
  const rows = db.prepare("SELECT id, title, content, linkedin_url, author_name, author_role, published_at, is_published, images FROM news_posts ORDER BY published_at DESC").all().map(r => {
    let imgs = []; try { imgs = JSON.parse(r.images || '[]'); } catch(_){}
    return Object.assign({}, r, { images: imgs });
  });
  res.json({ ok:true, posts: rows });
});
const newsImagesMiddleware = newsImageUploader ? newsImageUploader.array('images', 6) : (req,res,next) => next();

app.post('/api/admin/news', adminWriteLimiter, requireAuth, newsImagesMiddleware, (req, res) => {
  for (const f of (req.files || [])) { if (rejectBadUpload(f, 'image')) return res.status(400).json({ ok:false, error:'One of the images is not a valid image file.' }); }
  const b = req.body || {};
  if (!b.title || !b.content) return res.status(400).json({ ok:false, error:'Title and content are required' });
  const imageMeta = (req.files || []).map(f => ({
    filename: String(f.originalname).slice(0, 200),
    storedname: String(f.filename).slice(0, 200),
  }));
  const isPublished = (b.is_published === false || b.is_published === 'false' || b.is_published === '0') ? 0 : 1;
  const info = db.prepare(
    "INSERT INTO news_posts (title, content, linkedin_url, author_name, author_role, is_published, images) VALUES (?, ?, ?, ?, ?, ?, ?)"
  ).run(
    String(b.title).slice(0, 300),
    String(b.content).slice(0, 12000),
    String(b.linkedin_url || '').slice(0, 600),
    String(b.author_name || 'Daljit Kaur').slice(0, 120),
    String(b.author_role || 'Ashiana Chair & Non-Executive Chief Officer (NECO)').slice(0, 200),
    isPublished,
    JSON.stringify(imageMeta)
  );
  res.json({ ok:true, id: info.lastInsertRowid, images: imageMeta });
});
app.put('/api/admin/news/:id', requireAuth, newsImagesMiddleware, (req, res) => {
  const b = req.body || {};
  if (!b.title || !b.content) return res.status(400).json({ ok:false, error:'Title and content are required' });
  // Fetch existing image list
  const cur = db.prepare("SELECT images FROM news_posts WHERE id = ?").get(req.params.id);
  let existing = [];
  try { existing = JSON.parse((cur && cur.images) || '[]'); } catch(_){}
  // If client sent keep_images (JSON array of storednames to KEEP), filter existing
  if (typeof b.keep_images === 'string') {
    try {
      const keep = new Set(JSON.parse(b.keep_images));
      existing = existing.filter(im => keep.has(im.storedname));
    } catch(_){}
  }
  // Add new uploads
  const added = (req.files || []).map(f => ({
    filename: String(f.originalname).slice(0, 200),
    storedname: String(f.filename).slice(0, 200),
  }));
  const finalImages = existing.concat(added);

  const isPublished = (b.is_published === false || b.is_published === 'false' || b.is_published === '0') ? 0 : 1;
  db.prepare(
    "UPDATE news_posts SET title = ?, content = ?, linkedin_url = ?, author_name = ?, author_role = ?, is_published = ?, images = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
  ).run(
    String(b.title).slice(0, 300),
    String(b.content).slice(0, 12000),
    String(b.linkedin_url || '').slice(0, 600),
    String(b.author_name || 'Daljit Kaur').slice(0, 120),
    String(b.author_role || 'Ashiana Chair & Non-Executive Chief Officer (NECO)').slice(0, 200),
    isPublished,
    JSON.stringify(finalImages),
    req.params.id
  );
  res.json({ ok:true, images: finalImages });
});
app.delete('/api/admin/news/:id', requireAuth, (req, res) => {
  db.prepare("DELETE FROM news_posts WHERE id = ?").run(req.params.id);
  res.json({ ok:true });
});

// Health check

// ---------- Donation funnel tracking (private) ----------
// The public site reports anonymous events (page view / button click / QR short-link hit).
// Totals are visible only at /stats with the STATS_KEY set in the environment.
const STATS_KEY = process.env.STATS_KEY || '';
const DONATE_EVENTS = new Set(['donate_view','donate_click','give_redirect']);
const trackBuckets = new Map();
app.post('/api/track', (req, res) => {
  try {
    const b = req.body || {};
    const event = String(b.event || '');
    if (!DONATE_EVENTS.has(event)) return res.status(400).json({ ok:false });
    const ip = getClientIp(req);
    const now = Date.now();
    const tb = trackBuckets.get(ip);
    if (tb && tb.resetAt > now && tb.count > 60) return res.json({ ok:true });
    if (!tb || tb.resetAt < now) trackBuckets.set(ip, { count:1, resetAt: now + 3600e3 }); else tb.count++;
    const ipHash = require('crypto').createHash('sha256').update(ip + JWT_SECRET).digest('hex').slice(0, 16);
    db.prepare('INSERT INTO donate_events (event, page, referrer, ip_hash, user_agent) VALUES (?,?,?,?,?)')
      .run(event, String(b.page || '').slice(0, 200), String(b.ref || '').slice(0, 300), ipHash, String(req.headers['user-agent'] || '').slice(0, 300));
    res.json({ ok:true });
  } catch (e) { res.json({ ok:true }); }
});
app.get('/api/stats/donate', (req, res) => {
  const key = String(req.query.key || req.headers['x-stats-key'] || '');
  if (!STATS_KEY || key !== STATS_KEY) return res.status(404).end();
  const one = (sql, ...a) => db.prepare(sql).get(...a);
  const all = (sql, ...a) => db.prepare(sql).all(...a);
  const byEvent = (since) => {
    const rows = all(`SELECT event, COUNT(*) n, COUNT(DISTINCT ip_hash) uniq FROM donate_events WHERE created_at >= datetime('now', ?) GROUP BY event`, since);
    const o = {}; for (const r of rows) o[r.event] = { count: r.n, unique: r.uniq }; return o;
  };
  res.json({
    ok: true,
    generated_at: new Date().toISOString(),
    totals: { all_time: byEvent('-100 years'), last_24h: byEvent('-1 day'), last_7d: byEvent('-7 days'), last_30d: byEvent('-30 days') },
    by_day: all(`SELECT date(created_at) day, event, COUNT(*) n FROM donate_events WHERE created_at >= datetime('now','-30 days') GROUP BY day, event ORDER BY day`),
    by_page: all(`SELECT page, COUNT(*) n FROM donate_events WHERE event='donate_click' GROUP BY page ORDER BY n DESC LIMIT 20`),
    by_referrer: all(`SELECT COALESCE(NULLIF(referrer,''),'(direct / QR)') referrer, COUNT(*) n FROM donate_events WHERE event='give_redirect' GROUP BY referrer ORDER BY n DESC LIMIT 20`),
    first_event: (one(`SELECT MIN(created_at) t FROM donate_events`) || {}).t || null,
  });
});
app.get('/stats', (req, res) => res.sendFile(path.join(__dirname, 'public', 'stats.html')));

app.get('/api/health', (req, res) => res.json({ ok:true, time: new Date().toISOString() }));

// Root serves admin login page
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// Unknown API routes answer in JSON; all errors answer generically (no stack traces).
app.use('/api', (req, res) => res.status(404).json({ ok:false, error:'Not found' }));
app.use((err, req, res, next) => {
  const status = err.status || (err.code === 'LIMIT_FILE_SIZE' ? 413 : 500);
  if (status >= 500) console.error('Unhandled error:', err.message);
  const msg = status === 413 ? (err.code === 'LIMIT_FILE_SIZE' ? 'File too large' : 'Request too large') : (status === 400 ? 'Bad request' : (err.message && /Unsupported|not allowed/i.test(err.message) ? err.message : 'Something went wrong'));
  res.status(status).json({ ok:false, error: msg });
});

app.listen(PORT, () => {
  console.log('Ashiana backend listening on port', PORT);
  console.log('DB file:', DB_PATH);
  if (ALLOWED.length) console.log('CORS allowed origins:', ALLOWED);
});
