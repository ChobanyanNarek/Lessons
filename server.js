const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const path    = require('path');
const crypto  = require('crypto');
const multer  = require('multer');

// ── Fail fast if DATABASE_URL is missing ──────────────────────────────────────
if (!process.env.DATABASE_URL) {
  console.error('✗ DATABASE_URL environment variable is not set.');
  console.error('  Go to Render → Web Service → Environment → add DATABASE_URL.');
  process.exit(1);
}
console.log('✓ DATABASE_URL is set:', process.env.DATABASE_URL.replace(/:\/\/.*@/, '://***@'));

const pool    = require('./db');

const app        = express();
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-production';
const SUPER_ADMIN_EMAIL = 'narek.a.chobanyan@gmail.com';

app.use(express.json());
app.use(require('cors')());  // allow GitHub Pages → Render API calls
app.use(express.static(path.join(__dirname, 'public')));

// Uploaded lesson materials (PDFs, Word docs, etc.) are kept in memory just long
// enough to write them into Postgres — nothing is written to local disk, since
// Render's disk is wiped on every redeploy. Postgres storage persists across deploys.
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 15 * 1024 * 1024 } }); // 15MB cap

// ─── MIDDLEWARE ──────────────────────────────────────────────────────────────

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token provided' });
  try {
    const token = header.split(' ')[1];
    req.user = jwt.verify(token, JWT_SECRET);
    trackActiveDay(req.user);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// One row per student per calendar day they use the platform (for "active
// days" leaderboard points). Cached in memory so it's one DB write per day.
const _activeSeen = new Map();
function trackActiveDay(user) {
  if (!user || user.is_admin) return;
  const day = new Date().toISOString().slice(0, 10);
  if (_activeSeen.get(user.id) === day) return;
  _activeSeen.set(user.id, day);
  pool.query('INSERT INTO activity_days (user_id, day) VALUES ($1, $2) ON CONFLICT DO NOTHING', [user.id, day])
    .catch(() => _activeSeen.delete(user.id));
}

function adminOnly(req, res, next) {
  if (!req.user.is_admin) return res.status(403).json({ error: 'Admin access required' });
  next();
}

function superAdminOnly(req, res, next) {
  if (req.user.role !== 'super_admin') return res.status(403).json({ error: 'Super admin access required' });
  next();
}

function slugify(name) {
  const base = String(name || '')
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return base || 'course';
}

// Admins often paste more than a bare URL here — e.g. copying a whole Google
// Meet/Calendar invite block, or just the "meet.google.com/xxx-xxxx-xxx" line
// with no protocol. Pull out the actual link and make sure it has a scheme.
function normalizeVideoCallUrl(raw) {
  const text = String(raw || '').trim();
  if (!text) return '';
  const match = text.match(
    /(https?:\/\/\S+)|((?:[\w-]+\.)?(?:meet\.google\.com|zoom\.us|teams\.microsoft\.com|teams\.live\.com)\S*)/i
  );
  let url = match ? match[0] : text.split(/\s+/)[0];
  url = url.replace(/[),.;]+$/, ''); // trim trailing punctuation from a sentence/paste
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  return url;
}

// ─── COURSES ROUTES ───────────────────────────────────────────────────────────

// GET /api/courses/:slug — public, used to brand the portal for a given course link
// ─── COURSE BRANDING ─────────────────────────────────────────────────────────
const HEX = /^#[0-9a-fA-F]{6}$/;
const BRAND_DEFAULTS = { primary: '#2451D6', accent: '#F2B33D', header: 'light', heading: 'classic', tagline: '' };
function cleanBrand(b) {
  b = b && typeof b === 'object' ? b : {};
  const out = {};
  if (HEX.test(b.primary || '')) out.primary = b.primary.toUpperCase();
  if (HEX.test(b.accent || '')) out.accent = b.accent.toUpperCase();
  if (['light', 'brand'].includes(b.header)) out.header = b.header;
  if (['classic', 'modern'].includes(b.heading)) out.heading = b.heading;
  if (typeof b.tagline === 'string') out.tagline = b.tagline.trim().slice(0, 40);
  return out;
}
function courseOut(row) {
  const o = { id: row.id, slug: row.slug, name: row.name, videocall_url: row.videocall_url };
  o.brand = Object.assign({}, BRAND_DEFAULTS, cleanBrand(row.brand));
  o.logo_url = row.logo_updated ? `/api/course-logo/${row.id}?v=${new Date(row.logo_updated).getTime()}` : null;
  return o;
}
// GET /api/course-logo/:id — public; the logo is shown on the course sign-in page too.
app.get('/api/course-logo/:id', async (req, res) => {
  try {
    const r = await pool.query('SELECT logo, logo_mime FROM courses WHERE id = $1', [req.params.id]);
    if (!r.rows.length || !r.rows[0].logo) return res.status(404).json({ error: 'No logo' });
    res.setHeader('Content-Type', r.rows[0].logo_mime || 'image/png');
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; sandbox");   // uploaded SVGs can't run scripts
    res.send(r.rows[0].logo);
  } catch (e) { console.error('Logo error:', e.message); res.status(500).json({ error: 'Server error' }); }
});
// PUT /api/courses/mine/branding — { primary, accent, header, heading, tagline } (admin, own course)
app.put('/api/courses/mine/branding', auth, adminOnly, async (req, res) => {
  if (!req.user.course_id) return res.status(400).json({ error: 'no-course-assigned' });
  try {
    const brand = req.body && req.body.reset ? {} : cleanBrand(req.body);
    const r = await pool.query('UPDATE courses SET brand = $1 WHERE id = $2 RETURNING id, slug, name, videocall_url, brand, logo_updated',
      [JSON.stringify(brand), req.user.course_id]);
    res.json(courseOut(r.rows[0]));
  } catch (e) { console.error('Branding error:', e.message); res.status(500).json({ error: 'Server error' }); }
});
const LOGO_TYPES = ['image/png', 'image/jpeg', 'image/webp', 'image/svg+xml', 'image/gif'];
app.post('/api/courses/mine/logo', auth, adminOnly, upload.single('file'), async (req, res) => {
  if (!req.user.course_id) return res.status(400).json({ error: 'no-course-assigned' });
  if (!req.file) return res.status(400).json({ error: 'file is required' });
  if (!LOGO_TYPES.includes(req.file.mimetype)) return res.status(400).json({ error: 'Use a PNG, JPG, WEBP or SVG image.' });
  if (req.file.size > 1024 * 1024) return res.status(400).json({ error: 'The logo must be smaller than 1 MB.' });
  try {
    const r = await pool.query(`UPDATE courses SET logo = $1, logo_mime = $2, logo_updated = NOW() WHERE id = $3
       RETURNING id, slug, name, videocall_url, brand, logo_updated`, [req.file.buffer, req.file.mimetype, req.user.course_id]);
    res.json(courseOut(r.rows[0]));
  } catch (e) { console.error('Logo upload error:', e.message); res.status(500).json({ error: 'Server error' }); }
});
app.delete('/api/courses/mine/logo', auth, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(`UPDATE courses SET logo = NULL, logo_mime = NULL, logo_updated = NULL WHERE id = $1
       RETURNING id, slug, name, videocall_url, brand, logo_updated`, [req.user.course_id]);
    res.json(courseOut(r.rows[0]));
  } catch (e) { console.error('Logo delete error:', e.message); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/courses/:slug', async (req, res) => {
  try {
    const r = await pool.query('SELECT id, slug, name, videocall_url, brand, logo_updated FROM courses WHERE slug = $1', [req.params.slug]);
    if (!r.rows.length) return res.status(404).json({ error: 'course-not-found' });
    res.json(courseOut(r.rows[0]));
  } catch (e) {
    console.error('Course fetch error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// PATCH /api/courses/mine — admin renames their own course and/or sets its video
// call link (Zoom/Meet/Teams — any URL works, shown to students on their dashboard).
// The shareable link's slug is regenerated from a new name so the link always
// reflects the course's current name.
app.patch('/api/courses/mine', auth, adminOnly, async (req, res) => {
  const { name, videocall_url } = req.body;
  if (name === undefined && videocall_url === undefined) {
    return res.status(400).json({ error: 'Nothing to update' });
  }
  if (!req.user.course_id) return res.status(400).json({ error: 'no-course-assigned' });
  try {
    const fields = [];
    const values = [];
    let i = 1;
    if (name !== undefined && String(name).trim()) {
      const baseSlug = slugify(name);
      let slug = baseSlug;
      let n = 1;
      let exists = true;
      while (exists) {
        const check = await pool.query('SELECT 1 FROM courses WHERE slug = $1 AND id != $2', [slug, req.user.course_id]);
        exists = check.rows.length > 0;
        if (exists) { n += 1; slug = `${baseSlug}-${n}`; }
      }
      fields.push(`name = $${i++}`); values.push(name);
      fields.push(`slug = $${i++}`); values.push(slug);
    }
    if (videocall_url !== undefined) {
      const normalized = normalizeVideoCallUrl(videocall_url);
      if (normalized && !/^https?:\/\/[^\s]+\.[^\s]+/i.test(normalized)) {
        return res.status(400).json({ error: "That doesn't look like a valid link — please paste the meeting URL." });
      }
      fields.push(`videocall_url = $${i++}`); values.push(normalized || null);
    }
    values.push(req.user.course_id);
    const r = await pool.query(
      `UPDATE courses SET ${fields.join(', ')} WHERE id = $${i} RETURNING id, slug, name, videocall_url`,
      values
    );
    res.json(r.rows[0]);
  } catch (e) {
    console.error('Course update error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── AUTH ROUTES ─────────────────────────────────────────────────────────────

// POST /api/auth/register — new students are created unapproved and cannot log in
// until their course's admin approves them. Requires a course slug so we know
// which course they're joining.
app.post('/api/auth/register', async (req, res) => {
  const { name, email, phone, password, course } = req.body;
  if (!name || !email || !password || !course) {
    return res.status(400).json({ error: 'name, email, password, and course are required' });
  }
  try {
    const courseRes = await pool.query('SELECT id FROM courses WHERE slug = $1', [course]);
    if (!courseRes.rows.length) return res.status(404).json({ error: 'course-not-found' });
    const courseId = courseRes.rows[0].id;

    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (name, email, phone, password_hash, approved, role, course_id)
       VALUES ($1, $2, $3, $4, false, 'student', $5)
       RETURNING id, name, email, phone, is_admin, approved`,
      [name, email, phone || '', hash, courseId]
    );
    notify({ course_id: courseId, audience: 'admin', kind: 'signup', text: `${name} signed up and is waiting for approval.` });
    tgAlert(courseId, 'signups', `🆕 <b>New sign-up</b>\n${tgEsc(name)} (${tgEsc(email)}) is waiting for approval.`);
    // No token is issued — the account is pending admin approval.
    res.status(201).json({ pending: true, user: result.rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'email-already-in-use' });
    console.error('Register error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }
  try {
    const result = await pool.query(
      `SELECT u.*, c.slug AS course_slug, c.name AS course_name, c.videocall_url AS course_videocall_url
       FROM users u LEFT JOIN courses c ON u.course_id = c.id
       WHERE u.email = $1`,
      [email]
    );
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'user-not-found' });
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'wrong-password' });
    if (!user.is_admin && !user.approved) return res.status(403).json({ error: 'account-pending' });
    pool.query('UPDATE users SET last_login = NOW(), last_seen = NOW() WHERE id = $1', [user.id]).catch(() => {});
    const token = jwt.sign(
      { id: user.id, email: user.email, is_admin: user.is_admin, role: user.role, course_id: user.course_id },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({
      token,
      user: {
        id: user.id, name: user.name, email: user.email, phone: user.phone,
        is_admin: user.is_admin, role: user.role,
        course_id: user.course_id, course_slug: user.course_slug, course_name: user.course_name,
        course_videocall_url: user.course_videocall_url
      }
    });
  } catch (e) {
    console.error('Login error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/auth/me  — returns current user + their progress + their course
app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const userRes = await pool.query(
      `SELECT u.id, u.name, u.email, u.phone, u.is_admin, u.role, u.course_id,
              c.slug AS course_slug, c.name AS course_name, c.videocall_url AS course_videocall_url,
              c.brand AS course_brand_raw, c.logo_updated AS course_logo_updated
       FROM users u LEFT JOIN courses c ON u.course_id = c.id
       WHERE u.id = $1`,
      [req.user.id]
    );
    const progressRes = await pool.query(
      `SELECT p.lesson_id, p.answers, p.note, p.cards, f.comment AS feedback, f.rating AS feedback_rating, f.updated_at AS feedback_at
       FROM user_progress p
       LEFT JOIN note_feedback f ON f.user_id = p.user_id AND f.lesson_id = p.lesson_id
       WHERE p.user_id = $1`,
      [req.user.id]
    );
    const user = userRes.rows[0];
    pool.query('UPDATE users SET last_seen = NOW() WHERE id = $1', [req.user.id]).catch(() => {});
    user.progress = progressRes.rows; // array of { lesson_id, answers, note }
    if (user.course_id) {
      const co = courseOut({ id: user.course_id, brand: user.course_brand_raw, logo_updated: user.course_logo_updated });
      user.course_brand = co.brand; user.course_logo_url = co.logo_url;
    }
    delete user.course_brand_raw; delete user.course_logo_updated;
    res.json(user);
  } catch (e) {
    console.error('Me error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Fire-and-forget: a failed notification must never break the action itself.
async function notify({ course_id, user_id = null, audience = 'student', kind, text, lesson_id = null }) {
  try {
    await pool.query(
      `INSERT INTO notifications (course_id, user_id, audience, kind, text, lesson_id) VALUES ($1,$2,$3,$4,$5,$6)`,
      [course_id, user_id, audience, kind, text, lesson_id]
    );
  } catch (e) { console.error('Notify error:', e.message); }
}


// ─── TELEGRAM ALERTS (admin) ─────────────────────────────────────────────────
// Each course can connect its own Telegram bot. The admin creates a bot with
// @BotFather, pastes the token in Settings, sends the bot any message, then
// presses "Connect" — we read getUpdates to learn the chat id. Stored per
// course in settings as tg:<courseId>. The token is never sent back to the
// browser.
const TG_API = process.env.TELEGRAM_API_BASE || 'https://api.telegram.org';
const TG_DEFAULT_EVENTS = { questions: true, notes: true, signups: true, lessons: true };
async function tgGet(courseId) {
  try {
    const r = await pool.query('SELECT value FROM settings WHERE key = $1', ['tg:' + courseId]);
    return r.rows.length ? JSON.parse(r.rows[0].value) : {};
  } catch (e) { return {}; }
}
async function tgSave(courseId, v) {
  await pool.query(`INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2`, ['tg:' + courseId, JSON.stringify(v)]);
}
async function tgCall(token, method, body) {
  const resp = await fetch(`${TG_API}/bot${token}/${method}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}),
    signal: AbortSignal.timeout(10000),
  });
  const data = await resp.json().catch(() => ({}));
  if (!data.ok) { const err = new Error(data.description || `Telegram error ${resp.status}`); err.tg = true; throw err; }
  return data.result;
}
const tgEsc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
function htmlToText(html) {
  return String(html || '')
    .replace(/<(br|\/p|\/div|\/li|\/h[1-6])\s*\/?>/gi, '\n').replace(/<li[^>]*>/gi, '• ')
    .replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&')
    .replace(/[ \t]+/g, ' ').replace(/\n\s*\n+/g, '\n').trim();
}
const clip = (s, n) => (s.length > n ? s.slice(0, n - 1).trimEnd() + '…' : s);
// Fire-and-forget: never let Telegram problems affect the student's request.
function tgAlert(courseId, event, html, opts = {}) {
  (async () => {
    const cfg = await tgGet(courseId);
    if (!cfg.token || !cfg.chat_id) return;
    const ev = Object.assign({}, TG_DEFAULT_EVENTS, cfg.events || {});
    if (!ev[event]) return;
    const body = { chat_id: cfg.chat_id, text: html, parse_mode: 'HTML', disable_web_page_preview: true };
    if (opts.questionId) {
      // Questions get action buttons and can be answered by replying.
      if (cfg.webhook_ok) body.text += '\n\n💬 <i>Reply to this message to answer.</i>';
      body.reply_markup = tgQuestionKeyboard(cfg, opts.questionId, false);
    } else if (cfg.app_url) {
      body.text += `\n\n<a href="${tgEsc(cfg.app_url)}">Open admin console</a>`;
    }
    const msg = await tgCall(cfg.token, 'sendMessage', body);
    if (opts.questionId && msg && msg.message_id) {
      await pool.query(`INSERT INTO tg_question_msgs (course_id, chat_id, message_id, question_id) VALUES ($1,$2,$3,$4)
                        ON CONFLICT DO NOTHING`, [courseId, cfg.chat_id, msg.message_id, opts.questionId]);
    }
  })().catch(e => console.error('Telegram alert error:', e.message));
}
function tgQuestionKeyboard(cfg, questionId, closed) {
  const row = [closed ? { text: '↩️ Reopen', callback_data: 'reopen:' + questionId } : { text: '✅ Close question', callback_data: 'close:' + questionId }];
  if (cfg.app_url && /^https:\/\//.test(cfg.app_url)) row.push({ text: 'Open in app', url: cfg.app_url });
  return { inline_keyboard: [row] };
}
// Webhook: Telegram pushes the admin's replies and button taps to us.
function tgServerOrigin(req) {
  const proto = String(req.headers['x-forwarded-proto'] || req.protocol || 'https').split(',')[0].trim();
  return `${proto}://${req.get('host')}`;
}
async function tgEnableWebhook(courseId, cfg, origin) {
  if (!cfg.token || !cfg.chat_id || !origin) return cfg;
  cfg.wh_secret = cfg.wh_secret || crypto.randomBytes(24).toString('hex');
  const url = `${origin.replace(/\/$/, '')}/api/telegram/webhook/${courseId}`;
  try {
    await tgCall(cfg.token, 'setWebhook', { url, secret_token: cfg.wh_secret, allowed_updates: ['message', 'callback_query'] });
    cfg.webhook_ok = true; cfg.wh_url = url;
  } catch (e) {
    console.error('Telegram setWebhook error:', e.message);
    cfg.webhook_ok = false; delete cfg.wh_url;
  }
  await tgSave(courseId, cfg);
  return cfg;
}
// On boot, make sure every connected course's webhook points at this server.
async function tgRefreshWebhooks(origin) {
  const r = await pool.query(`SELECT key FROM settings WHERE key LIKE 'tg:%'`);
  for (const row of r.rows) {
    const courseId = Number(row.key.slice(3)); const cfg = await tgGet(courseId);
    if (cfg.token && cfg.chat_id && cfg.wh_url !== `${origin.replace(/\/$/, '')}/api/telegram/webhook/${courseId}`) await tgEnableWebhook(courseId, cfg, origin);
  }
}
// Shared by the admin API and Telegram replies.
async function answerQuestionCore(courseId, questionId, answerText) {
  const answer = String(answerText || '').trim().slice(0, 8000);
  if (!answer) return null;
  const r = await pool.query(
    `UPDATE lesson_questions SET answer = $1, answered_at = NOW()
      WHERE id = $2 AND course_id = $3
      RETURNING id, lesson_id, user_id, question, answer, answered_at, closed_at, created_at`,
    [answer, questionId, courseId]);
  if (!r.rows.length) return null;
  const q = r.rows[0];
  const l = await pool.query('SELECT title FROM lessons WHERE id = $1', [q.lesson_id]);
  notify({ course_id: courseId, user_id: q.user_id, kind: 'answer', lesson_id: q.lesson_id,
           text: `Your instructor answered your question about "${l.rows[0] ? l.rows[0].title : 'a lesson'}".` });
  return q;
}
async function closeQuestionCore(courseId, questionId, closed) {
  const r = await pool.query(
    `UPDATE lesson_questions SET closed_at = ${closed ? 'NOW()' : 'NULL'}
      WHERE id = $1 AND course_id = $2
      RETURNING id, lesson_id, user_id, question, answer, answered_at, closed_at, created_at`,
    [questionId, courseId]);
  return r.rows[0] || null;
}
// Notes are saved many times while a student works, so only alert once per
// student+lesson per window.
const TG_NOTE_WINDOW_MS = 20 * 60 * 1000;
const tgNoteSent = new Map();
function tgNoteThrottled(key) {
  const now = Date.now(), last = tgNoteSent.get(key) || 0;
  if (now - last < TG_NOTE_WINDOW_MS) return true;
  tgNoteSent.set(key, now);
  if (tgNoteSent.size > 5000) for (const [k, t] of tgNoteSent) if (now - t > TG_NOTE_WINDOW_MS) tgNoteSent.delete(k);
  return false;
}
async function tgStudentLesson(userId, lessonId) {
  const r = await pool.query(
    `SELECT u.name, u.email, u.course_id, u.is_admin, l.title FROM users u
       LEFT JOIN lessons l ON l.id = $2 AND l.course_id = u.course_id WHERE u.id = $1`, [userId, lessonId]);
  return r.rows[0] || null;
}

// ─── SCHEDULED LESSON OPENING ────────────────────────────────────────────────
// Opens every lesson whose open_at has passed. The UPDATE … RETURNING is
// atomic, so concurrent calls (timer + page load) never notify twice. Runs on
// a timer and also on every lessons fetch, so a sleeping free-tier server
// still opens overdue lessons the moment anyone visits.
async function openDueLessons() {
  const r = await pool.query(
    `UPDATE lessons SET status = 'open', open_at = NULL, opened_at = NOW()
      WHERE status <> 'open' AND open_at IS NOT NULL AND open_at <= NOW()
      RETURNING id, course_id, title`);
  for (const l of r.rows) {
    notify({ course_id: l.course_id, kind: 'lesson', lesson_id: l.id, text: `New lesson opened: ${l.title}` });
    lbSettings(l.course_id).then(st => { if (st.enabled && st.mode === 'lesson') return currentLeaderboard(l.course_id, { force: true }); }).catch(() => {});
    tgAlert(l.course_id, 'lessons', `🗓 <b>Lesson opened on schedule</b>\n📘 ${tgEsc(l.title)}\nStudents have been notified.`);
  }
  return r.rows;
}
setInterval(() => { openDueLessons().catch(e => console.error('Auto-open error:', e.message)); }, 60 * 1000);

// ─── LESSONS ROUTES ──────────────────────────────────────────────────────────

// GET /api/version — deploy verification marker
app.get('/api/version', (req, res) => {
  res.json({ version: 'multi-course-v1', deployedAt: '2026-08-07T00:00:00Z' });
});

// GET /api/lessons?course=SLUG  — public, no auth needed
app.get('/api/lessons', async (req, res) => {
  const { course } = req.query;
  if (!course) return res.status(400).json({ error: 'course query param is required' });
  try {
    const courseRes = await pool.query('SELECT id FROM courses WHERE slug = $1', [course]);
    if (!courseRes.rows.length) return res.status(404).json({ error: 'course-not-found' });
    await openDueLessons().catch(e => console.error('Auto-open error:', e.message));
    const result = await pool.query(
      'SELECT * FROM lessons WHERE course_id = $1 ORDER BY sort_order ASC NULLS LAST, id ASC',
      [courseRes.rows[0].id]
    );
    res.json(result.rows);
  } catch (e) {
    console.error('Lessons list error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/lessons  — admin only, created under the admin's own course
app.post('/api/lessons', auth, adminOnly, async (req, res) => {
  const { title, blurb, status, quiz, slides, quiz_mandatory } = req.body;
  if (!title) return res.status(400).json({ error: 'title is required' });
  if (!req.user.course_id) return res.status(400).json({ error: 'no-course-assigned' });
  try {
    // New lessons land at the end of the manual order by default — the admin
    // can move them elsewhere afterwards via sort_order.
    const maxOrder = await pool.query(
      'SELECT COALESCE(MAX(sort_order), 0) AS max FROM lessons WHERE course_id = $1',
      [req.user.course_id]
    );
    const nextOrder = Number(maxOrder.rows[0].max) + 1;
    const result = await pool.query(
      `INSERT INTO lessons (title, blurb, status, quiz, slides, course_id, sort_order, quiz_mandatory)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [title, blurb || '', status || 'draft', JSON.stringify(quiz || []), JSON.stringify(slides || []), req.user.course_id, nextOrder, quiz_mandatory === false ? false : true]
    );
    res.status(201).json(result.rows[0]);
  } catch (e) {
    console.error('Create lesson error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// PATCH /api/lessons/:id  — admin only, must own the lesson's course
app.patch('/api/lessons/:id', auth, adminOnly, async (req, res) => {
  const { title, blurb, status, quiz, slides, sort_order, quiz_mandatory, flashcards, open_at } = req.body;
  const { id } = req.params;
  try {
    const existing = await pool.query('SELECT course_id, status, title FROM lessons WHERE id = $1', [id]);
    if (!existing.rows.length) return res.status(404).json({ error: 'Lesson not found' });
    if (existing.rows[0].course_id !== req.user.course_id) return res.status(403).json({ error: 'Forbidden' });

    const fields = [];
    const values = [];
    let i = 1;
    if (title   !== undefined) { fields.push(`title  = $${i++}`); values.push(title); }
    if (blurb   !== undefined) { fields.push(`blurb  = $${i++}`); values.push(blurb); }
    if (status  !== undefined) { fields.push(`status = $${i++}`); values.push(status); }
    if (status === 'open' && existing.rows[0].status !== 'open') { fields.push('open_at = NULL', 'opened_at = NOW()'); }
    else if (open_at !== undefined) {
      if (open_at === null || open_at === '') { fields.push('open_at = NULL'); }
      else {
        const d = new Date(open_at);
        if (isNaN(d.getTime())) return res.status(400).json({ error: 'Invalid date' });
        fields.push(`open_at = $${i++}`); values.push(d.toISOString());
      }
    }
    if (quiz    !== undefined) { fields.push(`quiz   = $${i++}`); values.push(JSON.stringify(quiz)); }
    if (slides  !== undefined) { fields.push(`slides = $${i++}`); values.push(JSON.stringify(slides)); }
    if (flashcards !== undefined) {
      const clean = (Array.isArray(flashcards) ? flashcards : []).slice(0, 300)
        .map(c => ({ term: String((c && c.term) || '').slice(0, 300), def: String((c && c.def) || '').slice(0, 2000) }));
      fields.push(`flashcards = $${i++}`); values.push(JSON.stringify(clean));
    }
    if (quiz_mandatory !== undefined) { fields.push(`quiz_mandatory = $${i++}`); values.push(!!quiz_mandatory); }
    if (sort_order !== undefined) {
      const n = parseInt(sort_order, 10);
      if (!Number.isFinite(n)) return res.status(400).json({ error: 'sort_order must be a number' });
      fields.push(`sort_order = $${i++}`); values.push(n);
    }
    if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });
    values.push(id);
    const result = await pool.query(
      `UPDATE lessons SET ${fields.join(', ')} WHERE id = $${i} RETURNING *`,
      values
    );
    if (status === 'open' && existing.rows[0].status !== 'open') {
      lbSettings(req.user.course_id).then(st => { if (st.enabled && st.mode === 'lesson') return currentLeaderboard(req.user.course_id, { force: true }); }).catch(() => {});
      notify({ course_id: req.user.course_id, kind: 'lesson', lesson_id: Number(id), text: `New lesson opened: ${result.rows[0].title}` });
    }
    res.json(result.rows[0]);
  } catch (e) {
    console.error('Update lesson error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/lessons/:id  — admin only, must own the lesson's course
app.delete('/api/lessons/:id', auth, adminOnly, async (req, res) => {
  try {
    const existing = await pool.query('SELECT course_id FROM lessons WHERE id = $1', [req.params.id]);
    if (!existing.rows.length) return res.status(404).json({ error: 'Lesson not found' });
    if (existing.rows[0].course_id !== req.user.course_id) return res.status(403).json({ error: 'Forbidden' });
    await pool.query('DELETE FROM lessons WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error('Delete lesson error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── LESSON FILES (uploaded materials) ───────────────────────────────────────
// Files are stored as bytes directly in Postgres (not on disk) so they survive
// Render redeploys, which wipe local disk every time.

// POST /api/lessons/:id/files — admin only, uploads a file for a lesson (max 15MB)
app.post('/api/lessons/:id/files', auth, adminOnly, upload.single('file'), async (req, res) => {
  const { id } = req.params;
  if (!req.file) return res.status(400).json({ error: 'file is required' });
  try {
    const existing = await pool.query('SELECT course_id FROM lessons WHERE id = $1', [id]);
    if (!existing.rows.length) return res.status(404).json({ error: 'Lesson not found' });
    if (existing.rows[0].course_id !== req.user.course_id) return res.status(403).json({ error: 'Forbidden' });

    const result = await pool.query(
      `INSERT INTO lesson_files (lesson_id, name, mimetype, data)
       VALUES ($1, $2, $3, $4)
       RETURNING id, name, mimetype, octet_length(data) AS size`,
      [id, req.file.originalname, req.file.mimetype || 'application/octet-stream', req.file.buffer]
    );
    res.status(201).json(result.rows[0]);
  } catch (e) {
    console.error('File upload error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/files/:fileId — public, streams the file back with a download or
// inline disposition (?disposition=inline lets PDFs open in-browser for "Open").
app.get('/api/files/:fileId', async (req, res) => {
  try {
    const result = await pool.query('SELECT name, mimetype, data FROM lesson_files WHERE id = $1', [req.params.fileId]);
    if (!result.rows.length) return res.status(404).json({ error: 'File not found' });
    const file = result.rows[0];
    // Lesson materials are view-only: always served inline, never as a download.
    const disposition = 'inline';
    const safeName = ensureExtension((file.name || 'download').replace(/[\r\n"]/g, ''), file.mimetype);
    res.setHeader('Content-Type', file.mimetype || 'application/octet-stream');
    res.setHeader('Content-Disposition', `${disposition}; filename="${safeName}"`);
    res.send(file.data);
  } catch (e) {
    console.error('File download error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/lessons/:id/files/:fileId — admin only, must own the lesson's course
app.delete('/api/lessons/:id/files/:fileId', auth, adminOnly, async (req, res) => {
  try {
    const existing = await pool.query('SELECT course_id FROM lessons WHERE id = $1', [req.params.id]);
    if (!existing.rows.length) return res.status(404).json({ error: 'Lesson not found' });
    if (existing.rows[0].course_id !== req.user.course_id) return res.status(403).json({ error: 'Forbidden' });
    await pool.query('DELETE FROM lesson_files WHERE id = $1 AND lesson_id = $2', [req.params.fileId, req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error('File delete error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Google Drive shows an HTML "can't scan this file for viruses" / confirmation
// page instead of the actual bytes for some files (usually driven by file size
// or link settings), even on the direct uc?export=download URL. This walks
// through that interstitial to reach the real file, retrying with the confirm
// (and, for large files, uuid) token pulled out of the HTML.
async function fetchGoogleDriveFile(fileId) {
  let target = `https://drive.google.com/uc?export=download&id=${fileId}`;
  let resp = await fetch(target, { redirect: 'follow' });
  let contentType = resp.headers.get('content-type') || '';

  if (resp.ok && contentType.includes('text/html')) {
    const html = await resp.text();
    const confirmMatch = html.match(/name="confirm"\s+value="([^"]+)"/) || html.match(/confirm=([0-9A-Za-z_-]+)&/);
    const uuidMatch = html.match(/name="uuid"\s+value="([^"]+)"/);
    const params = new URLSearchParams({ export: 'download', id: fileId, confirm: confirmMatch ? confirmMatch[1] : 't' });
    if (uuidMatch) params.set('uuid', uuidMatch[1]);
    resp = await fetch(`https://drive.google.com/uc?${params.toString()}`, { redirect: 'follow' });
    contentType = resp.headers.get('content-type') || '';
  }
  return { resp, stillHtml: resp.ok && contentType.includes('text/html') };
}

// docs.google.com links (Google Docs/Sheets/Slides — these are NOT drive.google.com
// file links, they're Google's own editors) have a built-in export endpoint that
// returns the real file directly, no confirmation-page dance needed, as long as
// the doc is shared as "Anyone with the link".
function googleDocsExportUrl(target) {
  let m = target.match(/docs\.google\.com\/presentation\/d\/([^/]+)/);
  if (m) return `https://docs.google.com/presentation/d/${m[1]}/export/pdf`;
  m = target.match(/docs\.google\.com\/document\/d\/([^/]+)/);
  if (m) return `https://docs.google.com/document/d/${m[1]}/export?format=pdf`;
  m = target.match(/docs\.google\.com\/spreadsheets\/d\/([^/]+)/);
  if (m) return `https://docs.google.com/spreadsheets/d/${m[1]}/export?format=pdf`;
  return null;
}

const MIME_EXTENSIONS = {
  'application/pdf': '.pdf',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation': '.pptx',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
  'application/msword': '.doc',
  'application/vnd.ms-powerpoint': '.ppt',
  'application/vnd.ms-excel': '.xls',
  'application/zip': '.zip',
  'image/png': '.png',
  'image/jpeg': '.jpg',
  'text/plain': '.txt',
};
// Browsers won't infer a file type for a download with no extension, so if the
// material's label doesn't already end in one, append one based on the real mimetype.
function ensureExtension(name, mimetype) {
  if (/\.[a-z0-9]{2,5}$/i.test(name)) return name;
  const ext = MIME_EXTENSIONS[(mimetype || '').split(';')[0].trim()];
  return ext ? name + ext : name;
}

// GET /api/download — disabled: course materials are view-only for students.
app.get('/api/download', (req, res) => res.status(410).json({ error: 'Downloading materials is disabled.' }));

// ─── USER PROGRESS ROUTES ────────────────────────────────────────────────────

// PATCH /api/users/:id/progress/:lessonId  — save answers and/or note
app.patch('/api/users/:id/progress/:lessonId', auth, async (req, res) => {
  if (req.user.id !== req.params.id && !req.user.is_admin) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const { answers, note, cards } = req.body;
  try {
    if (cards !== undefined) {
      await pool.query(
        `INSERT INTO user_progress (user_id, lesson_id, cards) VALUES ($1, $2, $3)
         ON CONFLICT (user_id, lesson_id) DO UPDATE SET cards = $3`,
        [req.params.id, req.params.lessonId, JSON.stringify(cards || {})]
      );
      if (answers === undefined && note === undefined) return res.json({ ok: true });
    }
    await pool.query(
      `INSERT INTO user_progress (user_id, lesson_id, answers, note, note_updated_at)
       VALUES ($1, $2, $3, $4, CASE WHEN $4::text IS NOT NULL THEN NOW() END)
       ON CONFLICT (user_id, lesson_id) DO UPDATE SET
         answers = CASE WHEN $3::text IS NOT NULL THEN $3 ELSE user_progress.answers END,
         note    = CASE WHEN $4::text IS NOT NULL THEN $4 ELSE user_progress.note    END,
         note_updated_at = CASE WHEN $4::text IS NOT NULL THEN NOW() ELSE user_progress.note_updated_at END`,
      [
        req.params.id,
        req.params.lessonId,
        answers !== undefined ? JSON.stringify(answers) : null,
        note    !== undefined ? note : null
      ]
    );
    res.json({ ok: true });
    if (note !== undefined && req.user.id === req.params.id && !req.user.is_admin) {
      const text = htmlToText(note);
      if (text && !tgNoteThrottled(req.params.id + ':' + req.params.lessonId)) {
        tgStudentLesson(req.params.id, req.params.lessonId).then(sl => {
          if (!sl || sl.is_admin) return;
          tgAlert(sl.course_id, 'notes', `📝 <b>Note saved</b> by ${tgEsc(sl.name)}\n📘 ${tgEsc(sl.title || 'Lesson')}\n\n${tgEsc(clip(text, 700))}`);
        }).catch(e => console.error('Telegram note lookup error:', e.message));
      }
    }
  } catch (e) {
    console.error('Progress update error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── NOTE ATTACHMENTS (student-uploaded files attached to their own notes) ───
// Kept in a separate table from lesson_files (course materials) because these
// are personal to each student, not shared with the class — so unlike the
// public GET /api/files/:fileId route, these downloads are auth-gated and
// checked against ownership.

// POST /api/notes/:lessonId/files — any logged-in user, attaches a file to
// their own note for that lesson (max 15MB, same cap as lesson materials).
app.post('/api/notes/:lessonId/files', auth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'file is required' });
  try {
    const result = await pool.query(
      `INSERT INTO note_files (user_id, lesson_id, name, mimetype, data)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, name, mimetype, octet_length(data) AS size`,
      [req.user.id, req.params.lessonId, req.file.originalname, req.file.mimetype || 'application/octet-stream', req.file.buffer]
    );
    res.status(201).json(result.rows[0]);
    if (!req.user.is_admin) tgStudentLesson(req.user.id, req.params.lessonId).then(sl => {
      if (!sl) return;
      tgAlert(sl.course_id, 'notes', `📎 <b>File attached to notes</b> by ${tgEsc(sl.name)}\n📘 ${tgEsc(sl.title || 'Lesson')}\n${tgEsc(req.file.originalname)}`);
    }).catch(e => console.error('Telegram file lookup error:', e.message));
  } catch (e) {
    console.error('Note file upload error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/notes/my-files — the logged-in user's own note attachments
// (metadata only), used for the "download all my notes" export.
app.get('/api/notes/my-files', auth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, lesson_id, name, mimetype, octet_length(data) AS size, created_at
         FROM note_files WHERE user_id = $1 ORDER BY lesson_id, created_at`,
      [req.user.id]
    );
    res.json(r.rows);
  } catch (e) {
    console.error('My note files error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/notes/:lessonId — a student deletes their own note for a lesson,
// including its attachments (instructor feedback is kept).
app.delete('/api/notes/:lessonId', auth, async (req, res) => {
  try {
    await pool.query(`UPDATE user_progress SET note = '' WHERE user_id = $1 AND lesson_id = $2`, [req.user.id, req.params.lessonId]);
    const f = await pool.query('DELETE FROM note_files WHERE user_id = $1 AND lesson_id = $2', [req.user.id, req.params.lessonId]);
    res.json({ ok: true, files_deleted: f.rowCount });
  } catch (e) {
    console.error('Note delete error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/admin/notes/:userId/:lessonId/state — admin marks a note 'done' or
// 'hidden' for their own review list ({ state: null } clears it). Students never see this.
app.put('/api/admin/notes/:userId/:lessonId/state', auth, adminOnly, async (req, res) => {
  const state = req.body && req.body.state;
  if (state !== null && state !== 'done' && state !== 'hidden') return res.status(400).json({ error: "state must be 'done', 'hidden' or null" });
  try {
    const ok = await pool.query(`SELECT 1 FROM users WHERE id = $1 AND role = 'student' AND course_id = $2`, [req.params.userId, req.user.course_id]);
    if (!ok.rows.length) return res.status(404).json({ error: 'Student not found' });
    if (state === null) {
      await pool.query('DELETE FROM note_admin_state WHERE user_id = $1 AND lesson_id = $2', [req.params.userId, req.params.lessonId]);
      return res.json({ ok: true, state: null });
    }
    const r = await pool.query(
      `INSERT INTO note_admin_state (user_id, lesson_id, state, updated_at) VALUES ($1, $2, $3, NOW())
       ON CONFLICT (user_id, lesson_id) DO UPDATE SET state = $3, updated_at = NOW()
       RETURNING state, updated_at`, [req.params.userId, req.params.lessonId, state]);
    res.json({ ok: true, ...r.rows[0] });
  } catch (e) {
    console.error('Note state error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/admin/notes/:userId/:lessonId — admin deletes a student's note,
// its attachments and the feedback on it (own course only).
app.delete('/api/admin/notes/:userId/:lessonId', auth, adminOnly, async (req, res) => {
  try {
    const ok = await pool.query(`SELECT 1 FROM users WHERE id = $1 AND role = 'student' AND course_id = $2`, [req.params.userId, req.user.course_id]);
    if (!ok.rows.length) return res.status(404).json({ error: 'Student not found' });
    await pool.query(`UPDATE user_progress SET note = '' WHERE user_id = $1 AND lesson_id = $2`, [req.params.userId, req.params.lessonId]);
    const f = await pool.query('DELETE FROM note_files WHERE user_id = $1 AND lesson_id = $2', [req.params.userId, req.params.lessonId]);
    await pool.query('DELETE FROM note_feedback WHERE user_id = $1 AND lesson_id = $2', [req.params.userId, req.params.lessonId]);
    await pool.query('DELETE FROM note_admin_state WHERE user_id = $1 AND lesson_id = $2', [req.params.userId, req.params.lessonId]);
    res.json({ ok: true, files_deleted: f.rowCount });
  } catch (e) {
    console.error('Admin note delete error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/notes/files/:fileId — owner (or an admin) only.
app.get('/api/notes/files/:fileId', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT user_id, name, mimetype, data FROM note_files WHERE id = $1', [req.params.fileId]);
    if (!result.rows.length) return res.status(404).json({ error: 'File not found' });
    const file = result.rows[0];
    if (file.user_id !== req.user.id && !req.user.is_admin) return res.status(403).json({ error: 'Forbidden' });
    const disposition = req.query.disposition === 'inline' ? 'inline' : 'attachment';
    const safeName = (file.name || 'download').replace(/[\r\n"]/g, '');
    res.setHeader('Content-Type', file.mimetype || 'application/octet-stream');
    res.setHeader('Content-Disposition', `${disposition}; filename="${safeName}"`);
    res.send(file.data);
  } catch (e) {
    console.error('Note file download error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/notes/files/:fileId — the owner, or an admin of the student's course.
app.delete('/api/notes/files/:fileId', auth, async (req, res) => {
  try {
    const existing = await pool.query(
      `SELECT f.user_id, u.course_id FROM note_files f JOIN users u ON u.id = f.user_id WHERE f.id = $1`, [req.params.fileId]);
    if (!existing.rows.length) return res.status(404).json({ error: 'File not found' });
    const isOwner = existing.rows[0].user_id === req.user.id;
    const isCourseAdmin = req.user.is_admin && existing.rows[0].course_id === req.user.course_id;
    if (!isOwner && !isCourseAdmin) return res.status(403).json({ error: 'Forbidden' });
    await pool.query('DELETE FROM note_files WHERE id = $1', [req.params.fileId]);
    res.json({ ok: true });
  } catch (e) {
    console.error('Note file delete error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/admin/notes — admin only: every student note and note attachment in
// the admin's own course, grouped by student and lesson.
app.get('/api/admin/notes', auth, adminOnly, async (req, res) => {
  try {
    const notesRes = await pool.query(
      `SELECT u.id AS user_id, u.name, u.email, p.lesson_id, p.note, p.note_updated_at
         FROM user_progress p
         JOIN users u   ON u.id = p.user_id
         JOIN lessons l ON l.id = p.lesson_id
        WHERE u.course_id = $1 AND u.role = 'student' AND l.course_id = $1
          AND p.note IS NOT NULL AND btrim(p.note) <> ''`,
      [req.user.course_id]
    );
    const filesRes = await pool.query(
      `SELECT f.id, f.user_id, f.lesson_id, f.name, f.mimetype, octet_length(f.data) AS size, f.created_at
         FROM note_files f
         JOIN users u   ON u.id = f.user_id
         JOIN lessons l ON l.id = f.lesson_id
        WHERE u.course_id = $1 AND u.role = 'student' AND l.course_id = $1
        ORDER BY f.created_at ASC`,
      [req.user.course_id]
    );
    const fbRes = await pool.query(
      `SELECT f.user_id, f.lesson_id, f.comment, f.rating, f.updated_at
         FROM note_feedback f JOIN users u ON u.id = f.user_id
        WHERE u.course_id = $1`, [req.user.course_id]);
    const stRes = await pool.query(
      `SELECT s.user_id, s.lesson_id, s.state, s.updated_at
         FROM note_admin_state s JOIN users u ON u.id = s.user_id
        WHERE u.course_id = $1`, [req.user.course_id]);
    res.json({ notes: notesRes.rows, files: filesRes.rows, feedback: fbRes.rows, states: stRes.rows });
  } catch (e) {
    console.error('Admin notes error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── TEMPLATES LIBRARY ───────────────────────────────────────────────────────

// GET /api/templates — any signed-in user in the course (metadata only).
app.get('/api/templates', auth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, lesson_id, title, description, name, mimetype, url, octet_length(data) AS size, created_at
         FROM templates WHERE course_id = $1 ORDER BY created_at DESC`, [req.user.course_id]);
    res.json(r.rows);
  } catch (e) { console.error('Templates list error:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// GET /api/templates/:id/file — download (or ?disposition=inline) for course members.
app.get('/api/templates/:id/file', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT course_id, name, mimetype, data FROM templates WHERE id = $1', [req.params.id]);
    if (!r.rows.length || !r.rows[0].data) return res.status(404).json({ error: 'Template not found' });
    const t = r.rows[0];
    if (t.course_id !== req.user.course_id && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Forbidden' });
    const disposition = req.query.disposition === 'inline' ? 'inline' : 'attachment';
    res.setHeader('Content-Type', t.mimetype || 'application/octet-stream');
    res.setHeader('Content-Disposition', `${disposition}; filename="${ensureExtension((t.name || 'template').replace(/[\r\n"]/g, ''), t.mimetype)}"`);
    res.send(t.data);
  } catch (e) { console.error('Template download error:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// POST /api/templates — admin uploads a template (multipart: file, title, description, lesson_id).
app.post('/api/templates', auth, adminOnly, upload.single('file'), async (req, res) => {
  let url = String((req.body && req.body.url) || '').trim();
  if (!req.file && !url) return res.status(400).json({ error: 'A file or a link is required' });
  if (!req.file) {
    if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
    try { const u = new URL(url); if (!/^https?:$/.test(u.protocol) || !u.hostname.includes('.')) throw 0; url = u.href; }
    catch (_) { return res.status(400).json({ error: 'invalid-url' }); }
  } else { url = null; }
  const title = String(req.body.title || (req.file ? req.file.originalname : url)).trim().slice(0, 200);
  const description = String(req.body.description || '').trim().slice(0, 2000);
  let lessonId = req.body.lesson_id ? parseInt(req.body.lesson_id, 10) : null;
  try {
    if (lessonId) {
      const l = await pool.query('SELECT 1 FROM lessons WHERE id = $1 AND course_id = $2', [lessonId, req.user.course_id]);
      if (!l.rows.length) lessonId = null;
    }
    const r = await pool.query(
      `INSERT INTO templates (course_id, lesson_id, title, description, name, mimetype, data, url)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING id, lesson_id, title, description, name, mimetype, url, octet_length(data) AS size, created_at`,
      [req.user.course_id, lessonId, title, description,
       req.file ? req.file.originalname : null, req.file ? (req.file.mimetype || 'application/octet-stream') : null,
       req.file ? req.file.buffer : null, url]);
    notify({ course_id: req.user.course_id, kind: 'template', text: `New resource available: ${title}` });
    res.status(201).json(r.rows[0]);
  } catch (e) { console.error('Template upload error:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// PATCH /api/templates/:id — admin edits title/description/lesson.
app.patch('/api/templates/:id', auth, adminOnly, async (req, res) => {
  const { title, description, lesson_id } = req.body || {};
  try {
    const r = await pool.query(
      `UPDATE templates SET
         title = COALESCE($1, title), description = COALESCE($2, description),
         lesson_id = CASE WHEN $3::text = 'keep' THEN lesson_id ELSE NULLIF($3::text, '')::int END
       WHERE id = $4 AND course_id = $5
       RETURNING id, lesson_id, title, description, name, mimetype, url, octet_length(data) AS size, created_at`,
      [title != null ? String(title).slice(0, 200) : null, description != null ? String(description).slice(0, 2000) : null,
       lesson_id === undefined ? 'keep' : (lesson_id === null ? '' : String(parseInt(lesson_id, 10) || '')),
       req.params.id, req.user.course_id]);
    if (!r.rows.length) return res.status(404).json({ error: 'Template not found' });
    res.json(r.rows[0]);
  } catch (e) { console.error('Template update error:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// DELETE /api/templates/:id — admin only, own course.
app.delete('/api/templates/:id', auth, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM templates WHERE id = $1 AND course_id = $2', [req.params.id, req.user.course_id]);
    res.json({ ok: true });
  } catch (e) { console.error('Template delete error:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// ─── ASK THE INSTRUCTOR (private Q&A per lesson) ─────────────────────────────

// GET /api/questions?lesson_id= — the student's own questions (optionally one lesson).
app.get('/api/questions', auth, async (req, res) => {
  try {
    const params = [req.user.id];
    let where = 'user_id = $1';
    if (req.query.lesson_id) { params.push(parseInt(req.query.lesson_id, 10)); where += ' AND lesson_id = $2'; }
    const r = await pool.query(
      `SELECT id, lesson_id, question, answer, answered_at, closed_at, created_at FROM lesson_questions
        WHERE ${where} ORDER BY created_at ASC`, params);
    res.json(r.rows);
  } catch (e) { console.error('Questions list error:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// POST /api/questions — a student asks about a lesson in their course.
app.post('/api/questions', auth, async (req, res) => {
  const question = String((req.body && req.body.question) || '').trim().slice(0, 4000);
  const lessonId = parseInt(req.body && req.body.lesson_id, 10);
  if (!question) return res.status(400).json({ error: 'question is required' });
  try {
    const l = await pool.query('SELECT title FROM lessons WHERE id = $1 AND course_id = $2', [lessonId, req.user.course_id]);
    if (!l.rows.length) return res.status(404).json({ error: 'Lesson not found' });
    const r = await pool.query(
      `INSERT INTO lesson_questions (course_id, lesson_id, user_id, question) VALUES ($1,$2,$3,$4)
       RETURNING id, lesson_id, question, answer, answered_at, created_at`,
      [req.user.course_id, lessonId, req.user.id, question]);
    const u = await pool.query('SELECT name FROM users WHERE id = $1', [req.user.id]);
    notify({ course_id: req.user.course_id, audience: 'admin', kind: 'question', lesson_id: lessonId,
             text: `${u.rows[0] ? u.rows[0].name : 'A student'} asked a question about "${l.rows[0].title}".` });
    tgAlert(req.user.course_id, 'questions',
      `❓ <b>New question</b> from ${tgEsc(u.rows[0] ? u.rows[0].name : 'a student')}\n📘 ${tgEsc(l.rows[0].title)}\n\n${tgEsc(clip(question, 1500))}`,
      { questionId: r.rows[0].id });
    res.status(201).json(r.rows[0]);
  } catch (e) { console.error('Question create error:', e.message); res.status(500).json({ error: 'Server error' }); }
});


// ─── TELEGRAM SETTINGS ROUTES ────────────────────────────────────────────────
function tgPublic(cfg) {
  return { has_token: !!cfg.token, bot_username: cfg.bot_username || null, connected: !!(cfg.token && cfg.chat_id),
           chat_name: cfg.chat_name || null, replies: !!(cfg.token && cfg.chat_id && cfg.webhook_ok), events: Object.assign({}, TG_DEFAULT_EVENTS, cfg.events || {}) };
}
app.get('/api/admin/telegram', auth, adminOnly, async (req, res) => {
  let cfg = await tgGet(req.user.course_id);
  const want = `${tgServerOrigin(req)}/api/telegram/webhook/${req.user.course_id}`;
  if (cfg.token && cfg.chat_id && cfg.wh_url !== want) cfg = await tgEnableWebhook(req.user.course_id, cfg, tgServerOrigin(req));
  res.json(tgPublic(cfg));
});
// PUT { token?, events? } — a new token is validated with getMe and resets the chat.
app.put('/api/admin/telegram', auth, adminOnly, async (req, res) => {
  try {
    const cfg = await tgGet(req.user.course_id);
    const { token, events } = req.body || {};
    if (token !== undefined) {
      const t = String(token).trim();
      if (!/^\d+:[A-Za-z0-9_-]{30,}$/.test(t)) return res.status(400).json({ error: 'That doesn’t look like a bot token. Copy the full token from @BotFather.' });
      let me;
      try { me = await tgCall(t, 'getMe'); } catch (e) { return res.status(400).json({ error: 'Telegram rejected this token. Check it and try again.' }); }
      cfg.token = t; cfg.bot_username = me.username; delete cfg.chat_id; delete cfg.chat_name;
    }
    if (events && typeof events === 'object') {
      cfg.events = Object.assign({}, TG_DEFAULT_EVENTS, cfg.events || {});
      for (const k of Object.keys(TG_DEFAULT_EVENTS)) if (k in events) cfg.events[k] = !!events[k];
    }
    if (req.headers.origin) cfg.app_url = req.headers.origin + (req.body.app_path || '');
    await tgSave(req.user.course_id, cfg);
    res.json(tgPublic(cfg));
  } catch (e) { console.error('Telegram settings error:', e.message); res.status(500).json({ error: 'Server error' }); }
});
// POST /api/admin/telegram/connect — finds the chat that last messaged the bot.
app.post('/api/admin/telegram/connect', auth, adminOnly, async (req, res) => {
  try {
    const cfg = await tgGet(req.user.course_id);
    if (!cfg.token) return res.status(400).json({ error: 'Add your bot token first.' });
    let updates;
    await tgCall(cfg.token, 'deleteWebhook', {}).catch(() => {});
    try { updates = await tgCall(cfg.token, 'getUpdates', { limit: 100, allowed_updates: ['message'] }); }
    catch (e) { return res.status(400).json({ error: 'Couldn’t reach your bot: ' + e.message }); }
    const msgs = (updates || []).map(u => u.message).filter(m => m && m.chat);
    const m = msgs.filter(x => x.chat.type === 'private').pop() || msgs.pop();
    if (!m) return res.status(404).json({ error: `Open @${cfg.bot_username || 'your bot'} in Telegram, press Start (or send any message), then try again.` });
    const c = m.chat;
    cfg.chat_id = c.id;
    cfg.chat_name = c.title || [c.first_name, c.last_name].filter(Boolean).join(' ') || (c.username ? '@' + c.username : String(c.id));
    if (req.body && req.body.app_path !== undefined && req.headers.origin) cfg.app_url = req.headers.origin + req.body.app_path;
    // Clear the updates we just read so they aren't replayed to the webhook.
    const lastId = (updates || []).reduce((mx, u) => Math.max(mx, u.update_id || 0), 0);
    if (lastId) await tgCall(cfg.token, 'getUpdates', { offset: lastId + 1, limit: 1 }).catch(() => {});
    await tgSave(req.user.course_id, cfg);
    await tgEnableWebhook(req.user.course_id, cfg, tgServerOrigin(req));
    await tgCall(cfg.token, 'sendMessage', { chat_id: cfg.chat_id, parse_mode: 'HTML',
      text: '✅ <b>Connected!</b>\nYou’ll get alerts here when students send questions, save notes, or sign up.' +
        (cfg.webhook_ok ? '\n\n💬 To answer a question, just <b>reply</b> to its message here.' : '') }).catch(() => {});
    res.json(tgPublic(cfg));
  } catch (e) { console.error('Telegram connect error:', e.message); res.status(500).json({ error: 'Server error' }); }
});
app.post('/api/admin/telegram/test', auth, adminOnly, async (req, res) => {
  const cfg = await tgGet(req.user.course_id);
  if (!cfg.token || !cfg.chat_id) return res.status(400).json({ error: 'Telegram isn’t connected yet.' });
  try { await tgCall(cfg.token, 'sendMessage', { chat_id: cfg.chat_id, text: '🔔 Test message — Telegram alerts are working.' }); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: 'Telegram error: ' + e.message }); }
});
app.delete('/api/admin/telegram', auth, adminOnly, async (req, res) => {
  try {
    const cfg = await tgGet(req.user.course_id);
    if (cfg.token) await tgCall(cfg.token, 'deleteWebhook', {}).catch(() => {});
    await pool.query('DELETE FROM settings WHERE key = $1', ['tg:' + req.user.course_id]); res.json(tgPublic({}));
  }
  catch (e) { console.error('Telegram disconnect error:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// POST /api/telegram/webhook/:courseId — called by Telegram. Only accepts
// updates carrying the course's secret, and only acts on the connected chat.
app.post('/api/telegram/webhook/:courseId', async (req, res) => {
  res.json({ ok: true });                       // always ack fast; Telegram retries otherwise
  const courseId = Number(req.params.courseId);
  try {
    const cfg = await tgGet(courseId);
    if (!cfg.token || !cfg.chat_id || !cfg.wh_secret) return;
    if (req.get('X-Telegram-Bot-Api-Secret-Token') !== cfg.wh_secret) return;
    const up = req.body || {};
    const send = (text, extra = {}) => tgCall(cfg.token, 'sendMessage', Object.assign({ chat_id: cfg.chat_id, text, parse_mode: 'HTML', disable_web_page_preview: true }, extra)).catch(e => console.error('Telegram reply error:', e.message));

    if (up.callback_query) {
      const cq = up.callback_query, m = cq.message;
      if (!m || String(m.chat.id) !== String(cfg.chat_id)) return;
      const [action, idStr] = String(cq.data || '').split(':');
      const qid = Number(idStr);
      if (!qid || !['close', 'reopen'].includes(action)) return tgCall(cfg.token, 'answerCallbackQuery', { callback_query_id: cq.id }).catch(() => {});
      const q = await closeQuestionCore(courseId, qid, action === 'close');
      await tgCall(cfg.token, 'answerCallbackQuery', { callback_query_id: cq.id,
        text: !q ? 'This question no longer exists.' : action === 'close' ? 'Question closed.' : 'Question reopened.' }).catch(() => {});
      if (q) await tgCall(cfg.token, 'editMessageReplyMarkup', { chat_id: m.chat.id, message_id: m.message_id,
        reply_markup: tgQuestionKeyboard(cfg, qid, action === 'close') }).catch(() => {});
      return;
    }

    const msg = up.message;
    if (!msg || String(msg.chat.id) !== String(cfg.chat_id)) return;
    const text = (msg.text || msg.caption || '').trim();
    if (!msg.reply_to_message) {
      if (/^\/start\b/.test(text)) return send('👋 You’re connected. New questions will appear here — <b>reply</b> to one to answer it.');
      return send('To answer a question, <b>reply</b> to the question’s message (swipe left on it, or long-press → Reply).');
    }
    const map = await pool.query(
      'SELECT question_id FROM tg_question_msgs WHERE course_id = $1 AND chat_id = $2 AND message_id = $3',
      [courseId, cfg.chat_id, msg.reply_to_message.message_id]);
    if (!map.rows.length) return send('That message isn’t a question. Reply to a “❓ New question” message to answer it.', { reply_to_message_id: msg.message_id });
    if (!text) return send('Only text answers are supported. Please type your answer.', { reply_to_message_id: msg.message_id });
    const qid = map.rows[0].question_id;
    const before = await pool.query('SELECT answer FROM lesson_questions WHERE id = $1 AND course_id = $2', [qid, courseId]);
    if (!before.rows.length) return send('This question was deleted, so the answer wasn’t sent.', { reply_to_message_id: msg.message_id });
    const q = await answerQuestionCore(courseId, qid, text);
    if (!q) return send('Couldn’t save the answer. Please try again.', { reply_to_message_id: msg.message_id });
    const u = await pool.query('SELECT name FROM users WHERE id = $1', [q.user_id]);
    const who = tgEsc(u.rows[0] ? u.rows[0].name : 'the student');
    send(`${before.rows[0].answer ? '✏️ Answer updated' : '✅ Answer sent'} to ${who}. They’ve been notified in the app.`, { reply_to_message_id: msg.message_id });
  } catch (e) { console.error('Telegram webhook error:', e.message); }
});

// PUT /api/admin/questions/:id/close — { closed: true|false }. Closing marks a
// question as handled without (or after) an answer, e.g. a "thank you" message.
app.put('/api/admin/questions/:id/close', auth, adminOnly, async (req, res) => {
  const closed = req.body && req.body.closed !== false;
  try {
    const q = await closeQuestionCore(req.user.course_id, req.params.id, closed);
    if (!q) return res.status(404).json({ error: 'Question not found' });
    res.json(q);
  } catch (e) { console.error('Question close error:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// DELETE /api/questions/:id — the student who asked (only while unanswered), or a course admin.
app.delete('/api/questions/:id', auth, async (req, res) => {
  try {
    const q = await pool.query('SELECT user_id, course_id, answer, closed_at FROM lesson_questions WHERE id = $1', [req.params.id]);
    if (!q.rows.length) return res.status(404).json({ error: 'Question not found' });
    const row = q.rows[0];
    const isAdmin = req.user.is_admin && row.course_id === req.user.course_id;
    const isOwner = row.user_id === req.user.id && !row.answer && !row.closed_at;
    if (!isAdmin && !isOwner) return res.status(403).json({ error: 'Forbidden' });
    await pool.query('DELETE FROM lesson_questions WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { console.error('Question delete error:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// GET /api/admin/questions — all questions in the admin's course.
app.get('/api/admin/questions', auth, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT q.id, q.lesson_id, q.user_id, u.name, u.email, q.question, q.answer, q.answered_at, q.closed_at, q.created_at
         FROM lesson_questions q JOIN users u ON u.id = q.user_id
        WHERE q.course_id = $1 ORDER BY (q.answer IS NULL AND q.closed_at IS NULL) DESC, q.created_at DESC`, [req.user.course_id]);
    res.json(r.rows);
  } catch (e) { console.error('Admin questions error:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// PUT /api/admin/questions/:id/answer — admin answers (or edits the answer); the student is notified.
app.put('/api/admin/questions/:id/answer', auth, adminOnly, async (req, res) => {
  if (!String((req.body && req.body.answer) || '').trim()) return res.status(400).json({ error: 'answer is required' });
  try {
    const q = await answerQuestionCore(req.user.course_id, req.params.id, req.body.answer);
    if (!q) return res.status(404).json({ error: 'Question not found' });
    res.json(q);
  } catch (e) { console.error('Answer error:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// ─── LEADERBOARD ("Course points", top 3) ────────────────────────────────────
const LB_POINTS = { correct: 1, lessonDone: 2, noteLesson: 1, reviewStar: 1, cardsPerPoint: 5, question: 1, questionCapPerLesson: 2, activeDay: 1 };
const LB_DEFAULTS = { enabled: true, mode: 'live' };          // mode: live | days2 | lesson

function lbQuizCorrect(q, ans) {
  if (q.multi) {
    const c = (q.correct || []).slice().sort((a, b) => a - b);
    const g = Array.isArray(ans) ? ans.slice().sort((a, b) => a - b) : [];
    return c.length > 0 && c.length === g.length && c.every((v, i) => v === g[i]);
  }
  return ans === q.answer;
}
function lbAnswered(q, ans) { return q.multi ? Array.isArray(ans) : ans !== undefined && ans !== null; }

async function lbSettings(courseId) {
  const r = await pool.query('SELECT value FROM settings WHERE key = $1', ['lb:' + courseId]);
  let v = {};
  try { v = r.rows.length ? JSON.parse(r.rows[0].value) : {}; } catch (_) {}
  return { ...LB_DEFAULTS, ...v };
}
async function lbSaveSettings(courseId, v) {
  await pool.query(`INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2`, ['lb:' + courseId, JSON.stringify(v)]);
}

// Full live ranking of approved students in a course, with a points breakdown.
async function computeLeaderboard(courseId) {
  const [stu, les, prog, fb, qs, act] = await Promise.all([
    pool.query(`SELECT id, name, created_at FROM users WHERE course_id = $1 AND role = 'student' AND approved = true`, [courseId]),
    pool.query(`SELECT id, quiz, flashcards FROM lessons WHERE course_id = $1`, [courseId]),
    pool.query(`SELECT p.user_id, p.lesson_id, p.answers, p.note, p.cards FROM user_progress p JOIN users u ON u.id = p.user_id WHERE u.course_id = $1`, [courseId]),
    pool.query(`SELECT f.user_id, f.rating FROM note_feedback f JOIN users u ON u.id = f.user_id WHERE u.course_id = $1 AND f.rating IS NOT NULL`, [courseId]),
    pool.query(`SELECT user_id, lesson_id, COUNT(*)::int AS n FROM lesson_questions WHERE course_id = $1 GROUP BY user_id, lesson_id`, [courseId]),
    pool.query(`SELECT a.user_id, COUNT(*)::int AS n FROM activity_days a JOIN users u ON u.id = a.user_id WHERE u.course_id = $1 GROUP BY a.user_id`, [courseId]),
  ]);
  const lessonById = {};
  les.rows.forEach(l => { lessonById[l.id] = { quiz: Array.isArray(l.quiz) ? l.quiz : [], cards: Array.isArray(l.flashcards) ? l.flashcards.length : 0 }; });
  const rows = {};
  stu.rows.forEach(u => { rows[u.id] = { id: u.id, name: u.name, joined: u.created_at,
    b: { correct: 0, lessonsDone: 0, noteLessons: 0, stars: 0, cardsKnown: 0, questions: 0, activeDays: 0 } }; });
  prog.rows.forEach(p => {
    const r = rows[p.user_id], l = lessonById[p.lesson_id]; if (!r || !l) return;
    const ans = p.answers || {};
    if (l.quiz.length) {
      r.b.correct += l.quiz.filter((q, i) => lbQuizCorrect(q, ans[i])).length;
      if (l.quiz.every((q, i) => lbAnswered(q, ans[i]))) r.b.lessonsDone += 1;
    }
    const text = String(p.note || '').replace(/<[^>]*>/g, '').replace(/&nbsp;/g, ' ').trim();
    if (text) r.b.noteLessons += 1;
    const cards = p.cards || {};
    r.b.cardsKnown += Object.entries(cards).filter(([i, v]) => v === 'known' && Number(i) < l.cards).length;
  });
  fb.rows.forEach(f => { if (rows[f.user_id]) rows[f.user_id].b.stars += Number(f.rating) || 0; });
  qs.rows.forEach(q => { if (rows[q.user_id]) rows[q.user_id].b.questions += Math.min(q.n, LB_POINTS.questionCapPerLesson); });
  act.rows.forEach(a => { if (rows[a.user_id]) rows[a.user_id].b.activeDays += a.n; });
  const list = Object.values(rows).map(r => {
    const b = r.b, P = LB_POINTS;
    const parts = { quiz: b.correct * P.correct, lessons: b.lessonsDone * P.lessonDone, notes: b.noteLessons * P.noteLesson,
                    reviews: b.stars * P.reviewStar, flashcards: Math.floor(b.cardsKnown / P.cardsPerPoint), questions: b.questions * P.question, activity: b.activeDays * P.activeDay };
    const points = Object.values(parts).reduce((a, x) => a + x, 0);
    return { id: r.id, name: r.name, points, parts, counts: b, joined: r.joined };
  });
  // Ties: more correct answers first, then whoever joined earlier.
  list.sort((a, b) => b.points - a.points || b.counts.correct - a.counts.correct || new Date(a.joined) - new Date(b.joined));
  list.forEach((r, i) => { r.rank = i + 1; delete r.joined; });
  return list;
}

// Returns the ranking students should see, honouring the update mode:
// live = always fresh; days2 = refreshed at most every 48h; lesson = frozen
// until the admin opens a new lesson. Also announces new top-3 entries.
async function currentLeaderboard(courseId, { force = false } = {}) {
  const st = await lbSettings(courseId);
  let ranking, at;
  const stale = !st.snapshot || (st.mode === 'days2' && Date.now() - new Date(st.snapshot.at).getTime() > 48 * 3600 * 1000);
  if (st.mode === 'live' || force || stale) {
    ranking = await computeLeaderboard(courseId);
    at = new Date().toISOString();
    const prevTop = (st.snapshot && st.snapshot.top3) || [];
    const top3 = ranking.slice(0, 3).filter(r => r.points > 0).map(r => r.id);
    const newcomers = top3.filter(id => !prevTop.includes(id));
    st.snapshot = { at, top3, ranking: st.mode === 'live' ? undefined : ranking };
    if (st.mode === 'live') delete st.snapshot.ranking;
    await lbSaveSettings(courseId, st);
    if (prevTop.length || st.notifiedOnce) {
      newcomers.forEach(id => { const r = ranking.find(x => x.id === id);
        notify({ course_id: courseId, kind: 'leaderboard', text: `${r.name} entered the top 3 with ${r.points} points!` }); });
    }
    if (!st.notifiedOnce) { st.notifiedOnce = true; await lbSaveSettings(courseId, st); }
  } else {
    ranking = st.snapshot.ranking || await computeLeaderboard(courseId);
    at = st.snapshot.at;
  }
  return { settings: st, ranking, at };
}

// GET /api/leaderboard — top 3 + the caller's own position.
app.get('/api/leaderboard', auth, async (req, res) => {
  try {
    if (!req.user.course_id) return res.json({ enabled: false });
    const st = await lbSettings(req.user.course_id);
    if (!st.enabled) return res.json({ enabled: false });
    const { ranking, at, settings } = await currentLeaderboard(req.user.course_id);
    const top = ranking.filter(r => r.points > 0).slice(0, 3).map(r => ({ rank: r.rank, name: r.name, points: r.points, me: r.id === req.user.id }));
    const mine = ranking.find(r => r.id === req.user.id);
    const third = ranking[2];
    res.json({ enabled: true, mode: settings.mode, updated_at: at, total: ranking.length, points: LB_POINTS, top,
      me: mine ? { rank: mine.rank, points: mine.points, parts: mine.parts, to_top3: mine.rank > 3 && third ? Math.max(1, third.points - mine.points + 1) : 0 } : null });
  } catch (e) { console.error('Leaderboard error:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// GET /api/admin/leaderboard — full live ranking with breakdown + settings.
app.get('/api/admin/leaderboard', auth, adminOnly, async (req, res) => {
  try {
    const st = await lbSettings(req.user.course_id);
    const ranking = await computeLeaderboard(req.user.course_id);
    res.json({ settings: { enabled: st.enabled, mode: st.mode, updated_at: st.snapshot ? st.snapshot.at : null }, points: LB_POINTS, ranking });
  } catch (e) { console.error('Admin leaderboard error:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// PUT /api/admin/leaderboard/settings — { enabled?, mode? }
app.put('/api/admin/leaderboard/settings', auth, adminOnly, async (req, res) => {
  try {
    const st = await lbSettings(req.user.course_id);
    if (typeof req.body.enabled === 'boolean') st.enabled = req.body.enabled;
    if (['live', 'days2', 'lesson'].includes(req.body.mode) && req.body.mode !== st.mode) { st.mode = req.body.mode; delete st.snapshot; }
    await lbSaveSettings(req.user.course_id, st);
    res.json({ enabled: st.enabled, mode: st.mode });
  } catch (e) { console.error('Leaderboard settings error:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// POST /api/admin/leaderboard/refresh — recalculate what students see now.
app.post('/api/admin/leaderboard/refresh', auth, adminOnly, async (req, res) => {
  try { const r = await currentLeaderboard(req.user.course_id, { force: true }); res.json({ ok: true, updated_at: r.at }); }
  catch (e) { console.error('Leaderboard refresh error:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// ─── NOTIFICATIONS ───────────────────────────────────────────────────────────

// GET /api/notifications — latest 30 for the current user + unread count.
app.get('/api/notifications', auth, async (req, res) => {
  try {
    const audience = req.user.is_admin ? 'admin' : 'student';
    const u = await pool.query('SELECT notif_seen_at, created_at FROM users WHERE id = $1', [req.user.id]);
    const seen = u.rows[0] && (u.rows[0].notif_seen_at || u.rows[0].created_at);
    const r = await pool.query(
      `SELECT id, kind, text, lesson_id, created_at, (created_at > $3) AS unread
         FROM notifications
        WHERE course_id = $1 AND audience = $4 AND (user_id IS NULL OR user_id = $2)
          AND created_at >= (SELECT created_at FROM users WHERE id = $2) - INTERVAL '1 day'
        ORDER BY created_at DESC LIMIT 30`,
      [req.user.course_id, req.user.id, seen, audience]);
    res.json({ items: r.rows, unread: r.rows.filter(x => x.unread).length });
  } catch (e) { console.error('Notifications error:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// POST /api/notifications/seen — mark everything up to now as read.
app.post('/api/notifications/seen', auth, async (req, res) => {
  try {
    await pool.query('UPDATE users SET notif_seen_at = NOW() WHERE id = $1', [req.user.id]);
    res.json({ ok: true });
  } catch (e) { console.error('Notifications seen error:', e.message); res.status(500).json({ error: 'Server error' }); }
});

// ─── ADMIN ROUTES (scoped to the admin's own course) ─────────────────────────

// PATCH /api/users/:id/approval — approve or revoke a student account (admin only, own course)
app.patch('/api/users/:id/approval', auth, adminOnly, async (req, res) => {
  const { approved } = req.body;
  if (typeof approved !== 'boolean') return res.status(400).json({ error: 'approved (boolean) is required' });
  try {
    const result = await pool.query(
      `UPDATE users SET approved = $1
       WHERE id = $2 AND is_admin = false AND course_id = $3
       RETURNING id, name, email, approved`,
      [approved, req.params.id, req.user.course_id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch (e) {
    console.error('Approval update error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/users/:id — permanently delete a student account (admin only, own course)
app.delete('/api/users/:id', auth, adminOnly, async (req, res) => {
  try {
    const result = await pool.query(
      `DELETE FROM users WHERE id = $1 AND is_admin = false AND course_id = $2 RETURNING id`,
      [req.params.id, req.user.course_id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found or cannot delete an admin' });
    res.json({ ok: true });
  } catch (e) {
    console.error('Delete user error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/admin/notes/:userId/:lessonId/feedback — admin leaves (or clears,
// with an empty comment) feedback on a student's note.
app.put('/api/admin/notes/:userId/:lessonId/feedback', auth, adminOnly, async (req, res) => {
  const comment = String((req.body && req.body.comment) || '').trim().slice(0, 5000);
  let rating = req.body && req.body.rating != null && req.body.rating !== '' ? parseInt(req.body.rating, 10) : null;
  if (rating !== null && !(rating >= 1 && rating <= 5)) return res.status(400).json({ error: 'rating must be 1-5' });
  try {
    const ok = await pool.query(
      `SELECT 1 FROM users u, lessons l
        WHERE u.id = $1 AND u.role = 'student' AND u.course_id = $3
          AND l.id = $2 AND l.course_id = $3`,
      [req.params.userId, req.params.lessonId, req.user.course_id]
    );
    if (!ok.rows.length) return res.status(404).json({ error: 'Student or lesson not found' });
    if (!comment && rating === null) {
      await pool.query('DELETE FROM note_feedback WHERE user_id = $1 AND lesson_id = $2', [req.params.userId, req.params.lessonId]);
      return res.json({ ok: true, comment: '', rating: null });
    }
    await pool.query(
      `INSERT INTO note_feedback (user_id, lesson_id, comment, rating, admin_id, updated_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       ON CONFLICT (user_id, lesson_id) DO UPDATE SET comment = $3, rating = $4, admin_id = $5, updated_at = NOW()`,
      [req.params.userId, req.params.lessonId, comment, rating, req.user.id]
    );
    const ln = await pool.query('SELECT title FROM lessons WHERE id = $1', [req.params.lessonId]);
    notify({ course_id: req.user.course_id, user_id: req.params.userId, kind: 'feedback', lesson_id: Number(req.params.lessonId),
             text: `Your instructor left feedback on your notes for "${ln.rows[0] ? ln.rows[0].title : 'a lesson'}".` });
    res.json({ ok: true, comment, rating });
  } catch (e) {
    console.error('Feedback save error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/users/:id/reset-password — admin generates a one-time temporary
// password for a student in their own course (no email service is configured,
// so the admin hands it over directly).
app.post('/api/users/:id/reset-password', auth, adminOnly, async (req, res) => {
  try {
    const temp = crypto.randomBytes(9).toString('base64').replace(/[^A-Za-z0-9]/g, '').slice(0, 10) + '7a';
    const hash = await bcrypt.hash(temp, 10);
    const r = await pool.query(
      `UPDATE users SET password_hash = $1
        WHERE id = $2 AND is_admin = false AND course_id = $3 RETURNING id, name, email`,
      [hash, req.params.id, req.user.course_id]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({ ok: true, name: r.rows[0].name, email: r.rows[0].email, temp_password: temp });
  } catch (e) {
    console.error('Reset password error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/auth/change-password — any logged-in user changes their own password.
app.post('/api/auth/change-password', auth, async (req, res) => {
  const { current_password, new_password } = req.body || {};
  if (!current_password || !new_password) return res.status(400).json({ error: 'current_password and new_password are required' });
  if (String(new_password).length < 6) return res.status(400).json({ error: 'password-too-short' });
  try {
    const u = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
    if (!u.rows.length) return res.status(404).json({ error: 'User not found' });
    if (!(await bcrypt.compare(current_password, u.rows[0].password_hash))) return res.status(401).json({ error: 'wrong-password' });
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [await bcrypt.hash(new_password, 10), req.user.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error('Change password error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// PATCH /api/admin/credentials — change the logged-in admin's own email/password
app.patch('/api/admin/credentials', auth, adminOnly, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password are required' });
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      `UPDATE users SET email = $1, password_hash = $2 WHERE id = $3`,
      [email, hash, req.user.id]
    );
    res.json({ ok: true });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'email-already-in-use' });
    console.error('Admin credentials update error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/users  — admin only, returns this admin's own students with progress
app.get('/api/users', auth, adminOnly, async (req, res) => {
  try {
    const usersRes = await pool.query(
      `SELECT id, name, email, phone, is_admin, approved, created_at, last_login, last_seen FROM users
       WHERE course_id = $1 AND role = 'student'
       ORDER BY created_at DESC`,
      [req.user.course_id]
    );
    const progressRes = await pool.query(`SELECT * FROM user_progress`);

    // attach progress to each user
    const progressMap = {};
    for (const row of progressRes.rows) {
      if (!progressMap[row.user_id]) progressMap[row.user_id] = [];
      progressMap[row.user_id].push({ lesson_id: row.lesson_id, answers: row.answers, note: row.note, cards: row.cards });
    }
    const users = usersRes.rows.map(u => ({ ...u, progress: progressMap[u.id] || [] }));
    res.json(users);
  } catch (e) {
    console.error('Users list error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── SUPER ADMIN ROUTES (platform-wide admin management) ─────────────────────
// The Super Admin manages ADMINS, not course/lesson/student content directly.
// For each admin they can only see how many courses and students that admin
// has (counts, no drill-in), plus create new admins or delete existing ones.

// GET /api/super/admins — list every admin with their course + student counts
app.get('/api/super/admins', auth, superAdminOnly, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        u.id, u.name, u.email, u.created_at,
        (SELECT COUNT(*)::int FROM courses c WHERE c.id = u.course_id) AS course_count,
        (SELECT COUNT(*)::int FROM users s WHERE s.course_id = u.course_id AND s.role = 'student') AS student_count
      FROM users u
      WHERE u.role = 'admin'
      ORDER BY u.created_at DESC
    `);
    res.json(result.rows);
  } catch (e) {
    console.error('Admins list error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/super/admins — create a new admin and their initial course in one step
app.post('/api/super/admins', auth, superAdminOnly, async (req, res) => {
  const { courseName, adminName, adminEmail, adminPassword } = req.body;
  if (!courseName || !adminName || !adminEmail || !adminPassword) {
    return res.status(400).json({ error: 'courseName, adminName, adminEmail, and adminPassword are required' });
  }
  try {
    const baseSlug = slugify(courseName);
    let slug = baseSlug;
    let n = 1;
    let exists = true;
    while (exists) {
      const check = await pool.query('SELECT 1 FROM courses WHERE slug = $1', [slug]);
      exists = check.rows.length > 0;
      if (exists) { n += 1; slug = `${baseSlug}-${n}`; }
    }
    const courseRes = await pool.query(
      'INSERT INTO courses (slug, name) VALUES ($1, $2) RETURNING id, slug, name',
      [slug, courseName]
    );
    const course = courseRes.rows[0];

    const hash = await bcrypt.hash(adminPassword, 10);
    const adminRes = await pool.query(
      `INSERT INTO users (name, email, password_hash, is_admin, approved, role, course_id)
       VALUES ($1, $2, $3, true, true, 'admin', $4)
       RETURNING id, name, email`,
      [adminName, adminEmail, hash, course.id]
    );
    res.status(201).json({ course, admin: adminRes.rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'email-already-in-use' });
    console.error('Create admin error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/super/admins/:id — delete an admin account, along with their course,
// its lessons, and its students. Only ever targets a role='admin' row, so a
// super_admin account can never be deleted through this endpoint.
app.delete('/api/super/admins/:id', auth, superAdminOnly, async (req, res) => {
  const { id } = req.params;
  try {
    const adminRes = await pool.query(`SELECT course_id FROM users WHERE id = $1 AND role = 'admin'`, [id]);
    if (!adminRes.rows.length) return res.status(404).json({ error: 'Admin not found' });
    const courseId = adminRes.rows[0].course_id;

    if (courseId) {
      await pool.query(
        `DELETE FROM user_progress WHERE user_id IN (SELECT id FROM users WHERE course_id = $1 AND role = 'student')`,
        [courseId]
      );
      await pool.query(`DELETE FROM users WHERE course_id = $1 AND role = 'student'`, [courseId]);
      await pool.query(`DELETE FROM lessons WHERE course_id = $1`, [courseId]);
    }
    await pool.query(`DELETE FROM user_progress WHERE user_id = $1`, [id]);
    await pool.query(`DELETE FROM users WHERE id = $1 AND role = 'admin'`, [id]);
    if (courseId) await pool.query(`DELETE FROM courses WHERE id = $1`, [courseId]);

    res.json({ ok: true });
  } catch (e) {
    console.error('Delete admin error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── CATCH-ALL: serve the frontend for any unmatched route ───────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── DB INIT ─────────────────────────────────────────────────────────────────

// Adds the starter flashcards from flashcards-seed.js once. Only touches lessons
// that match by id AND title in the target course and have no cards yet; a
// settings flag makes sure deleted cards are never re-added on later restarts.
async function seedFlashcards() {
  try {
    const seed = require('./flashcards-seed');
    const done = await pool.query('SELECT 1 FROM settings WHERE key = $1', [seed.settingsKey]);
    if (done.rows.length) return;
    const course = await pool.query('SELECT id FROM courses WHERE slug = $1', [seed.courseSlug]);
    if (!course.rows.length) return;          // course not on this database — try again next start
    let n = 0;
    for (const l of seed.lessons) {
      const r = await pool.query(
        `UPDATE lessons SET flashcards = $1
          WHERE id = $2 AND course_id = $3 AND lower(btrim(title)) = lower(btrim($4))
            AND (flashcards IS NULL OR jsonb_array_length(flashcards) = 0)`,
        [JSON.stringify(l.cards), l.id, course.rows[0].id, l.title]);
      n += r.rowCount;
    }
    await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING', [seed.settingsKey, new Date().toISOString()]);
    console.log(`✓ Starter flashcards added to ${n} lesson(s)`);
  } catch (e) {
    console.error('Flashcard seed error:', e.message);
  }
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS courses (
      id         SERIAL PRIMARY KEY,
      slug       TEXT UNIQUE NOT NULL,
      name       TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS users (
      id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name          TEXT NOT NULL,
      email         TEXT UNIQUE NOT NULL,
      phone         TEXT DEFAULT '',
      password_hash TEXT NOT NULL,
      is_admin      BOOLEAN DEFAULT FALSE,
      approved      BOOLEAN DEFAULT FALSE,
      created_at    TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS lessons (
      id         SERIAL PRIMARY KEY,
      title      TEXT NOT NULL,
      blurb      TEXT DEFAULT '',
      status     TEXT DEFAULT 'draft',
      quiz       JSONB DEFAULT '[]',
      slides     JSONB DEFAULT '[]',
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS user_progress (
      user_id   UUID    REFERENCES users(id)   ON DELETE CASCADE,
      lesson_id INTEGER REFERENCES lessons(id) ON DELETE CASCADE,
      answers   JSONB DEFAULT '{}',
      note      TEXT  DEFAULT '',
      PRIMARY KEY (user_id, lesson_id)
    );

    CREATE TABLE IF NOT EXISTS lesson_files (
      id         SERIAL PRIMARY KEY,
      lesson_id  INTEGER REFERENCES lessons(id) ON DELETE CASCADE,
      name       TEXT NOT NULL,
      mimetype   TEXT NOT NULL,
      data       BYTEA NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS settings (
      key   TEXT PRIMARY KEY,
      value TEXT
    );

    CREATE TABLE IF NOT EXISTS note_feedback (
      user_id    UUID    REFERENCES users(id)   ON DELETE CASCADE,
      lesson_id  INTEGER REFERENCES lessons(id) ON DELETE CASCADE,
      comment    TEXT NOT NULL,
      admin_id   UUID,
      updated_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (user_id, lesson_id)
    );

    CREATE TABLE IF NOT EXISTS note_files (
      id         SERIAL PRIMARY KEY,
      user_id    UUID    REFERENCES users(id)   ON DELETE CASCADE,
      lesson_id  INTEGER REFERENCES lessons(id) ON DELETE CASCADE,
      name       TEXT NOT NULL,
      mimetype   TEXT NOT NULL,
      data       BYTEA NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // Migrations for databases created before multi-course support existed.
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS approved BOOLEAN DEFAULT FALSE`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'student'`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS course_id INTEGER REFERENCES courses(id)`);
  await pool.query(`ALTER TABLE lessons ADD COLUMN IF NOT EXISTS course_id INTEGER REFERENCES courses(id)`);
  await pool.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS videocall_url TEXT`);
  // Per-lesson switch: when FALSE the quiz is optional and doesn't gate the next lesson.
  await pool.query(`ALTER TABLE lessons ADD COLUMN IF NOT EXISTS quiz_mandatory BOOLEAN DEFAULT TRUE`);
  await pool.query(`UPDATE lessons SET quiz_mandatory = TRUE WHERE quiz_mandatory IS NULL`);
  // Optional 1–5 star review an admin can give alongside written feedback.
  await pool.query(`ALTER TABLE note_feedback ADD COLUMN IF NOT EXISTS rating SMALLINT`);
  // Flashcards (per lesson, admin-authored) and each student's card progress.
  await pool.query(`ALTER TABLE lessons ADD COLUMN IF NOT EXISTS flashcards JSONB DEFAULT '[]'`);
  await pool.query(`ALTER TABLE user_progress ADD COLUMN IF NOT EXISTS cards JSONB DEFAULT '{}'`);
  // When the student last changed a note (text or attachments) + the admin's
  // own review state per note ('done' or 'hidden').
  await pool.query(`ALTER TABLE user_progress ADD COLUMN IF NOT EXISTS note_updated_at TIMESTAMP`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS note_admin_state (
      user_id    UUID    REFERENCES users(id)   ON DELETE CASCADE,
      lesson_id  INTEGER REFERENCES lessons(id) ON DELETE CASCADE,
      state      TEXT NOT NULL,
      updated_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (user_id, lesson_id)
    )`);
  // Activity tracking + notification read marker.
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS notif_seen_at TIMESTAMP DEFAULT NOW()`);
  // PM templates library (course-wide files, optionally tied to a lesson).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS templates (
      id          SERIAL PRIMARY KEY,
      course_id   INTEGER REFERENCES courses(id) ON DELETE CASCADE,
      lesson_id   INTEGER REFERENCES lessons(id) ON DELETE SET NULL,
      title       TEXT NOT NULL,
      description TEXT DEFAULT '',
      name        TEXT NOT NULL,
      mimetype    TEXT NOT NULL,
      data        BYTEA NOT NULL,
      created_at  TIMESTAMP DEFAULT NOW()
    )`);
  // Notifications: user_id NULL = for everyone in the course with that audience.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id         SERIAL PRIMARY KEY,
      course_id  INTEGER REFERENCES courses(id) ON DELETE CASCADE,
      user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
      audience   TEXT NOT NULL DEFAULT 'student',
      kind       TEXT NOT NULL,
      text       TEXT NOT NULL,
      lesson_id  INTEGER,
      created_at TIMESTAMP DEFAULT NOW()
    )`);
  // Private student → instructor questions, one thread item per question.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS lesson_questions (
      id          SERIAL PRIMARY KEY,
      course_id   INTEGER REFERENCES courses(id) ON DELETE CASCADE,
      lesson_id   INTEGER REFERENCES lessons(id) ON DELETE CASCADE,
      user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
      question    TEXT NOT NULL,
      answer      TEXT,
      answered_at TIMESTAMP,
      created_at  TIMESTAMP DEFAULT NOW()
    )`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS activity_days (
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      day     DATE NOT NULL,
      PRIMARY KEY (user_id, day)
    )`);
  await pool.query(`ALTER TABLE lesson_questions ADD COLUMN IF NOT EXISTS closed_at TIMESTAMP`);
  // Scheduled auto-opening: open_at = when to open; opened_at = when it last opened.
  await pool.query(`ALTER TABLE lessons ADD COLUMN IF NOT EXISTS open_at TIMESTAMPTZ`);
  // Per-course branding (colors, header style, heading font, tagline) + uploaded logo.
  await pool.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS brand JSONB DEFAULT '{}'::jsonb`);
  await pool.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS logo BYTEA`);
  await pool.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS logo_mime TEXT`);
  await pool.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS logo_updated TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE lessons ADD COLUMN IF NOT EXISTS opened_at TIMESTAMPTZ`);
  await pool.query(`CREATE TABLE IF NOT EXISTS tg_question_msgs (
      course_id   INTEGER,
      chat_id     BIGINT,
      message_id  BIGINT,
      question_id INTEGER REFERENCES lesson_questions(id) ON DELETE CASCADE,
      created_at  TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (course_id, chat_id, message_id))`);
  // Resources can also be plain links (no file).
  await pool.query(`ALTER TABLE templates ADD COLUMN IF NOT EXISTS url TEXT`);
  await pool.query(`ALTER TABLE templates ALTER COLUMN data DROP NOT NULL`);
  await pool.query(`ALTER TABLE templates ALTER COLUMN name DROP NOT NULL`);
  await pool.query(`ALTER TABLE templates ALTER COLUMN mimetype DROP NOT NULL`);
  await pool.query(`CREATE INDEX IF NOT EXISTS notifications_course_idx ON notifications(course_id, created_at DESC)`);

  // Lesson ordering used to be purely derived from creation order (id ASC).
  // sort_order lets an admin manually reorder/renumber lessons instead.
  await pool.query(`ALTER TABLE lessons ADD COLUMN IF NOT EXISTS sort_order INTEGER`);
  // Backfill any lesson that predates this column (or was created before a
  // sibling got a manual number) using its existing id-based position, so
  // nothing jumps around the first time this runs.
  await pool.query(`
    UPDATE lessons l SET sort_order = sub.rn
    FROM (
      SELECT id, ROW_NUMBER() OVER (PARTITION BY course_id ORDER BY id ASC) AS rn
      FROM lessons
    ) sub
    WHERE l.id = sub.id AND l.sort_order IS NULL
  `);

  // Admins are always approved automatically.
  await pool.query(`UPDATE users SET approved = true WHERE is_admin = true AND approved = false`);
  // Any pre-existing admin row that predates the role column gets 'admin' (not 'student').
  await pool.query(`UPDATE users SET role = 'admin' WHERE is_admin = true AND role = 'student'`);

  // Ensure a default course exists and that anything created before multi-course
  // support (lessons, users) gets attached to it.
  const courseCount = await pool.query('SELECT COUNT(*) FROM courses');
  let defaultCourseId;
  if (courseCount.rows[0].count === '0') {
    const nameRow = await pool.query(`SELECT value FROM settings WHERE key = 'course_name'`);
    const defaultName = (nameRow.rows[0] && nameRow.rows[0].value) || 'IT Project Management Course';
    const created = await pool.query(
      `INSERT INTO courses (slug, name) VALUES ('main', $1) RETURNING id`,
      [defaultName]
    );
    defaultCourseId = created.rows[0].id;
    console.log(`✓ Default course created — slug: main  name: ${defaultName}`);
  } else {
    const first = await pool.query('SELECT id FROM courses ORDER BY id ASC LIMIT 1');
    defaultCourseId = first.rows[0].id;
  }
  await pool.query(`UPDATE lessons SET course_id = $1 WHERE course_id IS NULL`, [defaultCourseId]);
  await pool.query(`UPDATE users SET course_id = $1 WHERE course_id IS NULL`, [defaultCourseId]);

  // Promote the platform owner to super_admin. Idempotent — safe to run every boot.
  await pool.query(
    `UPDATE users SET role = 'super_admin', course_id = COALESCE(course_id, $1)
     WHERE email = $2 AND role != 'super_admin'`,
    [defaultCourseId, SUPER_ADMIN_EMAIL]
  );

  // Emergency super admin password reset: set SUPER_ADMIN_RESET_PASSWORD in the
  // host's environment (e.g. Render → Environment), deploy, sign in, then REMOVE
  // the variable. Creates the super admin account if it doesn't exist yet.
  const resetPw = process.env.SUPER_ADMIN_RESET_PASSWORD;
  if (resetPw) {
    if (String(resetPw).length < 8) {
      console.error('✗ SUPER_ADMIN_RESET_PASSWORD is too short (min 8 characters) — ignored.');
    } else {
      const hash = await bcrypt.hash(String(resetPw), 10);
      const upd = await pool.query(
        `UPDATE users SET password_hash = $1, role = 'super_admin', is_admin = true, approved = true WHERE LOWER(email) = LOWER($2)`,
        [hash, SUPER_ADMIN_EMAIL]);
      if (!upd.rowCount) {
        await pool.query(
          `INSERT INTO users (name, email, password_hash, is_admin, approved, role, course_id)
           VALUES ('Super Admin', $1, $2, true, true, 'super_admin', $3)`,
          [SUPER_ADMIN_EMAIL, hash, defaultCourseId]);
      }
      console.log('✓ Super admin password was reset from SUPER_ADMIN_RESET_PASSWORD — remove this variable now.');
    }
  }

  // Seed an admin user only if NO admin/super_admin exists yet at all —
  // prevents recreating a stray default admin after credentials have been changed.
  const anyAdmin = await pool.query(`SELECT id FROM users WHERE is_admin = true LIMIT 1`);
  if (!anyAdmin.rows.length) {
    const hash = await bcrypt.hash('admin123', 10);
    await pool.query(
      `INSERT INTO users (name, email, password_hash, is_admin, approved, role, course_id)
       VALUES ($1, $2, $3, $4, $5, 'admin', $6)`,
      ['Admin', 'admin@itpm.com', hash, true, true, defaultCourseId]
    );
    console.log('✓ Admin user created — email: admin@itpm.com  password: admin123');
  }

  await seedFlashcards();
  console.log('✓ Database ready');
}

// ─── START ────────────────────────────────────────────────────────────────────

initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`✓ Server running on port ${PORT}`));
    openDueLessons().catch(e => console.error('Auto-open error:', e.message));
    if (process.env.RENDER_EXTERNAL_URL) tgRefreshWebhooks(process.env.RENDER_EXTERNAL_URL).catch(e => console.error('Telegram webhook refresh error:', e.message));
  })
  .catch(err => {
    console.error('✗ DB init failed:', err);
    process.exit(1);
  });
