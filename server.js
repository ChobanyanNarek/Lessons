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
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
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
app.get('/api/courses/:slug', async (req, res) => {
  try {
    const r = await pool.query('SELECT id, slug, name, videocall_url FROM courses WHERE slug = $1', [req.params.slug]);
    if (!r.rows.length) return res.status(404).json({ error: 'course-not-found' });
    res.json(r.rows[0]);
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
              c.slug AS course_slug, c.name AS course_name, c.videocall_url AS course_videocall_url
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
  const { title, blurb, status, quiz, slides, sort_order, quiz_mandatory, flashcards } = req.body;
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
    const disposition = req.query.disposition === 'inline' ? 'inline' : 'attachment';
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

// GET /api/download — proxies an external link (Google Docs/Slides/Sheets, Google
// Drive, Dropbox, etc.) and forces a real download via Content-Disposition, since
// the browser's <a download> attribute is ignored for cross-origin links.
app.get('/api/download', async (req, res) => {
  const { url, name } = req.query;
  if (!url) return res.status(400).json({ error: 'url is required' });
  let target = String(url);
  if (!/^https?:\/\//i.test(target)) return res.status(400).json({ error: 'Only http(s) links are supported' });

  const docsExport = googleDocsExportUrl(target);
  const gdrive = !docsExport && (
    target.match(/drive\.google\.com\/file\/d\/([^/]+)/) ||
    target.match(/drive\.google\.com\/open\?id=([^&]+)/) ||
    target.match(/drive\.google\.com\/uc\?.*[?&]id=([^&]+)/)
  );

  try {
    let upstream;
    if (docsExport) {
      upstream = await fetch(docsExport, { redirect: 'follow' });
      const ct = upstream.headers.get('content-type') || '';
      if (upstream.ok && ct.includes('text/html')) {
        return res.status(502).json({
          error: 'Google would not export this doc — make sure it\'s shared as "Anyone with the link" (Share → General access), then try again.'
        });
      }
    } else if (gdrive) {
      const { resp, stillHtml } = await fetchGoogleDriveFile(gdrive[1]);
      if (stillHtml) {
        return res.status(502).json({
          error: 'Google Drive would not hand over the raw file for this link — this usually means the link isn\'t set to "Anyone with the link", or Drive is showing a confirmation page it wouldn\'t skip. Double-check the sharing setting and try again.'
        });
      }
      upstream = resp;
    } else {
      upstream = await fetch(target, { redirect: 'follow' });
    }
    if (!upstream.ok) return res.status(502).json({ error: 'Could not fetch the file from its source.' });

    const contentLength = parseInt(upstream.headers.get('content-length') || '0', 10);
    if (contentLength && contentLength > 50 * 1024 * 1024) {
      return res.status(413).json({ error: 'That file is larger than this proxy supports (50MB). Try opening the link directly instead.' });
    }

    const contentType = upstream.headers.get('content-type') || 'application/octet-stream';
    if (!docsExport && !gdrive && contentType.includes('text/html')) {
      // The source handed back a webpage, not a file — sending that through would just
      // produce a "corrupt"/unreadable download labeled with the wrong extension.
      return res.status(502).json({ error: 'That link points to a webpage, not a direct file — the download would come out unreadable. Use a direct file link instead.' });
    }

    const safeName = ensureExtension(String(name || 'download').replace(/[\r\n"]/g, ''), contentType);
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${safeName}"`);
    res.send(Buffer.from(await upstream.arrayBuffer()));
  } catch (e) {
    console.error('Download proxy error:', e.message);
    res.status(502).json({ error: 'Could not download the file from its source.' });
  }
});

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
  })
  .catch(err => {
    console.error('✗ DB init failed:', err);
    process.exit(1);
  });
