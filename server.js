const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const path    = require('path');
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
      const trimmed = String(videocall_url || '').trim();
      if (trimmed && !/^https?:\/\//i.test(trimmed)) {
        return res.status(400).json({ error: 'Video call link must start with http:// or https://' });
      }
      fields.push(`videocall_url = $${i++}`); values.push(trimmed || null);
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
      'SELECT lesson_id, answers, note FROM user_progress WHERE user_id = $1',
      [req.user.id]
    );
    const user = userRes.rows[0];
    user.progress = progressRes.rows; // array of { lesson_id, answers, note }
    res.json(user);
  } catch (e) {
    console.error('Me error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

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
      'SELECT * FROM lessons WHERE course_id = $1 ORDER BY id ASC',
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
  const { title, blurb, status, quiz, slides } = req.body;
  if (!title) return res.status(400).json({ error: 'title is required' });
  if (!req.user.course_id) return res.status(400).json({ error: 'no-course-assigned' });
  try {
    const result = await pool.query(
      `INSERT INTO lessons (title, blurb, status, quiz, slides, course_id)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [title, blurb || '', status || 'draft', JSON.stringify(quiz || []), JSON.stringify(slides || []), req.user.course_id]
    );
    res.status(201).json(result.rows[0]);
  } catch (e) {
    console.error('Create lesson error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// PATCH /api/lessons/:id  — admin only, must own the lesson's course
app.patch('/api/lessons/:id', auth, adminOnly, async (req, res) => {
  const { title, blurb, status, quiz, slides } = req.body;
  const { id } = req.params;
  try {
    const existing = await pool.query('SELECT course_id FROM lessons WHERE id = $1', [id]);
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
    if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });
    values.push(id);
    const result = await pool.query(
      `UPDATE lessons SET ${fields.join(', ')} WHERE id = $${i} RETURNING *`,
      values
    );
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
  const { answers, note } = req.body;
  try {
    await pool.query(
      `INSERT INTO user_progress (user_id, lesson_id, answers, note)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id, lesson_id) DO UPDATE SET
         answers = CASE WHEN $3::text IS NOT NULL THEN $3 ELSE user_progress.answers END,
         note    = CASE WHEN $4::text IS NOT NULL THEN $4 ELSE user_progress.note    END`,
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
      `SELECT id, name, email, phone, is_admin, approved, created_at FROM users
       WHERE course_id = $1 AND role = 'student'
       ORDER BY created_at DESC`,
      [req.user.course_id]
    );
    const progressRes = await pool.query(`SELECT * FROM user_progress`);

    // attach progress to each user
    const progressMap = {};
    for (const row of progressRes.rows) {
      if (!progressMap[row.user_id]) progressMap[row.user_id] = [];
      progressMap[row.user_id].push({ lesson_id: row.lesson_id, answers: row.answers, note: row.note });
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
  `);

  // Migrations for databases created before multi-course support existed.
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS approved BOOLEAN DEFAULT FALSE`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'student'`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS course_id INTEGER REFERENCES courses(id)`);
  await pool.query(`ALTER TABLE lessons ADD COLUMN IF NOT EXISTS course_id INTEGER REFERENCES courses(id)`);
  await pool.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS videocall_url TEXT`);

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
