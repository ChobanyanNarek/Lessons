const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const path    = require('path');

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
    const r = await pool.query('SELECT id, slug, name FROM courses WHERE slug = $1', [req.params.slug]);
    if (!r.rows.length) return res.status(404).json({ error: 'course-not-found' });
    res.json(r.rows[0]);
  } catch (e) {
    console.error('Course fetch error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// PATCH /api/courses/mine — admin renames their own course (shown to their students).
// The shareable link's slug is regenerated from the new name too, so the link
// always reflects the course's current name.
app.patch('/api/courses/mine', auth, adminOnly, async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });
  if (!req.user.course_id) return res.status(400).json({ error: 'no-course-assigned' });
  try {
    const baseSlug = slugify(name);
    let slug = baseSlug;
    let n = 1;
    let exists = true;
    while (exists) {
      const check = await pool.query(
        'SELECT 1 FROM courses WHERE slug = $1 AND id != $2',
        [slug, req.user.course_id]
      );
      exists = check.rows.length > 0;
      if (exists) { n += 1; slug = `${baseSlug}-${n}`; }
    }
    const r = await pool.query(
      'UPDATE courses SET name = $1, slug = $2 WHERE id = $3 RETURNING id, slug, name',
      [name, slug, req.user.course_id]
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
      `SELECT u.*, c.slug AS course_slug, c.name AS course_name
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
        course_id: user.course_id, course_slug: user.course_slug, course_name: user.course_name
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
              c.slug AS course_slug, c.name AS course_name
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

// ─── SUPER ADMIN ROUTES (platform-wide course management) ────────────────────

// GET /api/super/courses — list every course with its admin and student count
app.get('/api/super/courses', auth, superAdminOnly, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        c.id, c.slug, c.name, c.created_at,
        (SELECT json_build_object('name', u.name, 'email', u.email)
           FROM users u WHERE u.course_id = c.id AND u.role = 'admin' LIMIT 1) AS admin,
        (SELECT COUNT(*)::int FROM users s WHERE s.course_id = c.id AND s.role = 'student') AS student_count
      FROM courses c
      ORDER BY c.created_at DESC
    `);
    res.json(result.rows);
  } catch (e) {
    console.error('Courses list error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/super/courses — create a new course and its admin account in one step
app.post('/api/super/courses', auth, superAdminOnly, async (req, res) => {
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
    console.error('Create course error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/super/courses/:id — delete a course, its lessons, and its admin/students.
// Never deletes a super_admin row, even if one happens to be tied to this course —
// instead it's detached (course_id set to null) so the foreign key doesn't block
// deleting the course itself. This means a super admin CAN delete every course,
// including their own / the last one remaining.
app.delete('/api/super/courses/:id', auth, superAdminOnly, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query(
      `DELETE FROM user_progress WHERE user_id IN (SELECT id FROM users WHERE course_id = $1 AND role != 'super_admin')`,
      [id]
    );
    await pool.query(`DELETE FROM users WHERE course_id = $1 AND role != 'super_admin'`, [id]);
    await pool.query(`UPDATE users SET course_id = NULL WHERE course_id = $1 AND role = 'super_admin'`, [id]);
    await pool.query(`DELETE FROM lessons WHERE course_id = $1`, [id]);
    const result = await pool.query(`DELETE FROM courses WHERE id = $1 RETURNING id`, [id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Course not found' });
    res.json({ ok: true });
  } catch (e) {
    console.error('Delete course error:', e.message);
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
