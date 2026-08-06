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

// ─── AUTH ROUTES ─────────────────────────────────────────────────────────────

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'name, email, and password are required' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (name, email, phone, password_hash)
       VALUES ($1, $2, $3, $4)
       RETURNING id, name, email, phone, is_admin`,
      [name, email, phone || '', hash]
    );
    const user = result.rows[0];
    const token = jwt.sign(
      { id: user.id, email: user.email, is_admin: user.is_admin },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.status(201).json({ token, user });
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
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'user-not-found' });
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'wrong-password' });
    const token = jwt.sign(
      { id: user.id, email: user.email, is_admin: user.is_admin },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, phone: user.phone, is_admin: user.is_admin }
    });
  } catch (e) {
    console.error('Login error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/auth/me  — returns current user + their progress
app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const userRes = await pool.query(
      'SELECT id, name, email, phone, is_admin FROM users WHERE id = $1',
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

// GET /api/lessons  — public, no auth needed
app.get('/api/lessons', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM lessons ORDER BY id ASC');
    res.json(result.rows);
  } catch (e) {
    console.error('Lessons list error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/lessons  — admin only
app.post('/api/lessons', auth, adminOnly, async (req, res) => {
  const { title, blurb, status, quiz, slides } = req.body;
  if (!title) return res.status(400).json({ error: 'title is required' });
  try {
    const result = await pool.query(
      `INSERT INTO lessons (title, blurb, status, quiz, slides)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [title, blurb || '', status || 'draft', JSON.stringify(quiz || []), JSON.stringify(slides || [])]
    );
    res.status(201).json(result.rows[0]);
  } catch (e) {
    console.error('Create lesson error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// PATCH /api/lessons/:id  — admin only
app.patch('/api/lessons/:id', auth, adminOnly, async (req, res) => {
  const { title, blurb, status, quiz, slides } = req.body;
  const { id } = req.params;
  try {
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
    if (!result.rows.length) return res.status(404).json({ error: 'Lesson not found' });
    res.json(result.rows[0]);
  } catch (e) {
    console.error('Update lesson error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/lessons/:id  — admin only
app.delete('/api/lessons/:id', auth, adminOnly, async (req, res) => {
  try {
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

// ─── ADMIN ROUTES ─────────────────────────────────────────────────────────────

// GET /api/users  — admin only, returns all students with progress
app.get('/api/users', auth, adminOnly, async (req, res) => {
  try {
    const usersRes = await pool.query(
      `SELECT id, name, email, phone, is_admin, created_at FROM users ORDER BY created_at DESC`
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

// ─── CATCH-ALL: serve the frontend for any unmatched route ───────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── DB INIT ─────────────────────────────────────────────────────────────────

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name          TEXT NOT NULL,
      email         TEXT UNIQUE NOT NULL,
      phone         TEXT DEFAULT '',
      password_hash TEXT NOT NULL,
      is_admin      BOOLEAN DEFAULT FALSE,
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
  `);

  // Seed admin user
  const existing = await pool.query('SELECT id FROM users WHERE email = $1', ['admin@itpm.com']);
  if (!existing.rows.length) {
    const hash = await bcrypt.hash('admin123', 10);
    await pool.query(
      `INSERT INTO users (name, email, password_hash, is_admin) VALUES ($1, $2, $3, $4)`,
      ['Admin', 'admin@itpm.com', hash, true]
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
