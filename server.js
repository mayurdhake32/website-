require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());

const {
  AIRTABLE_API_KEY,
  AIRTABLE_BASE_ID,
  AIRTABLE_TABLE_NAME,
  ADMIN_PASSWORD,
  JWT_SECRET,
  FRONTEND_URL,
  PORT,
} = process.env;

// Fail fast if someone forgets to set an env var on Render
const required = [
  'AIRTABLE_API_KEY',
  'AIRTABLE_BASE_ID',
  'AIRTABLE_TABLE_NAME',
  'ADMIN_PASSWORD',
  'JWT_SECRET',
  'FRONTEND_URL',
];
for (const key of required) {
  if (!process.env[key]) {
    console.error(`Missing required environment variable: ${key}`);
    process.exit(1);
  }
}

// Only allow requests from your real frontend (comma-separate if you have more than one)
const allowedOrigins = FRONTEND_URL.split(',').map((o) => o.trim());
app.use(
  cors({
    origin: allowedOrigins,
  })
);

const AIRTABLE_URL = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(
  AIRTABLE_TABLE_NAME
)}`;

function airtableHeaders() {
  return {
    Authorization: `Bearer ${AIRTABLE_API_KEY}`,
    'Content-Type': 'application/json',
  };
}

// ---- Auth middleware for write actions (add/edit/delete blog) ----
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token, please log in again' });
  }
}

// Limit login attempts so the password can't be brute-forced
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { error: 'Too many attempts. Please try again later.' },
});

// ---- Health check (Render pings this / you can check it in a browser) ----
app.get('/', (req, res) => {
  res.send('Backend is running.');
});

// ---- Admin login: exchanges the password for a short-lived token ----
app.post('/api/admin/login', loginLimiter, (req, res) => {
  const { password } = req.body || {};
  if (!password || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Incorrect password' });
  }
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '2h' });
  res.json({ token });
});

// ---- Public: list blogs ----
app.get('/api/blogs', async (req, res) => {
  try {
    const url = `${AIRTABLE_URL}?sort%5B0%5D%5Bfield%5D=date&sort%5B0%5D%5Bdirection%5D=desc`;
    const response = await fetch(url, { headers: airtableHeaders() });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error?.message || 'Failed to fetch blogs');

    const posts = data.records.map((record) => ({
      id: record.fields.id || parseInt(record.id, 36),
      airtableId: record.id,
      title: record.fields.title || 'Untitled',
      excerpt: record.fields.excerpt || '',
      date: record.fields.date || '',
      author: record.fields.author || 'Adv. Mahesh N. Dhake',
      image: record.fields.image || 'https://picsum.photos/seed/default/800/500',
      body: record.fields.body || '',
    }));
    res.json(posts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- Protected: create blog ----
app.post('/api/blogs', requireAuth, async (req, res) => {
  try {
    const response = await fetch(AIRTABLE_URL, {
      method: 'POST',
      headers: airtableHeaders(),
      body: JSON.stringify({ records: [{ fields: req.body }] }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error?.message || 'Failed to create blog');
    res.json(data.records[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- Protected: update blog ----
app.patch('/api/blogs/:airtableId', requireAuth, async (req, res) => {
  try {
    const { airtableId } = req.params;
    const response = await fetch(`${AIRTABLE_URL}/${airtableId}`, {
      method: 'PATCH',
      headers: airtableHeaders(),
      body: JSON.stringify({ fields: req.body }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error?.message || 'Failed to update blog');
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- Protected: delete blog ----
app.delete('/api/blogs/:airtableId', requireAuth, async (req, res) => {
  try {
    const { airtableId } = req.params;
    const response = await fetch(`${AIRTABLE_URL}/${airtableId}`, {
      method: 'DELETE',
      headers: airtableHeaders(),
    });
    if (!response.ok) {
      const data = await response.json();
      throw new Error(data.error?.message || 'Failed to delete blog');
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const port = PORT || 10000;
app.listen(port, () => console.log(`Server running on port ${port}`));
