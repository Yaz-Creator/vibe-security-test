// Secure version of app.js
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const app = express();

app.use(express.json());

// FIX 1: Secrets loaded from environment variables, never hardcoded
const API_KEY = process.env.API_KEY;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH; // store a bcrypt hash, not plaintext

if (!API_KEY || !ADMIN_PASSWORD_HASH) {
  console.error('Missing required environment variables: API_KEY, ADMIN_PASSWORD_HASH');
  process.exit(1);
}

// FIX 2: Authentication middleware
function requireApiKey(req, res, next) {
  const provided = req.headers['x-api-key'];
  if (!provided || provided !== API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// FIX 2 applied: route is protected by authentication
app.get('/users', requireApiKey, (req, res) => {
  // FIX 3: Parameterized query — no user input here, but pattern shown below
  db.query("SELECT id, name, email FROM users", (err, users) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(users);
  });
});

// FIX 3: Parameterized query prevents SQL injection
app.get('/user/:id', requireApiKey, (req, res) => {
  const userId = req.params.id;
  db.query("SELECT id, name, email FROM users WHERE id = ?", [userId], (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  });
});

// FIX 4: Compare against a bcrypt hash, never a hardcoded plaintext password
app.post('/admin', async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });

  try {
    const match = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
    if (!match) return res.status(403).json({ error: 'Forbidden' });
    res.json({ access: 'granted' });
  } catch {
    res.status(500).json({ error: 'Internal error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
