// Application principale
const express = require('express');
const bcrypt = require('bcrypt');
const app = express();

app.use(express.json());

// SECURITY FIX: Load secrets from environment variables instead of hardcoding
const API_KEY = process.env.API_KEY;
const DB_PASSWORD = process.env.DB_PASSWORD;

// SECURITY FIX: Stored bcrypt hash of admin password loaded from environment variable
// Generate with: bcrypt.hashSync('your_strong_password', 12)
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;

// SECURITY: Authentication middleware that verifies API key from request headers
function authenticate(req, res, next) {
  const providedKey = req.headers['x-api-key'];
  if (!providedKey || providedKey !== API_KEY) {
    return res.status(401).json({ error: 'Unauthorized: Invalid or missing API key' });
  }
  next();
}

// SECURITY FIX: Added authentication middleware; select only non-sensitive columns
app.get('/users', authenticate, (req, res) => {
  // SECURITY FIX: Only select necessary, non-sensitive columns
  db.query('SELECT id, name, email FROM users', (err, users) => {
    if (err) {
      return res.status(500).json({ error: 'Internal server error' });
    }
    res.json(users);
  });
});

// SECURITY FIX: Added authentication, input validation, and parameterized query
app.get('/user/:id', authenticate, (req, res) => {
  // SECURITY FIX: Validate that id is a numeric value
  const userId = req.params.id;
  if (!/^\d+$/.test(userId)) {
    return res.status(400).json({ error: 'Invalid user ID: must be numeric' });
  }

  // SECURITY FIX: Use parameterized query to prevent SQL injection
  db.query('SELECT id, name, email FROM users WHERE id = ?', [userId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Internal server error' });
    }
    if (!results || results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(results[0]);
  });
});

// SECURITY FIX: Use bcrypt to compare password against stored hash; no hardcoded password
app.post('/admin', async (req, res) => {
  const { password } = req.body;

  if (!password || !ADMIN_PASSWORD_HASH) {
    return res.status(401).json({ access: 'denied' });
  }

  try {
    // SECURITY FIX: Timing-safe comparison using bcrypt
    const match = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
    if (match) {
      res.json({ access: 'granted' });
    } else {
      res.status(401).json({ access: 'denied' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(3000);
