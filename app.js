// Application principale
const express = require('express');
const app = express();

// FAILLE 1 : Clé API exposée directement dans le code
const API_KEY = "sk-prod-1234567890abcdef";
const DB_PASSWORD = "admin123";

// FAILLE 2 : Pas d'authentification sur les routes
app.get('/users', (req, res) => {
  const users = db.query("SELECT * FROM users");
  res.json(users);
});

// FAILLE 3 : Injection SQL possible
app.get('/user/:id', (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.params.id;
  db.query(query);
});

// FAILLE 4 : Mot de passe admin en dur
app.post('/admin', (req, res) => {
  if(req.body.password === "admin123") {
    res.json({ access: "granted" });
  }
});

app.listen(3000);
