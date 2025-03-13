const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../config/db");

const router = express.Router();

router.post("/register", (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);

  db.query(
    "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
    [name, email, hashedPassword],
    (err, result) => {
      if (err) return res.status(500).json(err);
      res.status(201).json({ message: "User registered!" });
    }
  );
});

router.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
    if (err) return res.status(500).json(err);
    if (results.length === 0)
      return res.status(401).json({ message: "User not found!" });

    const user = results[0];
    const isValid = bcrypt.compareSync(password, user.password);

    if (!isValid)
      return res.status(401).json({ message: "Incorrect password!" });

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email },
    });
  });
});

module.exports = router;
