const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const User = require("../models/User");

// Register
router.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  const existingUser = await User.findOne({ where: { email } });
  if (existingUser)
    return res.status(400).json({ error: "Email already registered" });

  const hashedPassword = await bcrypt.hash(password, 10);
  await User.create({ name, email, password: hashedPassword });
  res.json({ message: "Registered" });
});

// Login
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  req.session.userId = user.id;
  res.json({ message: "Logged in" });
});

// Logout
router.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ message: "Logged out" });
  });
});

// Get current user (no login check)
router.get("/me", async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Not logged in" });
  }
  const user = await User.findByPk(req.session.userId);
  res.json({
    id: user.id,
    name: user.name,
    email: user.email,
    score: user.score,
  });
});

// Submit score (no login check)
router.post("/submit", async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Not logged in" });
  }
  const user = await User.findByPk(req.session.userId);
  if (user.score !== null)
    return res.status(400).json({ error: "Already submitted" });

  user.score = req.body.score;
  await user.save();
  res.json({ message: "Score submitted" });
});

// Leaderboard
router.get("/leaderboard", async (req, res) => {
  const users = await User.findAll({
    where: { score: { [require("sequelize").Op.ne]: null } },
    order: [["score", "DESC"]],
  });
  res.json(users);
});

// Update profile (no login check)
router.put("/profile", async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Not logged in" });
  }
  const user = await User.findByPk(req.session.userId);
  user.name = req.body.name || user.name;
  user.email = req.body.email || user.email;
  await user.save();
  res.json({ message: "Profile updated" });
});

module.exports = router;
