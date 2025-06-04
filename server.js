require("dotenv").config();
const express = require("express");
const session = require("express-session");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const { Op } = require("sequelize");
const db = require("./config/db"); // DB config
const User = require("./models/User"); // Sequelize User model

const app = express();

// Middleware
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);
app.use(express.json());
app.use(
  session({
    secret: "your-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: {
      // default session expires when browser closes if maxAge not set here
      httpOnly: true,
      // secure: true, // enable in production with HTTPS
    },
  })
);

// ===== Routes =====

// Register
app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;
  const existingUser = await User.findOne({ where: { email } });
  if (existingUser)
    return res.status(400).json({ error: "Email already registered" });

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await User.create({ name, email, password: hashedPassword }); // <-- assign to 'user'

  req.session.userId = user.id; // <-- now 'user' exists here

  res.json({ message: "Registered" });
});

// Login
app.post("/api/login", async (req, res) => {
  const { email, password, rememberMe } = req.body;
  const user = await User.findOne({ where: { email } });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  req.session.userId = user.id;

  if (rememberMe) {
    // Remember me: persist session for 30 days
    req.session.cookie.maxAge = 1000 * 60 * 60 * 24 * 30; // 30 days
  } else {
    // Session cookie expires on browser close
    req.session.cookie.expires = false;
  }

  res.json({ message: "Logged in" });
});

// Logout
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ message: "Logged out" });
  });
});

// Get current user
app.get("/api/me", async (req, res) => {
  if (!req.session.userId)
    return res.status(401).json({ error: "Not logged in" });

  const user = await User.findByPk(req.session.userId);
  res.json({
    id: user.id,
    name: user.name,
    email: user.email,
    score: user.score,
  });
});

// Submit score
app.post("/api/submit", async (req, res) => {
  if (!req.session.userId)
    return res.status(401).json({ error: "Not logged in" });

  const user = await User.findByPk(req.session.userId);
  if (user.score !== null)
    return res.status(400).json({ error: "Already submitted" });

  user.score = req.body.score;
  await user.save();
  res.json({ message: "Score submitted" });
});

// Leaderboard
app.get("/api/leaderboard", async (req, res) => {
  const users = await User.findAll({
    where: { score: { [Op.ne]: null } },
    order: [["score", "DESC"]],
  });
  res.json(users);
});

// Update profile
app.put("/api/profile", async (req, res) => {
  if (!req.session.userId)
    return res.status(401).json({ error: "Not logged in" });

  const user = await User.findByPk(req.session.userId);
  user.name = req.body.name || user.name;
  user.email = req.body.email || user.email;
  await user.save();
  res.json({ message: "Profile updated" });
});

// ===== Start Server =====
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

// ===== Test DB Connection =====
db.authenticate()
  .then(() => console.log("Database connected"))
  .catch((err) => console.error("DB connection failed:", err));
