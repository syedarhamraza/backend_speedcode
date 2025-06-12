require("dotenv").config();
const express = require("express");
const session = require("express-session");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const MongoStore = require("connect-mongo");

const app = express();

// ===== Mongoose Connection Function =====
let isConnected = false;
const connectDB = async () => {
  if (isConnected) return;
  try {
    await mongoose.connect(process.env.MONGO_URI);
    isConnected = true;
    console.log("MongoDB connected");
  } catch (err) {
    console.error("MongoDB connection error:", err);
  }
};

// ===== Mongoose User Schema =====
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  score: { type: Number, default: null },
});
const User = mongoose.models.User || mongoose.model("User", userSchema);

app.set("trust proxy", 1); // ✅ IMPORTANT for production on Vercel (or any reverse proxy)

// ===== Middleware =====
app.use(
  cors({
    origin: "https://frontend-speedcode.vercel.app" || "http://localhost:3000",
    credentials: true,
  })
);
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      collectionName: "sessions",
    }),
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 7,
      sameSite: "none",
      secure: true,
    },
  })
);

// ===== Routes =====

// Register
app.post("/api/register", async (req, res) => {
  await connectDB();
  try {
    const { name, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ error: "Email already registered" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();

    req.session.userId = user._id;
    res.json({ message: "Registered" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  await connectDB();
  try {
    const { email, password, rememberMe } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

    req.session.userId = user._id;
    req.session.cookie.maxAge = rememberMe ? 1000 * 60 * 60 * 24 * 30 : null;

    req.session.save((err) => {
      if (err) {
        console.error("Session save error:", err);
        return res.status(500).json({ error: "Could not save session" });
      }
      res.json({ message: "Logged in" });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Logout
app.post("/api/logout", async (req, res) => {
  await connectDB();
  req.session.destroy(() => {
    res.json({ message: "Logged out" });
  });
});

// Get current user
app.get("/api/me", async (req, res) => {
  await connectDB();
  try {
    if (!req.session.userId)
      return res.status(401).json({ error: "Not logged in" });

    const user = await User.findById(req.session.userId).select(
      "_id name email score"
    );
    if (!user) return res.status(404).json({ error: "User not found" });

    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Submit score
app.post("/api/submit", async (req, res) => {
  await connectDB();
  try {
    if (!req.session.userId)
      return res.status(401).json({ error: "Not logged in" });

    const user = await User.findById(req.session.userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    const incomingScore = req.body.score;

    if (
      typeof incomingScore !== "number" ||
      incomingScore < 0 ||
      incomingScore > 100
    ) {
      return res.status(400).json({ error: "Invalid score" });
    }

    // If user has no score yet, initialize it to 0
    if (user.score === null || typeof user.score !== "number") {
      user.score = 0;
    }

    user.score = user.score + incomingScore;

    await user.save();

    res.json({ message: "Score added successfully", totalScore: user.score });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Leaderboard
app.get("/api/leaderboard", async (req, res) => {
  await connectDB();
  try {
    const users = await User.find({ score: { $ne: null } }).sort({ score: -1 });
    res.json(users);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Update profile
app.put("/api/profile", async (req, res) => {
  await connectDB();
  try {
    if (!req.session.userId)
      return res.status(401).json({ error: "Not logged in" });

    const user = await User.findById(req.session.userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    user.name = req.body.name || user.name;
    user.email = req.body.email || user.email;
    await user.save();

    res.json({ message: "Profile updated" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Get profile info
app.get("/api/profile", async (req, res) => {
  await connectDB();
  try {
    if (!req.session.userId) {
      return res.status(401).json({ error: "Not logged in" });
    }

    const user = await User.findById(req.session.userId).select("name email");
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(user);
  } catch (err) {
    console.error("Profile GET error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/session", (req, res) => {
  if (req.session.user) {
    res.json({ user: req.session.user });
  } else {
    res.status(401).json({ message: "Not authenticated" });
  }
});

// ===== Start Server =====
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

module.exports = app; // required for Vercel
