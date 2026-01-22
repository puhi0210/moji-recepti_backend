const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(express.json());

// MySQL pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// JWT
function signAccessToken(payload) {
  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {
    expiresIn: process.env.JWT_ACCESS_TTL || "15m",
  });
}
function signRefreshToken(payload) {
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_TTL || "30d",
  });
}

function authRequired(req, res, next) {
  const header = req.headers.authorization || "";
  const [type, token] = header.split(" ");

  if (type !== "Bearer" || !token) {
    return res.status(401).json({
      error: { code: "UNAUTHORIZED", message: "Missing Bearer token" },
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    req.user = decoded; // { sub: userId, email }
    next();
  } catch (err) {
    return res.status(401).json({
      error: { code: "UNAUTHORIZED", message: "Invalid or expired token" },
    });
  }
}


// API routes

// Health check
app.get("/health", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT 1 AS ok");
    res.status(200).json({ status: "ok", db: rows[0] });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// AUTHENTICATION AND USER MANAGEMENT 

// POST /auth/register
app.post("/auth/register", async (req, res) => {
  try {
    const { email, password, fullName = null } = req.body || {};

    if (!email || typeof email !== "string" || !email.includes("@")) {
      return res.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "Invalid email" },
      });
    }
    if (!password || typeof password !== "string" || password.length < 8) {
      return res.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "Password must be at least 8 characters" },
      });
    }

    // Check if exists
    const [existing] = await pool.query(
      "SELECT id FROM users WHERE email = ? LIMIT 1",
      [email.trim().toLowerCase()]
    );
    if (existing.length > 0) {
      return res.status(409).json({
        error: { code: "CONFLICT", message: "Email already registered" },
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    // Insert user (PRILAGODI ime stolpcev, če se razlikujejo)
    const [result] = await pool.query(
      `INSERT INTO users (email, password_hash, full_name, created_at, updated_at)
       VALUES (?, ?, ?, NOW(), NOW())`,
      [email.trim().toLowerCase(), passwordHash, fullName]
    );

    const userId = result.insertId;

    const accessToken = signAccessToken({ sub: String(userId), email: email.trim().toLowerCase() });
    const refreshToken = signRefreshToken({ sub: String(userId) });

    return res.status(201).json({
      data: {
        user: { id: userId, email: email.trim().toLowerCase(), fullName },
        tokens: { accessToken, refreshToken },
      },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: { code: "INTERNAL_ERROR", message: err.message } });
  }
});

// POST /auth/login
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "email and password are required" },
      });
    }

    const [rows] = await pool.query(
      `SELECT id, email, password_hash, full_name
       FROM users
       WHERE email = ?
       LIMIT 1`,
      [email.trim().toLowerCase()]
    );

    if (rows.length === 0) {
      return res.status(401).json({
        error: { code: "UNAUTHORIZED", message: "Invalid credentials" },
      });
    }

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({
        error: { code: "UNAUTHORIZED", message: "Invalid credentials" },
      });
    }

    const accessToken = signAccessToken({ sub: String(user.id), email: user.email });
    const refreshToken = signRefreshToken({ sub: String(user.id) });

    return res.status(200).json({
      data: {
        user: { id: user.id, email: user.email, fullName: user.full_name },
        tokens: { accessToken, refreshToken },
      },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: { code: "INTERNAL_ERROR", message: err.message } });
  }
});

// POST /auth/refresh
app.post("/auth/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) {
      return res.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "refreshToken is required" },
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch (e) {
      return res.status(401).json({
        error: { code: "UNAUTHORIZED", message: "Invalid refresh token" },
      });
    }

    const userId = decoded.sub;

    // (opcijsko) preveri, da user še obstaja
    const [rows] = await pool.query("SELECT id, email FROM users WHERE id = ? LIMIT 1", [userId]);
    if (rows.length === 0) {
      return res.status(401).json({
        error: { code: "UNAUTHORIZED", message: "User not found" },
      });
    }

    const accessToken = signAccessToken({ sub: String(rows[0].id), email: rows[0].email });
    const newRefreshToken = signRefreshToken({ sub: String(rows[0].id) });

    return res.status(200).json({
      data: { tokens: { accessToken, refreshToken: newRefreshToken } },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: { code: "INTERNAL_ERROR", message: err.message } });
  }
});

// GET /auth/me
app.get("/auth/me", authRequired, async (req, res) => {
  const userId = req.user.sub;

  const [rows] = await pool.query(
    "SELECT id, email, full_name FROM users WHERE id = ? LIMIT 1",
    [userId]
  );

  if (rows.length === 0) {
    return res.status(404).json({ error: { code: "NOT_FOUND", message: "User not found" } });
  }

  return res.status(200).json({
    data: { id: rows[0].id, email: rows[0].email, fullName: rows[0].full_name },
  });
});


// RECIPE MANAGEMENT

// POST /auth/register
app.post("/auth/register", async (req, res) => {
  try {
    const { email, password, fullName = null } = req.body || {};

    if (!email || typeof email !== "string" || !email.includes("@")) {
      return res.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "Invalid email" },
      });
    }
    if (!password || typeof password !== "string" || password.length < 8) {
      return res.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "Password must be at least 8 characters" },
      });
    }

    // Check if exists
    const [existing] = await pool.query(
      "SELECT id FROM users WHERE email = ? LIMIT 1",
      [email.trim().toLowerCase()]
    );
    if (existing.length > 0) {
      return res.status(409).json({
        error: { code: "CONFLICT", message: "Email already registered" },
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    // Insert user (PRILAGODI ime stolpcev, če se razlikujejo)
    const [result] = await pool.query(
      `INSERT INTO users (email, password_hash, full_name, created_at, updated_at)
       VALUES (?, ?, ?, NOW(), NOW())`,
      [email.trim().toLowerCase(), passwordHash, fullName]
    );

    const userId = result.insertId;

    const accessToken = signAccessToken({ sub: String(userId), email: email.trim().toLowerCase() });
    const refreshToken = signRefreshToken({ sub: String(userId) });

    return res.status(201).json({
      data: {
        user: { id: userId, email: email.trim().toLowerCase(), fullName },
        tokens: { accessToken, refreshToken },
      },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: { code: "INTERNAL_ERROR", message: err.message } });
  }
});

// POST /auth/login
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "email and password are required" },
      });
    }

    const [rows] = await pool.query(
      `SELECT id, email, password_hash, full_name
       FROM users
       WHERE email = ?
       LIMIT 1`,
      [email.trim().toLowerCase()]
    );

    if (rows.length === 0) {
      return res.status(401).json({
        error: { code: "UNAUTHORIZED", message: "Invalid credentials" },
      });
    }

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({
        error: { code: "UNAUTHORIZED", message: "Invalid credentials" },
      });
    }

    const accessToken = signAccessToken({ sub: String(user.id), email: user.email });
    const refreshToken = signRefreshToken({ sub: String(user.id) });

    return res.status(200).json({
      data: {
        user: { id: user.id, email: user.email, fullName: user.full_name },
        tokens: { accessToken, refreshToken },
      },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: { code: "INTERNAL_ERROR", message: err.message } });
  }
});

// POST /auth/refresh
app.post("/auth/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) {
      return res.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "refreshToken is required" },
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch (e) {
      return res.status(401).json({
        error: { code: "UNAUTHORIZED", message: "Invalid refresh token" },
      });
    }

    const userId = decoded.sub;

    // (opcijsko) preveri, da user še obstaja
    const [rows] = await pool.query("SELECT id, email FROM users WHERE id = ? LIMIT 1", [userId]);
    if (rows.length === 0) {
      return res.status(401).json({
        error: { code: "UNAUTHORIZED", message: "User not found" },
      });
    }

    const accessToken = signAccessToken({ sub: String(rows[0].id), email: rows[0].email });
    const newRefreshToken = signRefreshToken({ sub: String(rows[0].id) });

    return res.status(200).json({
      data: { tokens: { accessToken, refreshToken: newRefreshToken } },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: { code: "INTERNAL_ERROR", message: err.message } });
  }
});

// GET /auth/me
app.get("/auth/me", authRequired, async (req, res) => {
  const userId = req.user.sub;

  const [rows] = await pool.query(
    "SELECT id, email, full_name FROM users WHERE id = ? LIMIT 1",
    [userId]
  );

  if (rows.length === 0) {
    return res.status(404).json({ error: { code: "NOT_FOUND", message: "User not found" } });
  }

  return res.status(200).json({
    data: { id: rows[0].id, email: rows[0].email, fullName: rows[0].full_name },
  });
});

// RECIPE MANAGEMENT

// POST /recipes
app.post("/recipes", authRequired, async (req, res) => {
  try {
    const userId = req.user.sub;

    const {
      title,
      description = null,
      instructions = null,
      prepTimeMinutes = null,
      cookTimeMinutes = null,
      servings = null,
      isPublic = 0,
    } = req.body || {};

    if (!title || typeof title !== "string" || title.trim().length < 2) {
      return res.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "title is required (min 2 chars)" },
      });
    }

    const [result] = await pool.query(
      `INSERT INTO recipes
       (user_id, title, description, instructions, prep_time_minutes, cook_time_minutes, servings, is_public, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
      [userId, title.trim(), description, instructions, prepTimeMinutes, cookTimeMinutes, servings, isPublic ? 1 : 0]
    );

    return res.status(201).json({ data: { id: result.insertId } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: { code: "INTERNAL_ERROR", message: err.message } });
  }
});

// GET /recipes
app.get("/recipes", authRequired, async (req, res) => {
  try {
    const userId = req.user.sub;

    const search = (req.query.search || "").toString().trim();
    const page = Math.max(1, parseInt(req.query.page || "1", 10));
    const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize || "20", 10)));
    const offset = (page - 1) * pageSize;

    let where = "WHERE user_id = ?";
    const params = [userId];

    if (search) {
      where += " AND (title LIKE ? OR description LIKE ?)";
      params.push(`%${search}%`, `%${search}%`);
    }

    const [countRows] = await pool.query(`SELECT COUNT(*) AS total FROM recipes ${where}`, params);
    const [items] = await pool.query(
      `SELECT id, title, description, servings, created_at, updated_at
       FROM recipes
       ${where}
       ORDER BY updated_at DESC
       LIMIT ? OFFSET ?`,
      [...params, pageSize, offset]
    );

    return res.status(200).json({
      data: { items, page, pageSize, total: countRows[0].total },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: { code: "INTERNAL_ERROR", message: err.message } });
  }
});

// START SERVER
const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => {
  console.log(`API running on port ${PORT}`);
});
