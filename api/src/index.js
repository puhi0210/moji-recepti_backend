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

// JWT helpers
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

// Helper to check recipe ownership
async function assertRecipeOwnership(recipeId, userId) {
  const [rows] = await pool.query(
    "SELECT id FROM recipes WHERE id = ? AND user_id = ? LIMIT 1",
    [recipeId, userId]
  );
  return rows.length > 0;
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


// ----------------------------------------------
// AUTHENTICATION AND USER MANAGEMENT 
// ----------------------------------------------

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


// ----------------------------------------------
// RECIPE MANAGEMENT
// ----------------------------------------------

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

// GET /recipes/:id
app.get("/recipes/:id", authRequired, async (req, res) => {
  try {
    const recipeId = Number(req.params.id);
    if (!Number.isInteger(recipeId)) {
      return res.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Invalid recipe id" } });
    }

    const userId = req.user.sub;

    const [rows] = await pool.query(
      `SELECT id, user_id, title, description, instructions,
              prep_time_minutes, cook_time_minutes, servings, is_public,
              created_at, updated_at
       FROM recipes
       WHERE id = ? AND user_id = ?
       LIMIT 1`,
      [recipeId, userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: { code: "NOT_FOUND", message: "Recipe not found" } });
    }

    const recipe = rows[0];

    const [ingredients] = await pool.query(
      `SELECT
         ri.id AS recipeIngredientId,
         ri.ingredient_id AS ingredientId,
         i.name AS ingredientName,
         i.category AS ingredientCategory,
         ri.quantity,
         ri.unit,
         ri.note,
         ri.created_at,
         ri.updated_at
       FROM recipe_ingredients ri
       JOIN ingredients i ON i.id = ri.ingredient_id
       WHERE ri.recipe_id = ?
       ORDER BY ri.id ASC`,
      [recipeId]
    );

    return res.status(200).json({ data: { ...recipe, ingredients } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: { code: "INTERNAL_ERROR", message: err.message } });
  }
});

// PATCH /recipes/:id

app.patch("/recipes/:id", authRequired, async (req, res) => {
  try {
    const recipeId = Number(req.params.id);
    if (!Number.isInteger(recipeId)) {
      return res.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Invalid recipe id" } });
    }

    const userId = req.user.sub;
    const ok = await assertRecipeOwnership(recipeId, userId);
    if (!ok) {
      return res.status(404).json({ error: { code: "NOT_FOUND", message: "Recipe not found" } });
    }

    const {
      title,
      description,
      instructions,
      prepTimeMinutes,
      cookTimeMinutes,
      servings,
      isPublic,
    } = req.body || {};

    const updates = [];
    const params = [];

    if (title !== undefined) {
      if (typeof title !== "string" || title.trim().length < 2) {
        return res.status(400).json({
          error: { code: "VALIDATION_ERROR", message: "title must be at least 2 chars" },
        });
      }
      updates.push("title = ?");
      params.push(title.trim());
    }

    if (description !== undefined) {
      updates.push("description = ?");
      params.push(description);
    }

    if (instructions !== undefined) {
      updates.push("instructions = ?");
      params.push(instructions);
    }

    if (prepTimeMinutes !== undefined) {
      updates.push("prep_time_minutes = ?");
      params.push(prepTimeMinutes);
    }

    if (cookTimeMinutes !== undefined) {
      updates.push("cook_time_minutes = ?");
      params.push(cookTimeMinutes);
    }

    if (servings !== undefined) {
      updates.push("servings = ?");
      params.push(servings);
    }

    if (isPublic !== undefined) {
      updates.push("is_public = ?");
      params.push(isPublic ? 1 : 0);
    }

    if (updates.length === 0) {
      return res.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "No fields to update" },
      });
    }

    updates.push("updated_at = NOW()");

    params.push(recipeId, userId);

    const [result] = await pool.query(
      `UPDATE recipes
       SET ${updates.join(", ")}
       WHERE id = ? AND user_id = ?`,
      params
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: { code: "NOT_FOUND", message: "Recipe not found" } });
    }

    return res.status(200).json({ data: { updated: true } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: { code: "INTERNAL_ERROR", message: err.message } });
  }
});

// DELETE /recipes/:id

app.delete("/recipes/:id", authRequired, async (req, res) => {
  try {
    const recipeId = Number(req.params.id);
    if (!Number.isInteger(recipeId)) {
      return res.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Invalid recipe id" } });
    }

    const userId = req.user.sub;

    const [result] = await pool.query(
      "DELETE FROM recipes WHERE id = ? AND user_id = ?",
      [recipeId, userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: { code: "NOT_FOUND", message: "Recipe not found" } });
    }

    return res.status(204).send();
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: { code: "INTERNAL_ERROR", message: err.message } });
  }
});


// ----------------------------------------------
// RECIPE INGREDIENT MANAGEMENT
// ----------------------------------------------

// GET /recipes/:id/ingredients
app.get("/recipes/:id/ingredients", authRequired, async (req, res) => {
  try {
    const recipeId = Number(req.params.id);
    if (!Number.isInteger(recipeId)) {
      return res.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Invalid recipe id" } });
    }

    const userId = req.user.sub;
    const ok = await assertRecipeOwnership(recipeId, userId);
    if (!ok) {
      return res.status(404).json({ error: { code: "NOT_FOUND", message: "Recipe not found" } });
    }

    const [items] = await pool.query(
      `SELECT
         ri.id,
         ri.recipe_id,
         ri.ingredient_id,
         i.name AS ingredient_name,
         i.category AS ingredient_category,
         ri.quantity,
         ri.unit,
         ri.note,
         ri.created_at,
         ri.updated_at
       FROM recipe_ingredients ri
       JOIN ingredients i ON i.id = ri.ingredient_id
       WHERE ri.recipe_id = ?
       ORDER BY ri.id ASC`,
      [recipeId]
    );

    return res.status(200).json({ data: { items } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: { code: "INTERNAL_ERROR", message: err.message } });
  }
});

// POST /recipes/:id/ingredients
app.post("/recipes/:id/ingredients", authRequired, async (req, res) => {
  try {
    const recipeId = Number(req.params.id);
    if (!Number.isInteger(recipeId)) {
      return res.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Invalid recipe id" } });
    }

    const userId = req.user.sub;
    const ok = await assertRecipeOwnership(recipeId, userId);
    if (!ok) {
      return res.status(404).json({ error: { code: "NOT_FOUND", message: "Recipe not found" } });
    }

    let { ingredientId, ingredientName, quantity, unit = null, note = null } = req.body || {};

    // validate quantity
    const q = Number(quantity);
    if (!Number.isFinite(q) || q <= 0) {
      return res.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "quantity must be a positive number" },
      });
    }

    // determine ingredientId
    if (!ingredientId) {
      if (!ingredientName || typeof ingredientName !== "string" || ingredientName.trim().length < 2) {
        return res.status(400).json({
          error: { code: "VALIDATION_ERROR", message: "ingredientId or ingredientName is required" },
        });
      }

      const cleanName = ingredientName.trim();

      // find existing
      const [found] = await pool.query("SELECT id, default_unit FROM ingredients WHERE name = ? LIMIT 1", [cleanName]);

      if (found.length > 0) {
        ingredientId = found[0].id;
        if (!unit) unit = found[0].default_unit || unit;
      } else {
        // create new ingredient
        const [created] = await pool.query(
          `INSERT INTO ingredients (name, category, default_unit, created_at, updated_at)
           VALUES (?, NULL, ?, NOW(), NOW())`,
          [cleanName, unit]
        );
        ingredientId = created.insertId;
      }
    }

    // insert recipe_ingredient
    const [result] = await pool.query(
      `INSERT INTO recipe_ingredients (recipe_id, ingredient_id, quantity, unit, note, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, NOW(), NOW())`,
      [recipeId, ingredientId, q, unit, note]
    );

    return res.status(201).json({ data: { id: result.insertId } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: { code: "INTERNAL_ERROR", message: err.message } });
  }
});

// PATCH /recipes/:id/ingredients/:riId
app.patch("/recipes/:id/ingredients/:riId", authRequired, async (req, res) => {
  try {
    const recipeId = Number(req.params.id);
    const riId = Number(req.params.riId);

    if (!Number.isInteger(recipeId) || !Number.isInteger(riId)) {
      return res.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Invalid id" } });
    }

    const userId = req.user.sub;
    const ok = await assertRecipeOwnership(recipeId, userId);
    if (!ok) {
      return res.status(404).json({ error: { code: "NOT_FOUND", message: "Recipe not found" } });
    }

    const { quantity, unit, note } = req.body || {};

    const updates = [];
    const params = [];

    if (quantity !== undefined) {
      const q = Number(quantity);
      if (!Number.isFinite(q) || q <= 0) {
        return res.status(400).json({
          error: { code: "VALIDATION_ERROR", message: "quantity must be a positive number" },
        });
      }
      updates.push("quantity = ?");
      params.push(q);
    }

    if (unit !== undefined) {
      updates.push("unit = ?");
      params.push(unit);
    }

    if (note !== undefined) {
      updates.push("note = ?");
      params.push(note);
    }

    if (updates.length === 0) {
      return res.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "No fields to update" },
      });
    }

    updates.push("updated_at = NOW()");

    // ensure this row belongs to the recipe
    params.push(recipeId, riId);

    const [result] = await pool.query(
      `UPDATE recipe_ingredients
       SET ${updates.join(", ")}
       WHERE recipe_id = ? AND id = ?`,
      params
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        error: { code: "NOT_FOUND", message: "Recipe ingredient not found" },
      });
    }

    return res.status(200).json({ data: { updated: true } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: { code: "INTERNAL_ERROR", message: err.message } });
  }
});


// DELETE /recipes/:id/ingredients/:riId
app.delete("/recipes/:id/ingredients/:riId", authRequired, async (req, res) => {
  try {
    const recipeId = Number(req.params.id);
    const riId = Number(req.params.riId);

    if (!Number.isInteger(recipeId) || !Number.isInteger(riId)) {
      return res.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Invalid id" } });
    }

    const userId = req.user.sub;
    const ok = await assertRecipeOwnership(recipeId, userId);
    if (!ok) {
      return res.status(404).json({ error: { code: "NOT_FOUND", message: "Recipe not found" } });
    }

    const [result] = await pool.query(
      `DELETE FROM recipe_ingredients
       WHERE recipe_id = ? AND id = ?`,
      [recipeId, riId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        error: { code: "NOT_FOUND", message: "Recipe ingredient not found" },
      });
    }

    return res.status(204).send();
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: { code: "INTERNAL_ERROR", message: err.message } });
  }
});



// ----------------------------------------------
// GLOBAL INGREDIENT MANAGEMENT
// ----------------------------------------------

// GET /ingredients
app.get("/ingredients", authRequired, async (req, res) => {
  try {
    const search = (req.query.search || "").toString().trim();
    const page = Math.max(1, parseInt(req.query.page || "1", 10));
    const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize || "20", 10)));
    const offset = (page - 1) * pageSize;

    let where = "";
    const params = [];

    if (search) {
      where = "WHERE name LIKE ? OR category LIKE ?";
      params.push(`%${search}%`, `%${search}%`);
    }

    const [countRows] = await pool.query(
      `SELECT COUNT(*) AS total FROM ingredients ${where}`,
      params
    );

    const [items] = await pool.query(
      `SELECT id, name, category, default_unit, created_at, updated_at
       FROM ingredients
       ${where}
       ORDER BY name ASC
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

// POST /ingredients
app.post("/ingredients", authRequired, async (req, res) => {
  try {
    const { name, category = null, defaultUnit = null } = req.body || {};

    if (!name || typeof name !== "string" || name.trim().length < 2) {
      return res.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "name is required (min 2 chars)" },
      });
    }

    const cleanName = name.trim();

    // prepreči duplikate po imenu (optional; če imaš unique constraint bo to 409)
    const [existing] = await pool.query("SELECT id FROM ingredients WHERE name = ? LIMIT 1", [cleanName]);
    if (existing.length > 0) {
      return res.status(409).json({
        error: { code: "CONFLICT", message: "Ingredient already exists" },
      });
    }

    const [result] = await pool.query(
      `INSERT INTO ingredients (name, category, default_unit, created_at, updated_at)
       VALUES (?, ?, ?, NOW(), NOW())`,
      [cleanName, category, defaultUnit]
    );

    return res.status(201).json({ data: { id: result.insertId } });
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
