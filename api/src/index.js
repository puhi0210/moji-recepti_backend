const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const swaggerUi = require("swagger-ui-express");
const swaggerJSDoc = require("swagger-jsdoc");
require("dotenv").config();

const app = express();
app.use(express.json());


// Swagger setup
const swaggerSpec = swaggerJSDoc({
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Moji Recepti API",
      version: "1.0.0",
    },
    servers: [{ url: "http://localhost:3000" }],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
        },
      },
    },
    tags: [
      { name: "System", description: "Health check" },
      { name: "Auth", description: "Authentication & user management" },
      { name: "Recipes", description: "Recipe CRUD" },
      { name: "Recipe Ingredients", description: "Ingredients inside recipes" },
      { name: "Ingredients", description: "Global ingredients catalog" },
      { name: "Inventory", description: "Inventory items" },
    ]

  },
  apis: ["./src/index.js"], // bere JSDoc komentarje iz index.js
});

app.use("/docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));
app.get("/openapi.json", (req, res) => res.json(swaggerSpec));


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
  // DEV MODE – avtomatski user
  if (process.env.NODE_ENV === "development" && process.env.DEV_USER_ID) {
    req.user = { sub: Number(process.env.DEV_USER_ID) };
    return next();
  }

  // === normalni JWT flow ===
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({
      error: { code: "UNAUTHORIZED", message: "Missing token" },
    });
  }

  try {
    const token = auth.slice(7);
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({
      error: { code: "UNAUTHORIZED", message: "Invalid token" },
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

// Helper to check inventory item ownership

async function assertInventoryOwnership(itemId, userId) {
  const [rows] = await pool.query(
    "SELECT id FROM inventory_items WHERE id = ? AND user_id = ? LIMIT 1",
    [itemId, userId]
  );
  return rows.length > 0;
}



/**
 * @openapi
 * components:
 *   schemas:
 *     ErrorResponse:
 *       type: object
 *       properties:
 *         error:
 *           type: object
 *           properties:
 *             code: { type: string, example: "VALIDATION_ERROR" }
 *             message: { type: string, example: "Invalid input" }
 *
 *     Tokens:
 *       type: object
 *       properties:
 *         accessToken: { type: string, example: "eyJhbGciOi..." }
 *         refreshToken: { type: string, example: "eyJhbGciOi..." }
 *
 *     User:
 *       type: object
 *       properties:
 *         id: { type: integer, format: int64, example: 1 }
 *         email: { type: string, example: "test-user@test.com" }
 *         fullName: { type: string, nullable: true, example: "Test User" }
 *
 *     RecipeListItem:
 *       type: object
 *       properties:
 *         id: { type: integer, format: int64, example: 1 }
 *         title: { type: string, example: "Palačinke" }
 *         description: { type: string, nullable: true, example: "Hitre palačinke" }
 *         servings: { type: integer, nullable: true, example: 4 }
 *         created_at: { type: string, format: date-time }
 *         updated_at: { type: string, format: date-time }
 *
 *     RecipeIngredientItem:
 *       type: object
 *       properties:
 *         id: { type: integer, format: int64, example: 10 }
 *         recipe_id: { type: integer, format: int64, example: 1 }
 *         ingredient_id: { type: integer, format: int64, example: 5 }
 *         ingredient_name: { type: string, example: "Moka" }
 *         ingredient_category: { type: string, nullable: true, example: "Osnovno" }
 *         quantity: { type: number, format: double, example: 300 }
 *         unit: { type: string, nullable: true, example: "g" }
 *         note: { type: string, nullable: true, example: "Tip 500" }
 *         created_at: { type: string, format: date-time }
 *         updated_at: { type: string, format: date-time }
 *
 *     InventoryItem:
 *       type: object
 *       properties:
 *         id: { type: integer, format: int64, example: 1 }
 *         user_id: { type: integer, format: int64, example: 1 }
 *         ingredient_id: { type: integer, format: int64, nullable: true, example: 5 }
 *         ingredient_name: { type: string, nullable: true, example: "Mleko" }
 *         custom_name: { type: string, nullable: true, example: "Bio jajca" }
 *         quantity: { type: number, format: double, example: 2 }
 *         unit: { type: string, example: "L" }
 *         location: { type: string, example: "FRIDGE" }
 *         expires_at: { type: string, format: date, nullable: true, example: "2026-02-01" }
 *         min_quantity: { type: number, format: double, nullable: true, example: 0.5 }
 *         created_at: { type: string, format: date-time }
 *         updated_at: { type: string, format: date-time }
 * 
 *     ShoppingList:
 *       type: object
 *       properties:
 *         id: { type: integer, format: int64, example: 12 }
 *         user_id: { type: integer, format: int64, example: 1 }
 *         name: { type: string, example: "Mercator - sobota" }
 *         status: { type: string, example: "active" }
 *         created_at: { type: string, format: date-time }
 *         updated_at: { type: string, format: date-time }
 *
 *     ShoppingListItem:
 *       type: object
 *       properties:
 *         id: { type: integer, format: int64, example: 88 }
 *         shopping_list_id: { type: integer, format: int64, example: 12 }
 *         ingredient_id: { type: integer, format: int64, nullable: true, example: 5 }
 *         ingredient_name: { type: string, nullable: true, example: "Moka" }
 *         custom_name: { type: string, nullable: true, example: "Papirnate brisače" }
 *         quantity: { type: number, nullable: true, example: 1 }
 *         unit: { type: string, nullable: true, example: "kg" }
 *         is_checked: { type: integer, example: 0, description: "0/1" }
 *         from_recipe_id: { type: integer, format: int64, nullable: true, example: 3 }
 *         created_at: { type: string, format: date-time }
 *         updated_at: { type: string, format: date-time }
 *
 *     ShoppingListsPage:
 *       type: object
 *       properties:
 *         items:
 *           type: array
 *           items: { $ref: '#/components/schemas/ShoppingList' }
 *         page: { type: integer, example: 1 }
 *         pageSize: { type: integer, example: 20 }
 *         total: { type: integer, example: 3 }
 *
 *     ShoppingListItemsPage:
 *       type: object
 *       properties:
 *         items:
 *           type: array
 *           items: { $ref: '#/components/schemas/ShoppingListItem' }
 *         page: { type: integer, example: 1 }
 *         pageSize: { type: integer, example: 50 }
 *         total: { type: integer, example: 8 }
 *
 *   responses:
 *     Unauthorized:
 *       description: Unauthorized (missing/invalid token)
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/ErrorResponse'
 *     ValidationError:
 *       description: Validation error
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/ErrorResponse'
 *     NotFound:
 *       description: Resource not found
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/ErrorResponse'
 *     Conflict:
 *       description: Conflict (duplicate)
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/ErrorResponse'
 */



// API routes

// Health check
/**
 * @openapi
 * /health:
 *   get:
 *     tags: [System]
 *     summary: Health check + DB connectivity test
 *     responses:
 *       200:
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status: { type: string, example: "ok" }
 *                 db:
 *                   type: object
 *                   properties:
 *                     ok: { type: integer, example: 1 }
 *       500:
 *         description: DB or server error
 */
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
/**
 * @openapi
 * /auth/register:
 *   post:
 *     tags: [Auth]
 *     summary: Registracija uporabnika
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password, fullName]
 *             properties:
 *               email:
 *                 type: string
 *                 example: test-user@test.com
 *               password:
 *                 type: string
 *                 example: SuperGeslo123!
 *               fullName:
 *                 type: string
 *                 example: Test User
 *     responses:
 *       201:
 *         description: Created
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   type: object
 *                   properties:
 *                     user:
 *                       $ref: '#/components/schemas/User'
 *                     tokens:
 *                       $ref: '#/components/schemas/Tokens'
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       409:
 *         $ref: '#/components/responses/Conflict'
 *       500:
 *         description: Server error
 */

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
/**
 * @openapi
 * /auth/login:
 *   post:
 *     tags: [Auth]
 *     summary: Login user and receive tokens
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email: { type: string, example: "test-user@test.com" }
 *               password: { type: string, example: "SuperGeslo123!" }
 *     responses:
 *       200:
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   type: object
 *                   properties:
 *                     user:
 *                       $ref: '#/components/schemas/User'
 *                     tokens:
 *                       $ref: '#/components/schemas/Tokens'
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/Unauthorized'
 *       500:
 *         description: Server error
 */
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
/**
 * @openapi
 * /auth/refresh:
 *   post:
 *     tags: [Auth]
 *     summary: Osveži access token (in običajno tudi refresh token)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [refreshToken]
 *             properties:
 *               refreshToken:
 *                 type: string
 *                 example: eyJhbGciOi...
 *     responses:
 *       200:
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   type: object
 *                   properties:
 *                     tokens:
 *                       $ref: '#/components/schemas/Tokens'
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/Unauthorized'
 *       500:
 *         description: Server error
 */
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
/**
 * @openapi
 * /auth/me:
 *   get:
 *     tags: [Auth]
 *     summary: Podatki prijavljenega uporabnika
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   $ref: '#/components/schemas/User'
 *       401:
 *         $ref: '#/components/responses/Unauthorized'
 *       500:
 *         description: Server error
 */
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
/**
 * @openapi
 * /recipes:
 *   get:
 *     tags: [Recipes]
 *     summary: Seznam receptov (s pagination + search)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: search
 *         schema: { type: string }
 *         description: Išče po title/description (LIKE %search%)
 *       - in: query
 *         name: page
 *         schema: { type: integer, minimum: 1, default: 1 }
 *       - in: query
 *         name: pageSize
 *         schema: { type: integer, minimum: 1, maximum: 100, default: 20 }
 *     responses:
 *       200:
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   type: object
 *                   properties:
 *                     items:
 *                       type: array
 *                       items: { $ref: '#/components/schemas/RecipeListItem' }
 *                     page: { type: integer, example: 1 }
 *                     pageSize: { type: integer, example: 20 }
 *                     total: { type: integer, example: 3 }
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       500:
 *         description: Server error
 */
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
/**
 * @openapi
 * /recipes:
 *   post:
 *     tags: [Recipes]
 *     summary: Ustvari recept
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [title]
 *             properties:
 *               title: { type: string, example: "Palačinke" }
 *               description: { type: string, nullable: true, example: "Hitre" }
 *               instructions: { type: string, nullable: true, example: "Zmešaj..." }
 *               prepTimeMinutes: { type: integer, nullable: true, example: 10 }
 *               cookTimeMinutes: { type: integer, nullable: true, example: 10 }
 *               servings: { type: integer, nullable: true, example: 4 }
 *               isPublic: { type: integer, example: 0, description: "0/1" }
 *     responses:
 *       201:
 *         description: Created
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   type: object
 *                   properties:
 *                     id: { type: integer, format: int64, example: 1 }
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       500:
 *         description: Server error
 */
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
/**
 * @openapi
 * /recipes/{id}:
 *   get:
 *     tags: [Recipes]
 *     summary: Vrne recept + njegove sestavine (recipe_ingredients)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer, format: int64 }
 *     responses:
 *       200:
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   type: object
 *                   properties:
 *                     recipe: { $ref: '#/components/schemas/Recipe' }
 *                     ingredients:
 *                       type: array
 *                       items:
 *                         type: object
 *                         properties:
 *                           recipeIngredientId: { type: integer, format: int64 }
 *                           ingredientId: { type: integer, format: int64 }
 *                           ingredientName: { type: string }
 *                           ingredientCategory: { type: string, nullable: true }
 *                           quantity: { type: number }
 *                           unit: { type: string, nullable: true }
 *                           note: { type: string, nullable: true }
 *                           created_at: { type: string, format: date-time }
 *                           updated_at: { type: string, format: date-time }
 *       400:
 *         description: Invalid id
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       404:
 *         description: Not found (ni tvoj recept ali ne obstaja)
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       500:
 *         description: Server error
 */
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
/**
 * @openapi
 * /recipes/{id}:
 *   patch:
 *     tags: [Recipes]
 *     summary: Posodobi recept (partial update)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer, format: int64 }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             description: "Pošlji samo polja, ki jih spreminjaš."
 *             properties:
 *               title: { type: string, example: "Nove palačinke" }
 *               description: { type: string, nullable: true }
 *               instructions: { type: string, nullable: true }
 *               prepTimeMinutes: { type: integer, nullable: true }
 *               cookTimeMinutes: { type: integer, nullable: true }
 *               servings: { type: integer, nullable: true }
 *               isPublic: { type: integer, example: 1 }
 *     responses:
 *       200:
 *         description: Updated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   type: object
 *                   properties:
 *                     updated: { type: boolean, example: true }
 *       400:
 *         description: Validation error / no fields
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       404:
 *         description: Recipe not found
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       500:
 *         description: Server error
 */
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
/**
 * @openapi
 * /recipes/{id}:
 *   delete:
 *     tags: [Recipes]
 *     summary: Izbriše recept
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer, format: int64 }
 *     responses:
 *       204:
 *         description: Deleted
 *       400:
 *         description: Invalid id
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       404:
 *         description: Recipe not found
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       500:
 *         description: Server error
 */
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
/**
 * @openapi
 * /recipes/{id}/ingredients:
 *   get:
 *     tags: [Recipe Ingredients]
 *     summary: Seznam sestavin recepta (recipe_ingredients)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer, format: int64 }
 *     responses:
 *       200:
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   type: object
 *                   properties:
 *                     items:
 *                       type: array
 *                       items: { $ref: '#/components/schemas/RecipeIngredientItem' }
 *       400:
 *         description: Invalid recipe id
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       404:
 *         description: Recipe not found (ni tvoj)
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       500:
 *         description: Server error
 */
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
/**
 * @openapi
 * /recipes/{id}/ingredients:
 *   post:
 *     tags: [Recipe Ingredients]
 *     summary: Doda sestavino v recept (po ingredientId ali ingredientName)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer, format: int64 }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [quantity]
 *             properties:
 *               ingredientId:
 *                 type: integer
 *                 format: int64
 *                 nullable: true
 *                 example: 5
 *               ingredientName:
 *                 type: string
 *                 nullable: true
 *                 example: "Moka"
 *               quantity:
 *                 type: number
 *                 example: 200
 *               unit:
 *                 type: string
 *                 nullable: true
 *                 example: "g"
 *               note:
 *                 type: string
 *                 nullable: true
 *                 example: "tip 500"
 *           examples:
 *             byId:
 *               value: { "ingredientId": 5, "quantity": 200, "unit": "g", "note": "tip 500" }
 *             byName:
 *               value: { "ingredientName": "Moka", "quantity": 200, "unit": "g" }
 *     responses:
 *       201:
 *         description: Created
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   type: object
 *                   properties:
 *                     id: { type: integer, format: int64, example: 12 }
 *       400:
 *         description: Validation error (quantity, ingredientId/ingredientName)
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       404:
 *         description: Recipe not found
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       500:
 *         description: Server error
 */
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
/**
 * @openapi
 * /recipes/{id}/ingredients/{riId}:
 *   patch:
 *     tags: [Recipe Ingredients]
 *     summary: Posodobi postavko recipe_ingredients (quantity/unit/note)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer, format: int64 }
 *       - in: path
 *         name: riId
 *         required: true
 *         schema: { type: integer, format: int64 }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               quantity: { type: number, example: 250 }
 *               unit: { type: string, example: "g" }
 *               note: { type: string, nullable: true, example: "polnozrnata" }
 *     responses:
 *       200:
 *         description: Updated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   type: object
 *                   properties:
 *                     updated: { type: boolean, example: true }
 *       400:
 *         description: Validation error / no fields
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       404:
 *         description: Recipe ali recipe ingredient ne obstaja
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       500:
 *         description: Server error
 */
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
/**
 * @openapi
 * /recipes/{id}/ingredients/{riId}:
 *   delete:
 *     tags: [Recipe Ingredients]
 *     summary: Izbriše postavko iz recepta (recipe_ingredients)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer, format: int64 }
 *       - in: path
 *         name: riId
 *         required: true
 *         schema: { type: integer, format: int64 }
 *     responses:
 *       204:
 *         description: Deleted
 *       400:
 *         description: Invalid id
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       404:
 *         description: Recipe ali recipe ingredient not found
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       500:
 *         description: Server error
 */
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
/**
 * @openapi
 * /ingredients:
 *   get:
 *     tags: [Ingredients]
 *     summary: Globalni seznam sestavin (search + pagination)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: search
 *         schema: { type: string }
 *         description: Išče po name/category
 *       - in: query
 *         name: page
 *         schema: { type: integer, minimum: 1, default: 1 }
 *       - in: query
 *         name: pageSize
 *         schema: { type: integer, minimum: 1, maximum: 100, default: 20 }
 *     responses:
 *       200:
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   type: object
 *                   properties:
 *                     items:
 *                       type: array
 *                       items: { $ref: '#/components/schemas/IngredientListItem' }
 *                     page: { type: integer }
 *                     pageSize: { type: integer }
 *                     total: { type: integer }
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       500:
 *         description: Server error
 */
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
/**
 * @openapi
 * /ingredients:
 *   post:
 *     tags: [Ingredients]
 *     summary: Ustvari globalno sestavino
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name]
 *             properties:
 *               name: { type: string, example: "Moka" }
 *               category: { type: string, nullable: true, example: "Suho" }
 *               defaultUnit: { type: string, nullable: true, example: "g" }
 *     responses:
 *       201:
 *         description: Created
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   type: object
 *                   properties:
 *                     id: { type: integer, format: int64, example: 5 }
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       409:
 *         description: Conflict (ingredient že obstaja)
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       500:
 *         description: Server error
 */
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


// ----------------------------------------------
// INVENTORY MANAGEMENT
// ----------------------------------------------

// GET /inventory/items
/**
 * @openapi
 * /inventory/items:
 *   get:
 *     tags: [Inventory]
 *     summary: Seznam inventory itemov (filtri + pagination)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: search
 *         schema: { type: string }
 *         description: Išče po ingredient name ali custom_name
 *       - in: query
 *         name: location
 *         schema: { type: string }
 *         description: Npr. fridge/pantry (po tvojem dogovoru)
 *       - in: query
 *         name: lowStockOnly
 *         schema: { type: boolean, default: false }
 *       - in: query
 *         name: expiresBefore
 *         schema: { type: string, format: date }
 *         description: Vrne iteme, ki jim poteče do vključno tega datuma
 *       - in: query
 *         name: page
 *         schema: { type: integer, minimum: 1, default: 1 }
 *       - in: query
 *         name: pageSize
 *         schema: { type: integer, minimum: 1, maximum: 100, default: 20 }
 *     responses:
 *       200:
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   type: object
 *                   properties:
 *                     items:
 *                       type: array
 *                       items: { $ref: '#/components/schemas/InventoryItem' }
 *                     page: { type: integer }
 *                     pageSize: { type: integer }
 *                     total: { type: integer }
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       500:
 *         description: Server error
 */
app.get("/inventory/items", authRequired, async (req, res) => {
  try {
    const userId = Number(req.user.sub);

    const search = (req.query.search || "").toString().trim();
    const location = (req.query.location || "").toString().trim();
    const lowStockOnly = (req.query.lowStockOnly || "").toString() === "true";
    const expiresBefore = (req.query.expiresBefore || "").toString().trim();

    const page = Math.max(1, parseInt(req.query.page || "1", 10));
    const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize || "20", 10)));
    const offset = (page - 1) * pageSize;

    let where = "WHERE ii.user_id = ?";
    const params = [userId];

    if (location) {
      where += " AND ii.location = ?";
      params.push(location);
    }

    if (expiresBefore) {
      where += " AND ii.expires_at IS NOT NULL AND ii.expires_at <= ?";
      params.push(expiresBefore);
    }

    if (lowStockOnly) {
      where += " AND ii.min_quantity IS NOT NULL AND ii.quantity <= ii.min_quantity";
    }

    if (search) {
      where += " AND (COALESCE(i.name, ii.custom_name) LIKE ?)";
      params.push(`%${search}%`);
    }

    const [countRows] = await pool.query(
      `SELECT COUNT(*) AS total
       FROM inventory_items ii
       LEFT JOIN ingredients i ON i.id = ii.ingredient_id
       ${where}`,
      params
    );

    const [items] = await pool.query(
      `SELECT
         ii.id,
         ii.user_id,
         ii.ingredient_id,
         i.name AS ingredient_name,
         ii.custom_name,
         ii.quantity,
         ii.unit,
         ii.location,
         ii.expires_at,
         ii.min_quantity,
         ii.created_at,
         ii.updated_at
       FROM inventory_items ii
       LEFT JOIN ingredients i ON i.id = ii.ingredient_id
       ${where}
       ORDER BY
         (ii.expires_at IS NULL) ASC,
         ii.expires_at ASC,
         COALESCE(i.name, ii.custom_name) ASC
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

// GET /inventory/items/:id
/**
 * @openapi
 * /inventory/items/{id}:
 *   get:
 *     tags: [Inventory]
 *     summary: Vrne en inventory item
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer, format: int64 }
 *     responses:
 *       200:
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data: { $ref: '#/components/schemas/InventoryItem' }
 *       400:
 *         description: Invalid id
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       404:
 *         description: Inventory item not found
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       500:
 *         description: Server error
 */
app.get("/inventory/items/:id", authRequired, async (req, res) => {
  try {
    const userId = Number(req.user.sub);
    const itemId = Number(req.params.id);

    if (!Number.isInteger(itemId)) {
      return res.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Invalid id" } });
    }

    const [rows] = await pool.query(
      `SELECT
         ii.id,
         ii.user_id,
         ii.ingredient_id,
         i.name AS ingredient_name,
         ii.custom_name,
         ii.quantity,
         ii.unit,
         ii.location,
         ii.expires_at,
         ii.min_quantity,
         ii.created_at,
         ii.updated_at
       FROM inventory_items ii
       LEFT JOIN ingredients i ON i.id = ii.ingredient_id
       WHERE ii.id = ? AND ii.user_id = ?
       LIMIT 1`,
      [itemId, userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: { code: "NOT_FOUND", message: "Inventory item not found" } });
    }

    return res.status(200).json({ data: rows[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: { code: "INTERNAL_ERROR", message: err.message } });
  }
});


// POST /inventory/items
/**
 * @openapi
 * /inventory/items:
 *   post:
 *     tags: [Inventory]
 *     summary: Ustvari inventory item (ingredientId ali customName)
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [quantity, unit, location]
 *             properties:
 *               ingredientId: { type: integer, format: int64, nullable: true, example: 5 }
 *               customName: { type: string, nullable: true, example: "Kruh" }
 *               quantity: { type: number, example: 1 }
 *               unit: { type: string, example: "kos" }
 *               location: { type: string, example: "pantry" }
 *               expiresAt: { type: string, format: date, nullable: true, example: "2026-02-10" }
 *               minQuantity: { type: number, nullable: true, example: 1 }
 *           description: "Moraš poslati ingredientId ALI customName."
 *     responses:
 *       201:
 *         description: Created
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   type: object
 *                   properties:
 *                     id: { type: integer, format: int64, example: 101 }
 *       400:
 *         description: Validation error (npr ingredientId ne obstaja)
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       500:
 *         description: Server error
 */
app.post("/inventory/items", authRequired, async (req, res) => {
  try {
    const userId = Number(req.user.sub);

    const {
      ingredientId = null,
      customName = null,
      quantity,
      unit,
      location,
      expiresAt = null,
      minQuantity = null,
    } = req.body || {};

    const q = Number(quantity);
    if (!Number.isFinite(q) || q < 0) {
      return res.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "quantity must be a number >= 0" },
      });
    }

    if (!unit || typeof unit !== "string") {
      return res.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "unit is required" },
      });
    }

    if (!location || typeof location !== "string") {
      return res.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "location is required" },
      });
    }

    // must have either ingredientId or customName
    if (!ingredientId && (!customName || typeof customName !== "string" || customName.trim().length < 2)) {
      return res.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "ingredientId or customName is required" },
      });
    }

    // if ingredientId provided, optionally verify it exists
    if (ingredientId) {
      const [found] = await pool.query("SELECT id FROM ingredients WHERE id = ? LIMIT 1", [ingredientId]);
      if (found.length === 0) {
        return res.status(400).json({
          error: { code: "VALIDATION_ERROR", message: "ingredientId does not exist" },
        });
      }
    }

    const [result] = await pool.query(
      `INSERT INTO inventory_items
       (user_id, ingredient_id, custom_name, quantity, unit, location, expires_at, min_quantity, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
      [userId, ingredientId, customName ? customName.trim() : null, q, unit, location, expiresAt, minQuantity]
    );

    return res.status(201).json({ data: { id: result.insertId } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: { code: "INTERNAL_ERROR", message: err.message } });
  }
});

// PATCH /inventory/items/:id
/**
 * @openapi
 * /inventory/items/{id}:
 *   patch:
 *     tags: [Inventory]
 *     summary: Posodobi inventory item (partial)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer, format: int64 }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               quantity: { type: number, example: 2 }
 *               unit: { type: string, example: "kos" }
 *               location: { type: string, example: "fridge" }
 *               expiresAt: { type: string, format: date, nullable: true }
 *               minQuantity: { type: number, nullable: true, example: 1 }
 *               customName: { type: string, nullable: true, example: "Kruh" }
 *     responses:
 *       200:
 *         description: Updated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   type: object
 *                   properties:
 *                     updated: { type: boolean, example: true }
 *       400:
 *         description: Validation error / no fields
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       404:
 *         description: Inventory item not found
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       500:
 *         description: Server error
 */
app.patch("/inventory/items/:id", authRequired, async (req, res) => {
  try {
    const userId = Number(req.user.sub);
    const itemId = Number(req.params.id);

    if (!Number.isInteger(itemId)) {
      return res.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Invalid id" } });
    }

    const ok = await assertInventoryOwnership(itemId, userId);
    if (!ok) {
      return res.status(404).json({ error: { code: "NOT_FOUND", message: "Inventory item not found" } });
    }

    const { quantity, unit, location, expiresAt, minQuantity, customName } = req.body || {};

    const updates = [];
    const params = [];

    if (quantity !== undefined) {
      const q = Number(quantity);
      if (!Number.isFinite(q) || q < 0) {
        return res.status(400).json({
          error: { code: "VALIDATION_ERROR", message: "quantity must be a number >= 0" },
        });
      }
      updates.push("quantity = ?");
      params.push(q);
    }

    if (unit !== undefined) {
      updates.push("unit = ?");
      params.push(unit);
    }

    if (location !== undefined) {
      updates.push("location = ?");
      params.push(location);
    }

    if (expiresAt !== undefined) {
      updates.push("expires_at = ?");
      params.push(expiresAt);
    }

    if (minQuantity !== undefined) {
      updates.push("min_quantity = ?");
      params.push(minQuantity);
    }

    if (customName !== undefined) {
      if (customName !== null && (typeof customName !== "string" || customName.trim().length < 2)) {
        return res.status(400).json({
          error: { code: "VALIDATION_ERROR", message: "customName must be null or min 2 chars" },
        });
      }
      updates.push("custom_name = ?");
      params.push(customName ? customName.trim() : null);
    }

    if (updates.length === 0) {
      return res.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "No fields to update" },
      });
    }

    updates.push("updated_at = NOW()");
    params.push(itemId, userId);

    const [result] = await pool.query(
      `UPDATE inventory_items
       SET ${updates.join(", ")}
       WHERE id = ? AND user_id = ?`,
      params
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: { code: "NOT_FOUND", message: "Inventory item not found" } });
    }

    return res.status(200).json({ data: { updated: true } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: { code: "INTERNAL_ERROR", message: err.message } });
  }
});


// DELETE /inventory/items/:id
/**
 * @openapi
 * /inventory/items/{id}:
 *   delete:
 *     tags: [Inventory]
 *     summary: Izbriše inventory item
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer, format: int64 }
 *     responses:
 *       204:
 *         description: Deleted
 *       400:
 *         description: Invalid id
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       404:
 *         description: Inventory item not found
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       500:
 *         description: Server error
 */
app.delete("/inventory/items/:id", authRequired, async (req, res) => {
  try {
    const userId = Number(req.user.sub);
    const itemId = Number(req.params.id);

    if (!Number.isInteger(itemId)) {
      return res.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Invalid id" } });
    }

    const [result] = await pool.query(
      "DELETE FROM inventory_items WHERE id = ? AND user_id = ?",
      [itemId, userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: { code: "NOT_FOUND", message: "Inventory item not found" } });
    }

    return res.status(204).send();
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: { code: "INTERNAL_ERROR", message: err.message } });
  }
});


// GET /inventory/low-stock
/**
 * @openapi
 * /inventory/low-stock:
 *   get:
 *     tags: [Inventory]
 *     summary: Seznam artiklov, ki jih zmanjkuje (quantity <= min_quantity)
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   type: object
 *                   properties:
 *                     items:
 *                       type: array
 *                       items: { $ref: '#/components/schemas/InventoryItem' }
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       500:
 *         description: Server error
 */
app.get("/inventory/low-stock", authRequired, async (req, res) => {
  try {
    const userId = Number(req.user.sub);

    const [items] = await pool.query(
      `SELECT
         ii.id,
         ii.ingredient_id,
         i.name AS ingredient_name,
         ii.custom_name,
         ii.location,
         ii.quantity,
         ii.unit,
         ii.min_quantity,
         ii.updated_at
       FROM inventory_items ii
       LEFT JOIN ingredients i ON i.id = ii.ingredient_id
       WHERE ii.user_id = ?
         AND ii.min_quantity IS NOT NULL
         AND ii.quantity <= ii.min_quantity
       ORDER BY COALESCE(i.name, ii.custom_name) ASC`,
      [userId]
    );

    return res.status(200).json({ data: { items } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: { code: "INTERNAL_ERROR", message: err.message } });
  }
});


// GET /inventory/expiring
/**
 * @openapi
 * /inventory/expiring:
 *   get:
 *     tags: [Inventory]
 *     summary: Artikli, ki jim poteče rok v naslednjih N dneh
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: days
 *         schema: { type: integer, minimum: 1, maximum: 365, default: 7 }
 *     responses:
 *       200:
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   type: object
 *                   properties:
 *                     days: { type: integer, example: 7 }
 *                     items:
 *                       type: array
 *                       items: { $ref: '#/components/schemas/InventoryItem' }
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/Error' }
 *       500:
 *         description: Server error
 */
app.get("/inventory/expiring", authRequired, async (req, res) => {
  try {
    const userId = Number(req.user.sub);
    const days = Math.min(365, Math.max(1, parseInt(req.query.days || "7", 10)));

    const [items] = await pool.query(
      `SELECT
         ii.id,
         ii.ingredient_id,
         i.name AS ingredient_name,
         ii.custom_name,
         ii.location,
         ii.quantity,
         ii.unit,
         ii.expires_at
       FROM inventory_items ii
       LEFT JOIN ingredients i ON i.id = ii.ingredient_id
       WHERE ii.user_id = ?
         AND ii.expires_at IS NOT NULL
         AND ii.expires_at <= DATE_ADD(CURDATE(), INTERVAL ? DAY)
       ORDER BY ii.expires_at ASC, COALESCE(i.name, ii.custom_name) ASC`,
      [userId, days]
    );

    return res.status(200).json({ data: { days, items } });
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
