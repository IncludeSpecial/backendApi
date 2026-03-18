// Load environment variables from project .env (dev)
try {
  require("dotenv").config({ path: require("path").join(process.cwd(), ".env") });
} catch {}

const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const path = require("path");
const crypto = require("crypto");

const app = express();
const isProd = process.env.NODE_ENV === "production";
const corsOriginEnv = process.env.CORS_ORIGIN || "";
const allowedOrigins = corsOriginEnv
  ? corsOriginEnv
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
  : [];
app.use(
  cors({
    origin: (origin, cb) => {
      // allow same-origin / server-side / curl
      if (!origin) return cb(null, true);
      if (!isProd) return cb(null, true);
      if (allowedOrigins.length === 0) return cb(null, false);
      return cb(null, allowedOrigins.includes(origin));
    },
    credentials: true,
  })
);
app.use(cookieParser());
app.use(express.json({ limit: "256kb" }));

const dbPath = path.join(__dirname, "data.db");
const db = new Database(dbPath);

const ALLOWED_TABLES = new Set(["users", "entries", "content"]);
const ALLOWED_COLS = new Set(["role", "username", "display_name", "bio", "avatar_url", "user_id"]);

function colExists(table, col) {
  if (!ALLOWED_TABLES.has(table) || !ALLOWED_COLS.has(col)) return false;
  try {
    const cols = db.prepare(`PRAGMA table_info("${table}")`).all();
    return cols.some((c) => c.name === col);
  } catch {
    return false;
  }
}

function ensureUsersAndMigrations() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      pass_hash TEXT NOT NULL,
      pass_salt TEXT NOT NULL,
      pass_iter INTEGER NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      username TEXT,
      display_name TEXT,
      bio TEXT,
      avatar_url TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
  `);

  // Migrate existing DBs that were created before profile/role fields
  if (!colExists("users", "role")) db.exec(`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'`);
  if (!colExists("users", "username")) db.exec(`ALTER TABLE users ADD COLUMN username TEXT`);
  if (!colExists("users", "display_name")) db.exec(`ALTER TABLE users ADD COLUMN display_name TEXT`);
  if (!colExists("users", "bio")) db.exec(`ALTER TABLE users ADD COLUMN bio TEXT`);
  if (!colExists("users", "avatar_url")) db.exec(`ALTER TABLE users ADD COLUMN avatar_url TEXT`);
  db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_unique ON users(username)`);

  db.exec(`
    CREATE TABLE IF NOT EXISTS password_resets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      token_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_password_resets_email ON password_resets(email);
  `);

  // Forum
  db.exec(`
    CREATE TABLE IF NOT EXISTS forum_threads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      author_user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      body TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_forum_threads_created_at ON forum_threads(created_at);

    CREATE TABLE IF NOT EXISTS forum_posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      thread_id INTEGER NOT NULL,
      author_user_id INTEGER NOT NULL,
      body TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_forum_posts_thread_id ON forum_posts(thread_id);
    CREATE INDEX IF NOT EXISTS idx_forum_posts_created_at ON forum_posts(created_at);
  `);

  // Ensure entries table exists first (legacy schema compatible)
  db.exec(`
    CREATE TABLE IF NOT EXISTS entries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL CHECK(type IN ('income','expense')),
      amount REAL NOT NULL,
      category TEXT NOT NULL,
      note TEXT,
      date TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );
  `);

  // Ensure content exists (legacy)
  db.exec(`
    CREATE TABLE IF NOT EXISTS content (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key TEXT UNIQUE NOT NULL,
      value TEXT,
      updated_at TEXT DEFAULT (datetime('now'))
    );
  `);

  // Create/ensure a legacy user to own old data
  let legacy = db.prepare("SELECT id FROM users WHERE email = ?").get("legacy@local");
  if (!legacy) {
    const salt = crypto.randomBytes(16).toString("hex");
    const iter = 150000;
    const hash = crypto.pbkdf2Sync("legacy", salt, iter, 32, "sha256").toString("hex");
    const r = db.prepare("INSERT INTO users (email, pass_hash, pass_salt, pass_iter) VALUES (?, ?, ?, ?)").run("legacy@local", hash, salt, iter);
    legacy = { id: Number(r.lastInsertRowid) };
  }
  const legacyUserId = Number(legacy.id);

  // Ensure legacy user has a username
  const legacyU = db.prepare("SELECT username FROM users WHERE id = ?").get(legacyUserId);
  if (!legacyU || !legacyU.username) {
    db.prepare("UPDATE users SET username = ?, display_name = ? WHERE id = ?").run("legacy", "Legacy", legacyUserId);
  }

  // Optional: seed hidden admin account from env
  const adminEmail = normalizeEmail(process.env.ADMIN_EMAIL || "");
  const adminPass = safeStr(process.env.ADMIN_PASSWORD || "");
  if (adminEmail && adminPass && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(adminEmail) && adminPass.length >= 6) {
    const existingAdmin = db.prepare("SELECT id FROM users WHERE email = ?").get(adminEmail);
    if (!existingAdmin) {
      const salt = crypto.randomBytes(16).toString("hex");
      const iter = 150000;
      const passHash = crypto.pbkdf2Sync(adminPass, salt, iter, 32, "sha256").toString("hex");
      const userPart = adminEmail.split("@")[0].replace(/[^a-z0-9_]+/gi, "").slice(0, 24) || "admin";
      const uname = userPart + "_admin";
      db.prepare(
        "INSERT INTO users (email, pass_hash, pass_salt, pass_iter, role, username, display_name) VALUES (?, ?, ?, ?, 'admin', ?, ?)"
      ).run(adminEmail, passHash, salt, iter, uname, "Admin");
    } else {
      db.prepare("UPDATE users SET role = 'admin' WHERE email = ?").run(adminEmail);
    }
  }

  // entries: add user_id and backfill
  if (!colExists("entries", "user_id")) {
    db.exec(`ALTER TABLE entries ADD COLUMN user_id INTEGER`);
    db.prepare("UPDATE entries SET user_id = ? WHERE user_id IS NULL").run(legacyUserId);
  }

  // content: rebuild table to change unique(key) -> unique(user_id, key)
  // If user_id doesn't exist, we'll rebuild. If it exists but unique is old, rebuilding is still safe.
  if (!colExists("content", "user_id")) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS content_new (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        key TEXT NOT NULL,
        value TEXT,
        updated_at TEXT DEFAULT (datetime('now')),
        UNIQUE(user_id, key)
      );
    `);
    const rows = db.prepare("SELECT id, key, value, updated_at FROM content").all();
    const ins = db.prepare("INSERT OR IGNORE INTO content_new (user_id, key, value, updated_at) VALUES (?, ?, ?, ?)");
    const tx = db.transaction(() => {
      for (const r of rows) ins.run(legacyUserId, r.key, r.value, r.updated_at);
    });
    tx();
    db.exec("DROP TABLE content;");
    db.exec("ALTER TABLE content_new RENAME TO content;");
  }
}

ensureUsersAndMigrations();

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const AUTH_COOKIE = "toolhub_auth";
const COOKIE_DOMAIN = (process.env.COOKIE_DOMAIN || "").trim() || undefined;
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || "").trim()
  ? ["1", "true", "yes", "on"].includes(String(process.env.COOKIE_SECURE).toLowerCase())
  : isProd;
const COOKIE_SAMESITE = (process.env.COOKIE_SAMESITE || "").trim() || "lax";

function safeStr(v) {
  return v == null ? "" : String(v);
}

function normalizeEmail(email) {
  return safeStr(email).trim().toLowerCase();
}

function pbkdf2HashPassword(password, saltHex, iter) {
  const salt = Buffer.from(saltHex, "hex");
  return crypto.pbkdf2Sync(Buffer.from(safeStr(password), "utf8"), salt, iter, 32, "sha256").toString("hex");
}

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { algorithm: "HS256", expiresIn: "7d" });
}

function setAuthCookie(res, token) {
  res.cookie(AUTH_COOKIE, token, {
    httpOnly: true,
    sameSite: COOKIE_SAMESITE,
    secure: COOKIE_SECURE,
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000,
    ...(COOKIE_DOMAIN ? { domain: COOKIE_DOMAIN } : null),
  });
}

function clearAuthCookie(res) {
  res.cookie(AUTH_COOKIE, "", {
    httpOnly: true,
    sameSite: COOKIE_SAMESITE,
    secure: COOKIE_SECURE,
    path: "/",
    maxAge: 0,
    ...(COOKIE_DOMAIN ? { domain: COOKIE_DOMAIN } : null),
  });
}

function authOptional(req, _res, next) {
  try {
    const cookieToken = req.cookies ? req.cookies[AUTH_COOKIE] : null;
    const authH = safeStr(req.headers.authorization || "");
    const bearer = authH.toLowerCase().startsWith("bearer ") ? authH.slice(7).trim() : "";
    const token = cookieToken || bearer;
    if (!token) {
      req.user = null;
      return next();
    }
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
    let u = decoded && typeof decoded === "object" ? decoded : null;
    // Backfill role/username from DB for older tokens
    if (u && u.sub && (!u.role || !u.username)) {
      try {
        const row = db.prepare("SELECT role, username, display_name FROM users WHERE id = ?").get(Number(u.sub));
        if (row) u = { ...u, role: row.role, username: row.username, display_name: row.display_name };
      } catch {}
    }
    req.user = u;
    return next();
  } catch {
    req.user = null;
    return next();
  }
}

function requireAuth(req, res, next) {
  if (!req.user || !req.user.sub) return res.status(401).json({ error: "Unauthorized" });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || !req.user.sub) return res.status(401).json({ error: "Unauthorized" });
  if (req.user.role !== "admin") return res.status(403).json({ error: "Forbidden" });
  next();
}

app.use(authOptional);

function slugUsernameFromEmail(email) {
  const base = normalizeEmail(email).split("@")[0] || "user";
  return base
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 24) || "user";
}

function pickUsernameUnique(base) {
  let u = base || "user";
  for (let i = 0; i < 50; i++) {
    const candidate = i === 0 ? u : `${u}${i}`;
    const row = db.prepare("SELECT id FROM users WHERE username = ?").get(candidate);
    if (!row) return candidate;
  }
  return `${u}_${crypto.randomBytes(2).toString("hex")}`;
}

// Auth API
app.post("/api/auth/register", (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = safeStr(req.body?.password);
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Invalid email" });
  if (!password || password.length < 6) return res.status(400).json({ error: "Password too short (min 6)" });
  try {
    const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
    if (existing) return res.status(409).json({ error: "Email already registered" });
    const salt = crypto.randomBytes(16).toString("hex");
    const iter = 150000;
    const passHash = pbkdf2HashPassword(password, salt, iter);
    const usernameBase = slugUsernameFromEmail(email);
    const username = pickUsernameUnique(usernameBase);
    const displayName = usernameBase;
    const r = db
      .prepare("INSERT INTO users (email, pass_hash, pass_salt, pass_iter, role, username, display_name) VALUES (?, ?, ?, ?, 'user', ?, ?)")
      .run(email, passHash, salt, iter, username, displayName);
    const userId = Number(r.lastInsertRowid);
    const token = signToken({ sub: String(userId), email, role: "user", username, display_name: displayName });
    setAuthCookie(res, token);
    return res.status(201).json({ ok: true, user: { id: userId, email, username, role: "user" } });
  } catch (e) {
    return res.status(500).json({ error: String(e.message) });
  }
});

app.post("/api/auth/login", (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = safeStr(req.body?.password);
  if (!email || !password) return res.status(400).json({ error: "Missing email or password" });
  try {
    const u = db.prepare("SELECT id, email, pass_hash, pass_salt, pass_iter, role, username, display_name FROM users WHERE email = ?").get(email);
    if (!u) return res.status(401).json({ error: "Invalid credentials" });
    const calc = pbkdf2HashPassword(password, u.pass_salt, Number(u.pass_iter));
    const ok = crypto.timingSafeEqual(Buffer.from(calc, "hex"), Buffer.from(String(u.pass_hash), "hex"));
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });
    const token = signToken({ sub: String(u.id), email: u.email, role: u.role, username: u.username, display_name: u.display_name });
    setAuthCookie(res, token);
    return res.json({ ok: true, user: { id: Number(u.id), email: u.email, username: u.username, role: u.role } });
  } catch (e) {
    return res.status(500).json({ error: String(e.message) });
  }
});

app.post("/api/auth/logout", (_req, res) => {
  clearAuthCookie(res);
  res.json({ ok: true });
});

app.post("/api/auth/forgot", (req, res) => {
  const email = normalizeEmail(req.body?.email);
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Invalid email" });
  try {
    const u = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
    // Always return OK to avoid user enumeration
    if (!u) return res.json({ ok: true });

    const token = crypto.randomBytes(24).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(token, "utf8").digest("hex");
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15m
    db.prepare("INSERT INTO password_resets (email, token_hash, expires_at) VALUES (?, ?, ?)").run(email, tokenHash, expiresAt);

    // Dev mode: return token so user can reset without email provider
    const isDev = process.env.NODE_ENV !== "production";
    return res.json(isDev ? { ok: true, devToken: token, expiresAt } : { ok: true });
  } catch (e) {
    return res.status(500).json({ error: String(e.message) });
  }
});

app.post("/api/auth/reset", (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const token = safeStr(req.body?.token).trim();
  const newPassword = safeStr(req.body?.newPassword);
  if (!email || !token || !newPassword) return res.status(400).json({ error: "Missing email, token or newPassword" });
  if (newPassword.length < 6) return res.status(400).json({ error: "Password too short (min 6)" });
  try {
    const u = db.prepare("SELECT id, email FROM users WHERE email = ?").get(email);
    if (!u) return res.status(400).json({ error: "Invalid token" });

    const tokenHash = crypto.createHash("sha256").update(token, "utf8").digest("hex");
    const row = db
      .prepare("SELECT id, expires_at FROM password_resets WHERE email = ? AND token_hash = ? ORDER BY id DESC LIMIT 1")
      .get(email, tokenHash);
    if (!row) return res.status(400).json({ error: "Invalid token" });
    if (new Date(row.expires_at).getTime() < Date.now()) return res.status(400).json({ error: "Token expired" });

    const salt = crypto.randomBytes(16).toString("hex");
    const iter = 150000;
    const passHash = pbkdf2HashPassword(newPassword, salt, iter);
    db.prepare("UPDATE users SET pass_hash = ?, pass_salt = ?, pass_iter = ? WHERE email = ?").run(passHash, salt, iter, email);
    db.prepare("DELETE FROM password_resets WHERE email = ?").run(email);

    const u2 = db.prepare("SELECT id, email, role, username, display_name FROM users WHERE email = ?").get(email);
    const tokenJwt = signToken({ sub: String(u2.id), email: u2.email, role: u2.role, username: u2.username, display_name: u2.display_name });
    setAuthCookie(res, tokenJwt);
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: String(e.message) });
  }
});

app.get("/api/auth/me", (req, res) => {
  if (!req.user || !req.user.sub) return res.json({ ok: true, user: null });
  res.json({
    ok: true,
    user: {
      id: Number(req.user.sub),
      email: req.user.email || null,
      role: req.user.role || "user",
      username: req.user.username || null,
      display_name: req.user.display_name || null,
    },
  });
});

// Profile API (forum-friendly)
app.get("/api/profile/me", requireAuth, (req, res) => {
  try {
    const row = db.prepare("SELECT id, email, role, username, display_name, bio, avatar_url, created_at FROM users WHERE id = ?").get(Number(req.user.sub));
    res.json({ ok: true, profile: row });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

app.put("/api/profile/me", requireAuth, (req, res) => {
  const displayName = safeStr(req.body?.display_name).trim().slice(0, 50);
  const bio = safeStr(req.body?.bio).trim().slice(0, 500);
  const avatarUrl = safeStr(req.body?.avatar_url).trim().slice(0, 500);
  try {
    db.prepare("UPDATE users SET display_name = ?, bio = ?, avatar_url = ? WHERE id = ?").run(displayName, bio, avatarUrl, Number(req.user.sub));
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

app.get("/api/users/:id", (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id) || id < 1) return res.status(400).json({ error: "Invalid id" });
  try {
    const row = db.prepare("SELECT id, username, display_name, bio, avatar_url, created_at FROM users WHERE id = ?").get(id);
    if (!row) return res.status(404).json({ error: "Not found" });
    res.json({ ok: true, profile: row });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

// Admin API (hidden account can review others)
app.get("/api/admin/users", requireAdmin, (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit || 50), 1), 200);
  const offset = Math.max(Number(req.query.offset || 0), 0);
  try {
    const rows = db
      .prepare("SELECT id, email, role, username, display_name, created_at FROM users ORDER BY id DESC LIMIT ? OFFSET ?")
      .all(limit, offset);
    res.json({ ok: true, users: rows, limit, offset });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

app.post("/api/admin/users/:id/role", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const role = safeStr(req.body?.role);
  if (!Number.isFinite(id) || id < 1) return res.status(400).json({ error: "Invalid id" });
  if (!["user", "admin"].includes(role)) return res.status(400).json({ error: "Invalid role" });
  try {
    db.prepare("UPDATE users SET role = ? WHERE id = ?").run(role, id);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

app.post("/api/admin/impersonate", requireAdmin, (req, res) => {
  const userId = Number(req.body?.userId);
  if (!Number.isFinite(userId) || userId < 1) return res.status(400).json({ error: "Invalid userId" });
  try {
    const u = db.prepare("SELECT id, email, role, username, display_name FROM users WHERE id = ?").get(userId);
    if (!u) return res.status(404).json({ error: "Not found" });
    const token = signToken({ sub: String(u.id), email: u.email, role: u.role, username: u.username, display_name: u.display_name, imp: true });
    setAuthCookie(res, token);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

app.get("/api/admin/entries", requireAdmin, (req, res) => {
  const userId = Number(req.query.userId);
  if (!Number.isFinite(userId) || userId < 1) return res.status(400).json({ error: "Invalid userId" });
  try {
    const rows = db.prepare("SELECT id, type, amount, category, note, date, user_id FROM entries WHERE user_id = ? ORDER BY id DESC").all(userId);
    res.json({ ok: true, entries: rows });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

app.delete("/api/admin/entries/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id) || id < 1) return res.status(400).json({ error: "Invalid id" });
  try {
    const r = db.prepare("DELETE FROM entries WHERE id = ?").run(id);
    if (r.changes === 0) return res.status(404).json({ error: "Not found" });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

app.get("/api/admin/cms", requireAdmin, (req, res) => {
  const userId = Number(req.query.userId);
  if (!Number.isFinite(userId) || userId < 1) return res.status(400).json({ error: "Invalid userId" });
  try {
    const rows = db.prepare("SELECT key, value, updated_at, user_id FROM content WHERE user_id = ? ORDER BY key").all(userId);
    res.json({ ok: true, items: rows });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

app.put("/api/admin/cms/:key", requireAdmin, (req, res) => {
  const userId = Number(req.body?.userId);
  const key = safeStr(req.params.key);
  const value = req.body?.value;
  if (!Number.isFinite(userId) || userId < 1) return res.status(400).json({ error: "Invalid userId" });
  if (!key || key.length > 200) return res.status(400).json({ error: "Invalid key" });
  try {
    db.prepare(
      "INSERT INTO content (user_id, key, value, updated_at) VALUES (?, ?, ?, datetime('now')) ON CONFLICT(user_id, key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')"
    ).run(userId, key, value != null ? String(value) : "");
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

app.get("/api/admin/forum/threads", requireAdmin, (req, res) => {
  const userId = Number(req.query.userId);
  if (!Number.isFinite(userId) || userId < 1) return res.status(400).json({ error: "Invalid userId" });
  try {
    const rows = db
      .prepare(
        `
        SELECT t.id, t.title, t.created_at, t.updated_at,
          (SELECT COUNT(1) FROM forum_posts p WHERE p.thread_id = t.id) as replies
        FROM forum_threads t
        WHERE t.author_user_id = ?
        ORDER BY t.id DESC
      `
      )
      .all(userId);
    res.json({ ok: true, threads: rows });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

app.delete("/api/admin/forum/threads/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id) || id < 1) return res.status(400).json({ error: "Invalid id" });
  try {
    const tx = db.transaction(() => {
      db.prepare("DELETE FROM forum_posts WHERE thread_id = ?").run(id);
      const r = db.prepare("DELETE FROM forum_threads WHERE id = ?").run(id);
      return r;
    });
    const r = tx();
    if (r.changes === 0) return res.status(404).json({ error: "Not found" });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

// Forum API (public read, auth required to write)
app.get("/api/forum/threads", (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit || 20), 1), 50);
  const offset = Math.max(Number(req.query.offset || 0), 0);
  const q = safeStr(req.query.q || "").trim().toLowerCase();
  try {
    const where = q ? "WHERE lower(t.title) LIKE ? OR lower(ifnull(t.body,'')) LIKE ?" : "";
    const params = q ? [`%${q}%`, `%${q}%`, limit, offset] : [limit, offset];
    const rows = db
      .prepare(
        `
        SELECT
          t.id, t.title, t.body, t.created_at, t.updated_at,
          u.id as author_id, u.username as author_username, u.display_name as author_display_name, u.avatar_url as author_avatar_url,
          (SELECT COUNT(1) FROM forum_posts p WHERE p.thread_id = t.id) as replies
        FROM forum_threads t
        JOIN users u ON u.id = t.author_user_id
        ${where}
        ORDER BY t.id DESC
        LIMIT ? OFFSET ?
      `
      )
      .all(...params);
    res.json({ ok: true, threads: rows, limit, offset });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

app.get("/api/forum/threads/:id", (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id) || id < 1) return res.status(400).json({ error: "Invalid id" });
  try {
    const thread = db
      .prepare(
        `
        SELECT
          t.id, t.title, t.body, t.created_at, t.updated_at,
          u.id as author_id, u.username as author_username, u.display_name as author_display_name, u.avatar_url as author_avatar_url
        FROM forum_threads t
        JOIN users u ON u.id = t.author_user_id
        WHERE t.id = ?
      `
      )
      .get(id);
    if (!thread) return res.status(404).json({ error: "Not found" });
    const posts = db
      .prepare(
        `
        SELECT
          p.id, p.thread_id, p.body, p.created_at,
          u.id as author_id, u.username as author_username, u.display_name as author_display_name, u.avatar_url as author_avatar_url
        FROM forum_posts p
        JOIN users u ON u.id = p.author_user_id
        WHERE p.thread_id = ?
        ORDER BY p.id ASC
      `
      )
      .all(id);
    res.json({ ok: true, thread, posts });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

app.post("/api/forum/threads", requireAuth, (req, res) => {
  const title = safeStr(req.body?.title).trim();
  const body = safeStr(req.body?.body).trim();
  if (!title || title.length < 3) return res.status(400).json({ error: "Title too short" });
  if (title.length > 120) return res.status(400).json({ error: "Title too long" });
  if (body.length > 10000) return res.status(400).json({ error: "Body too long" });
  try {
    const r = db
      .prepare("INSERT INTO forum_threads (author_user_id, title, body, created_at, updated_at) VALUES (?, ?, ?, datetime('now'), datetime('now'))")
      .run(Number(req.user.sub), title, body || null);
    res.status(201).json({ ok: true, id: Number(r.lastInsertRowid) });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

app.post("/api/forum/threads/:id/reply", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const body = safeStr(req.body?.body).trim();
  if (!Number.isFinite(id) || id < 1) return res.status(400).json({ error: "Invalid id" });
  if (!body || body.length < 1) return res.status(400).json({ error: "Empty body" });
  if (body.length > 10000) return res.status(400).json({ error: "Body too long" });
  try {
    const t = db.prepare("SELECT id FROM forum_threads WHERE id = ?").get(id);
    if (!t) return res.status(404).json({ error: "Not found" });
    const r = db.prepare("INSERT INTO forum_posts (thread_id, author_user_id, body, created_at) VALUES (?, ?, ?, datetime('now'))").run(id, Number(req.user.sub), body);
    db.prepare("UPDATE forum_threads SET updated_at = datetime('now') WHERE id = ?").run(id);
    res.status(201).json({ ok: true, id: Number(r.lastInsertRowid) });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

// Finance API
app.get("/api/entries", requireAuth, (req, res) => {
  try {
    const userId = Number(req.user.sub);
    const rows = db.prepare("SELECT id, type, amount, category, note, date FROM entries WHERE user_id = ? ORDER BY id DESC").all(userId);
    res.json({ entries: rows });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

app.post("/api/entries", requireAuth, (req, res) => {
  const { type, amount, category, note, date } = req.body || {};
  if (!type || amount == null || !category) {
    return res.status(400).json({ error: "Missing type, amount or category" });
  }
  if (!["income", "expense"].includes(type)) {
    return res.status(400).json({ error: "type must be income or expense" });
  }
  if (!Number.isFinite(Number(amount))) {
    return res.status(400).json({ error: "amount must be a number" });
  }
  if (String(category).length > 64) {
    return res.status(400).json({ error: "category too long" });
  }
  if (note != null && String(note).length > 2000) {
    return res.status(400).json({ error: "note too long" });
  }
  if (date != null && !/^\d{4}-\d{2}-\d{2}$/.test(String(date))) {
    return res.status(400).json({ error: "date must be YYYY-MM-DD" });
  }
  try {
    const stmt = db.prepare(
      "INSERT INTO entries (user_id, type, amount, category, note, date) VALUES (?, ?, ?, ?, ?, ?)"
    );
    const result = stmt.run(Number(req.user.sub), type, Number(amount), String(category), note || null, date || new Date().toISOString().slice(0, 10));
    res.status(201).json({ id: result.lastInsertRowid });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

app.delete("/api/entries/:id", requireAuth, (req, res) => {
  try {
    const stmt = db.prepare("DELETE FROM entries WHERE id = ? AND user_id = ?");
    const result = stmt.run(Number(req.params.id), Number(req.user.sub));
    if (result.changes === 0) return res.status(404).json({ error: "Not found" });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

// CMS API (simple key-value content)
app.get("/api/cms/:key", requireAuth, (req, res) => {
  try {
    const row = db.prepare("SELECT value FROM content WHERE user_id = ? AND key = ?").get(Number(req.user.sub), req.params.key);
    res.json({ value: row ? row.value : null });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

app.get("/api/cms", requireAuth, (req, res) => {
  try {
    const rows = db.prepare("SELECT key, value, updated_at FROM content WHERE user_id = ? ORDER BY key").all(Number(req.user.sub));
    res.json({ items: rows });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

app.put("/api/cms/:key", requireAuth, (req, res) => {
  const { value } = req.body || {};
  try {
    db.prepare(
      "INSERT INTO content (user_id, key, value, updated_at) VALUES (?, ?, ?, datetime('now')) ON CONFLICT(user_id, key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')"
    ).run(Number(req.user.sub), req.params.key, value != null ? String(value) : "");
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

app.delete("/api/cms/:key", requireAuth, (req, res) => {
  try {
    const r = db.prepare("DELETE FROM content WHERE user_id = ? AND key = ?").run(Number(req.user.sub), req.params.key);
    if (r.changes === 0) return res.status(404).json({ error: "Not found" });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

// Converters / Tools API
app.get("/api/health", (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

app.get("/api/meta", (req, res) => {
  res.json({
    name: "ToolHub API",
    version: "1",
    basePath: "/api",
    endpoints: [
      { method: "GET", path: "/api/health", purpose: "Healthcheck" },
      { method: "GET", path: "/api/meta", purpose: "Self-described endpoints" },
      { method: "POST", path: "/api/auth/register", purpose: "Register + set auth cookie" },
      { method: "POST", path: "/api/auth/login", purpose: "Login + set auth cookie" },
      { method: "POST", path: "/api/auth/logout", purpose: "Clear auth cookie" },
      { method: "POST", path: "/api/auth/forgot", purpose: "Create password reset token (dev returns token)" },
      { method: "POST", path: "/api/auth/reset", purpose: "Reset password using token (sets auth cookie)" },
      { method: "GET", path: "/api/auth/me", purpose: "Get current user (cookie)" },
      { method: "GET", path: "/api/profile/me", purpose: "Get my profile (auth required)" },
      { method: "PUT", path: "/api/profile/me", purpose: "Update my profile (auth required)" },
      { method: "GET", path: "/api/users/:id", purpose: "Public profile by id (forum)" },
      { method: "GET", path: "/api/admin/users", purpose: "Admin: list users" },
      { method: "POST", path: "/api/admin/users/:id/role", purpose: "Admin: set user role" },
      { method: "POST", path: "/api/admin/impersonate", purpose: "Admin: login as user (sets cookie)" },
      { method: "GET", path: "/api/admin/entries?userId=1", purpose: "Admin: list entries of user" },
      { method: "DELETE", path: "/api/admin/entries/:id", purpose: "Admin: delete entry" },
      { method: "GET", path: "/api/admin/cms?userId=1", purpose: "Admin: list cms of user" },
      { method: "PUT", path: "/api/admin/cms/:key", purpose: "Admin: upsert cms for user" },
      { method: "GET", path: "/api/admin/forum/threads?userId=1", purpose: "Admin: list forum threads of user" },
      { method: "DELETE", path: "/api/admin/forum/threads/:id", purpose: "Admin: delete forum thread + posts" },
      { method: "GET", path: "/api/forum/threads", purpose: "Forum: list threads (public)" },
      { method: "GET", path: "/api/forum/threads/:id", purpose: "Forum: get thread + posts (public)" },
      { method: "POST", path: "/api/forum/threads", purpose: "Forum: create thread (auth required)" },
      { method: "POST", path: "/api/forum/threads/:id/reply", purpose: "Forum: reply to thread (auth required)" },
      { method: "GET", path: "/api/entries", purpose: "List finance entries (auth required)" },
      { method: "POST", path: "/api/entries", purpose: "Create finance entry (auth required)" },
      { method: "DELETE", path: "/api/entries/:id", purpose: "Delete finance entry (auth required)" },
      { method: "GET", path: "/api/cms", purpose: "List CMS keys (auth required)" },
      { method: "GET", path: "/api/cms/:key", purpose: "Get CMS value by key (auth required)" },
      { method: "PUT", path: "/api/cms/:key", purpose: "Upsert CMS value by key (auth required)" },
      { method: "DELETE", path: "/api/cms/:key", purpose: "Delete CMS key (auth required)" },
      { method: "POST", path: "/api/tools/hash", purpose: "Hash text (SHA-*) -> hex" },
      { method: "POST", path: "/api/tools/hmac-sha256", purpose: "HMAC-SHA256 -> hex" },
      { method: "POST", path: "/api/tools/pbkdf2", purpose: "PBKDF2 -> hex" },
      { method: "POST", path: "/api/tools/crc32", purpose: "CRC32 -> hex" },
      { method: "POST", path: "/api/tools/slugify", purpose: "Slugify + RU translit" },
      { method: "POST", path: "/api/tools/validate", purpose: "Validate email/uuid/luhn/iban/semver" },
    ],
  });
});

function translitRuToLat(input) {
  const s = safeStr(input);
  const mapLower = {
    а: "a", б: "b", в: "v", г: "g", д: "d", е: "e", ё: "yo", ж: "zh", з: "z", и: "i",
    й: "y", к: "k", л: "l", м: "m", н: "n", о: "o", п: "p", р: "r", с: "s", т: "t",
    у: "u", ф: "f", х: "h", ц: "ts", ч: "ch", ш: "sh", щ: "sch", ъ: "", ы: "y", ь: "",
    э: "e", ю: "yu", я: "ya",
  };
  return s.replace(/[А-Яа-яЁё]/g, (ch) => {
    const lower = ch.toLowerCase();
    const t = mapLower[lower];
    if (t == null) return ch;
    return ch === lower ? t : (t ? t[0].toUpperCase() + t.slice(1) : "");
  });
}

function slugify(input) {
  return translitRuToLat(input)
    .trim()
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
}

function crc32(text) {
  const buf = Buffer.from(safeStr(text), "utf8");
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
  }
  return ((c ^ 0xffffffff) >>> 0).toString(16).padStart(8, "0");
}

app.post("/api/tools/hash", (req, res) => {
  const { alg, text } = req.body || {};
  const a = safeStr(alg).toLowerCase();
  const t = safeStr(text);
  const map = { "sha-256": "sha256", "sha-1": "sha1", "sha-384": "sha384", "sha-512": "sha512" };
  const nodeAlg = map[a];
  if (!nodeAlg) return res.status(400).json({ error: "Unsupported alg" });
  try {
    const out = crypto.createHash(nodeAlg).update(t, "utf8").digest("hex");
    res.json({ hex: out });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

app.post("/api/tools/hmac-sha256", (req, res) => {
  const { key, message } = req.body || {};
  try {
    const out = crypto.createHmac("sha256", Buffer.from(safeStr(key), "utf8")).update(safeStr(message), "utf8").digest("hex");
    res.json({ hex: out });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

app.post("/api/tools/pbkdf2", (req, res) => {
  const { password, salt, iterations, length, digest } = req.body || {};
  const iter = Number(iterations);
  const len = Number(length);
  const dig = safeStr(digest || "sha256").toLowerCase();
  if (!Number.isFinite(iter) || iter < 1 || iter > 2000000) return res.status(400).json({ error: "Invalid iterations" });
  if (!Number.isFinite(len) || len < 1 || len > 128) return res.status(400).json({ error: "Invalid length" });
  if (!["sha256", "sha1", "sha384", "sha512"].includes(dig)) return res.status(400).json({ error: "Invalid digest" });
  try {
    const out = crypto.pbkdf2Sync(
      Buffer.from(safeStr(password), "utf8"),
      Buffer.from(safeStr(salt), "utf8"),
      Math.floor(iter),
      Math.floor(len),
      dig
    ).toString("hex");
    res.json({ hex: out });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

app.post("/api/tools/crc32", (req, res) => {
  const { text } = req.body || {};
  try {
    res.json({ hex: crc32(text) });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

app.post("/api/tools/slugify", (req, res) => {
  const { text } = req.body || {};
  res.json({ slug: slugify(text) });
});

app.post("/api/tools/validate", (req, res) => {
  const { kind, value } = req.body || {};
  const k = safeStr(kind);
  const v = safeStr(value).trim();
  try {
    if (k === "email") {
      const ok = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) && !/\.\./.test(v);
      return res.json({ ok, message: ok ? "OK" : "Invalid email" });
    }
    if (k === "uuid") {
      const ok = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(v);
      return res.json({ ok, message: ok ? "OK" : "Invalid UUID" });
    }
    if (k === "luhn") {
      const digits = v.replace(/\D/g, "");
      if (!digits) return res.json({ ok: false, message: "No digits" });
      let sum = 0;
      let alt = false;
      for (let i = digits.length - 1; i >= 0; i--) {
        let d = Number(digits[i]);
        if (alt) {
          d *= 2;
          if (d > 9) d -= 9;
        }
        sum += d;
        alt = !alt;
      }
      const ok = sum % 10 === 0;
      return res.json({ ok, message: ok ? "OK" : "Invalid checksum" });
    }
    if (k === "iban") {
      const s = v.replace(/\s+/g, "").toUpperCase();
      if (!/^[A-Z0-9]+$/.test(s) || s.length < 8) return res.json({ ok: false, message: "Invalid IBAN" });
      const rearr = s.slice(4) + s.slice(0, 4);
      let num = "";
      for (const ch of rearr) {
        if (/[0-9]/.test(ch)) num += ch;
        else num += String(ch.charCodeAt(0) - 55);
      }
      let mod = 0;
      for (let i = 0; i < num.length; i += 7) mod = Number(String(mod) + num.slice(i, i + 7)) % 97;
      const ok = mod === 1;
      return res.json({ ok, message: ok ? "OK" : "Invalid IBAN" });
    }
    if (k === "semver") {
      const ok = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/.test(v);
      return res.json({ ok, message: ok ? "OK" : "Not semver" });
    }
    return res.status(400).json({ error: "Unsupported kind" });
  } catch (e) {
    res.status(500).json({ error: String(e.message) });
  }
});

const PORT = process.env.API_PORT || 3003;
const server = app.listen(PORT, () => {
  console.log(`API server http://localhost:${PORT}`);
});
server.on("error", (e) => {
  if (e.code === "EADDRINUSE") {
    console.error(`Port ${PORT} is already in use. Set API_PORT to use another port.`);
  } else {
    console.error("API server error:", e);
  }
});

