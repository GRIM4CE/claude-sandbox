const express = require("express");
const http = require("http");
const { WebSocketServer } = require("ws");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");

const app = express();
const server = http.createServer(app);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: true } : false,
});

// --- Database setup ---
const SESSION_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(30) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      username VARCHAR(30) NOT NULL,
      text TEXT NOT NULL,
      timestamp BIGINT NOT NULL
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      id SERIAL PRIMARY KEY,
      token VARCHAR(64) UNIQUE NOT NULL,
      username VARCHAR(30) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  // Clean up expired sessions on startup
  await pool.query(
    "DELETE FROM sessions WHERE created_at < NOW() - INTERVAL '7 days'"
  );
}

function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

async function createSession(username) {
  // Remove old sessions for this user (limit to 5 active sessions)
  await pool.query(`
    DELETE FROM sessions WHERE id IN (
      SELECT id FROM sessions WHERE username = $1
      ORDER BY created_at DESC OFFSET 4
    )
  `, [username]);
  const token = generateToken();
  await pool.query(
    "INSERT INTO sessions (token, username) VALUES ($1, $2)", [token, username]
  );
  return token;
}

async function validateSession(token) {
  if (!token || typeof token !== "string") return null;
  const result = await pool.query(
    "SELECT username FROM sessions WHERE token = $1 AND created_at > NOW() - INTERVAL '7 days'",
    [token]
  );
  return result.rows.length > 0 ? result.rows[0].username : null;
}

// --- Middleware ---
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'", "wss:", "ws:"],
    },
  },
}));
app.use(express.json());
app.get("/healthz", (req, res) => res.send("ok"));
app.use(express.static(path.join(__dirname, "public")));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  message: { error: "Too many attempts, please try again later" },
});

// --- Auth endpoints ---
const MAX_MESSAGES = 20;
const USERNAME_RE = /^[a-z0-9_-]{2,30}$/;

app.post("/api/register", authLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required" });
  }
  const trimmed = String(username).trim().slice(0, 30).toLowerCase();
  if (!USERNAME_RE.test(trimmed)) {
    return res.status(400).json({ error: "Username must be 2-30 characters (letters, numbers, - or _)" });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters" });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO users (username, password_hash) VALUES ($1, $2)", [trimmed, hash]
    );
    const token = await createSession(trimmed);
    res.json({ username: trimmed, token });
  } catch (err) {
    if (err.code === "23505") { // unique constraint violation
      return res.status(409).json({ error: "Username already taken" });
    }
    console.error("Register error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/login", authLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required" });
  }

  try {
    const result = await pool.query(
      "SELECT username, password_hash FROM users WHERE username = $1",
      [String(username).trim().toLowerCase()]
    );
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Invalid username or password" });
    }
    const token = await createSession(user.username);
    res.json({ username: user.username, token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/verify", async (req, res) => {
  const { token } = req.body;
  const username = await validateSession(token);
  if (!username) {
    return res.status(401).json({ error: "Invalid session" });
  }
  res.json({ username });
});

app.post("/api/logout", async (req, res) => {
  const { token } = req.body;
  if (token) {
    await pool.query("DELETE FROM sessions WHERE token = $1", [token]);
  }
  res.json({ ok: true });
});

// --- WebSocket chat ---
const wss = new WebSocketServer({
  server,
  maxPayload: 4096,
});

const clients = new Map();

function broadcast(message) {
  const data = JSON.stringify(message);
  for (const client of clients.keys()) {
    if (client.readyState === client.OPEN) {
      client.send(data);
    }
  }
}

function getOnlineUsers() {
  return Array.from(clients.values());
}

async function getRecentMessages() {
  const result = await pool.query(
    "SELECT username, text, timestamp FROM messages ORDER BY id DESC LIMIT $1",
    [MAX_MESSAGES]
  );
  return result.rows.reverse().map((row) => ({
    type: "chat",
    username: row.username,
    text: row.text,
    timestamp: Number(row.timestamp),
  }));
}

async function saveMessage(username, text, timestamp) {
  await pool.query(
    "INSERT INTO messages (username, text, timestamp) VALUES ($1, $2, $3)",
    [username, text, timestamp]
  );
  await pool.query(`
    DELETE FROM messages WHERE id NOT IN (
      SELECT id FROM messages ORDER BY id DESC LIMIT $1
    )
  `, [MAX_MESSAGES]);
}

wss.on("connection", (ws) => {
  let username = null;
  ws.isAlive = true;
  let lastMessageTime = 0;
  let messageCount = 0;

  ws.on("pong", () => { ws.isAlive = true; });

  ws.on("message", async (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }

    if (msg.type === "join") {
      // Authenticate via session token
      if (typeof msg.token !== "string") { ws.close(); return; }
      const validUser = await validateSession(msg.token);
      if (!validUser) { ws.close(); return; }
      username = validUser;
      clients.set(ws, username);

      try {
        const history = await getRecentMessages();
        if (history.length > 0) {
          ws.send(JSON.stringify({ type: "history", messages: history }));
        }
      } catch (err) {
        console.error("History load error:", err);
      }

      broadcast({ type: "system", text: `${username} joined the chat` });
      broadcast({ type: "users", users: getOnlineUsers() });
    }

    if (msg.type === "chat" && username) {
      // Rate limit: max 5 messages per second
      const now = Date.now();
      if (now - lastMessageTime < 1000) {
        messageCount++;
        if (messageCount > 5) return;
      } else {
        messageCount = 1;
        lastMessageTime = now;
      }

      if (typeof msg.text !== "string") return;
      const text = msg.text.trim().slice(0, 1000);
      if (!text) return;
      const timestamp = now;
      const chatMsg = { type: "chat", username, text, timestamp };

      try {
        await saveMessage(username, text, timestamp);
      } catch (err) {
        console.error("Message save error:", err);
      }

      broadcast(chatMsg);
    }
  });

  ws.on("close", () => {
    if (username) {
      clients.delete(ws);
      broadcast({ type: "system", text: `${username} left the chat` });
      broadcast({ type: "users", users: getOnlineUsers() });
    }
  });
});

const HEARTBEAT_INTERVAL = 25000;
setInterval(() => {
  for (const client of wss.clients) {
    if (!client.isAlive) { client.terminate(); continue; }
    client.isAlive = false;
    client.ping();
  }
}, HEARTBEAT_INTERVAL);

// Clean up expired sessions every hour
setInterval(async () => {
  try {
    await pool.query("DELETE FROM sessions WHERE created_at < NOW() - INTERVAL '7 days'");
  } catch (err) {
    console.error("Session cleanup error:", err);
  }
}, 60 * 60 * 1000);

const PORT = process.env.PORT || 3000;
initDb()
  .then(() => {
    server.listen(PORT, () => {
      console.log(`Chat server running on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error("Failed to initialize database:", err);
    process.exit(1);
  });
