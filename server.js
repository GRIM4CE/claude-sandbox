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
  await pool.query(`
    CREATE TABLE IF NOT EXISTS reactions (
      id SERIAL PRIMARY KEY,
      message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
      username VARCHAR(30) NOT NULL,
      emoji TEXT NOT NULL,
      UNIQUE(message_id, username)
    )
  `);
  // Add created_at column if it doesn't exist (for tables created before this migration)
  await pool.query(`
    ALTER TABLE sessions ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()
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

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 2,
  message: { error: "Too many registration attempts, please try again later" },
});

// --- Auth endpoints ---
const MAX_MESSAGES = 20;
const USERNAME_RE = /^[a-z0-9_-]{2,30}$/;

app.post("/api/register", registerLimiter, async (req, res) => {
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

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  message: { error: "Too many login attempts, please try again later" },
});

app.post("/api/login", loginLimiter, async (req, res) => {
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

async function getReactionsForMessages(messageIds) {
  if (messageIds.length === 0) return {};
  const result = await pool.query(
    "SELECT message_id, emoji, username FROM reactions WHERE message_id = ANY($1)",
    [messageIds]
  );
  const reactionsByMsg = {};
  for (const row of result.rows) {
    if (!reactionsByMsg[row.message_id]) reactionsByMsg[row.message_id] = {};
    if (!reactionsByMsg[row.message_id][row.emoji]) reactionsByMsg[row.message_id][row.emoji] = [];
    reactionsByMsg[row.message_id][row.emoji].push(row.username);
  }
  return reactionsByMsg;
}

async function getRecentMessages() {
  const result = await pool.query(
    "SELECT id, username, text, timestamp FROM messages ORDER BY id DESC LIMIT $1",
    [MAX_MESSAGES]
  );
  const rows = result.rows.reverse();
  const messageIds = rows.map((r) => r.id);
  const reactionsByMsg = await getReactionsForMessages(messageIds);
  return rows.map((row) => ({
    type: "chat",
    msgId: row.id,
    username: row.username,
    text: row.text,
    timestamp: Number(row.timestamp),
    reactions: reactionsByMsg[row.id] || {},
  }));
}

async function saveMessage(username, text, timestamp) {
  const result = await pool.query(
    "INSERT INTO messages (username, text, timestamp) VALUES ($1, $2, $3) RETURNING id",
    [username, text, timestamp]
  );
  await pool.query(`
    DELETE FROM messages WHERE id NOT IN (
      SELECT id FROM messages ORDER BY id DESC LIMIT $1
    )
  `, [MAX_MESSAGES]);
  return result.rows[0].id;
}

async function getReactionsForMessage(msgId) {
  const result = await pool.query(
    "SELECT emoji, username FROM reactions WHERE message_id = $1",
    [msgId]
  );
  const reactions = {};
  for (const row of result.rows) {
    if (!reactions[row.emoji]) reactions[row.emoji] = [];
    reactions[row.emoji].push(row.username);
  }
  return reactions;
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

      let msgId;
      try {
        msgId = await saveMessage(username, text, timestamp);
      } catch (err) {
        console.error("Message save error:", err);
        return;
      }

      broadcast({ type: "chat", msgId, username, text, timestamp, reactions: {} });
    }

    if (msg.type === "react" && username) {
      if (typeof msg.msgId !== "number") return;
      if (typeof msg.emoji !== "string") return;
      // Only allow a single emoji character (no text)
      const emojiRe = /^(\p{Emoji_Presentation}|\p{Emoji}\uFE0F)(\u200D(\p{Emoji_Presentation}|\p{Emoji}\uFE0F))*$/u;
      if (!emojiRe.test(msg.emoji)) return;

      try {
        // Check if user already has this exact emoji on this message
        const existing = await pool.query(
          "SELECT emoji FROM reactions WHERE message_id = $1 AND username = $2",
          [msg.msgId, username]
        );
        const hadSameEmoji = existing.rows.length > 0 && existing.rows[0].emoji === msg.emoji;

        // Remove user's existing reaction on this message (one per user)
        await pool.query(
          "DELETE FROM reactions WHERE message_id = $1 AND username = $2",
          [msg.msgId, username]
        );

        // If they tapped a different emoji, add it. If same emoji, just remove (toggle off).
        if (!hadSameEmoji) {
          await pool.query(
            "INSERT INTO reactions (message_id, username, emoji) VALUES ($1, $2, $3)",
            [msg.msgId, username, msg.emoji]
          );
        }

        const reactions = await getReactionsForMessage(msg.msgId);
        broadcast({ type: "reaction", msgId: msg.msgId, reactions });
      } catch (err) {
        console.error("Reaction error:", err);
      }
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
