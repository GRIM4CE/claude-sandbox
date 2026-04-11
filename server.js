const express = require("express");
const http = require("http");
const { WebSocketServer } = require("ws");
const path = require("path");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

// --- Database setup ---
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
}

app.use(express.json());
app.get("/healthz", (req, res) => res.send("ok"));
app.use(express.static(path.join(__dirname, "public")));

// --- Auth endpoints ---
const MAX_MESSAGES = 20;

app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required" });
  }
  const trimmed = username.trim().slice(0, 30);
  if (trimmed.length < 2) {
    return res.status(400).json({ error: "Username must be at least 2 characters" });
  }
  if (password.length < 4) {
    return res.status(400).json({ error: "Password must be at least 4 characters" });
  }

  try {
    const existing = await pool.query(
      "SELECT 1 FROM users WHERE LOWER(username) = LOWER($1)", [trimmed]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: "Username already taken" });
    }

    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO users (username, password_hash) VALUES ($1, $2)", [trimmed, hash]
    );
    res.json({ username: trimmed });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required" });
  }

  try {
    const result = await pool.query(
      "SELECT username, password_hash FROM users WHERE LOWER(username) = LOWER($1)",
      [username.trim()]
    );
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Invalid username or password" });
    }
    res.json({ username: user.username });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// --- WebSocket chat ---
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
  // Trim to keep only the latest MAX_MESSAGES
  await pool.query(`
    DELETE FROM messages WHERE id NOT IN (
      SELECT id FROM messages ORDER BY id DESC LIMIT $1
    )
  `, [MAX_MESSAGES]);
}

wss.on("connection", (ws) => {
  let username = null;
  ws.isAlive = true;

  ws.on("pong", () => { ws.isAlive = true; });

  ws.on("message", async (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }

    if (msg.type === "join") {
      username = msg.username.trim().slice(0, 30);
      if (!username) return;
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
      const text = msg.text.trim().slice(0, 1000);
      if (!text) return;
      const timestamp = Date.now();
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
