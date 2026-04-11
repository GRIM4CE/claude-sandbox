const express = require("express");
const http = require("http");
const { WebSocketServer } = require("ws");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

app.use(express.json());
app.get("/healthz", (req, res) => res.send("ok"));
app.use(express.static(path.join(__dirname, "public")));

// --- User storage (JSON file) ---
const USERS_FILE = path.join(__dirname, "users.json");

function loadUsers() {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, "utf-8"));
  } catch {
    return {};
  }
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// --- Auth endpoints ---
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

  const users = loadUsers();
  if (users[trimmed.toLowerCase()]) {
    return res.status(409).json({ error: "Username already taken" });
  }

  const hash = await bcrypt.hash(password, 10);
  users[trimmed.toLowerCase()] = { username: trimmed, hash };
  saveUsers(users);
  res.json({ username: trimmed });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required" });
  }

  const users = loadUsers();
  const user = users[username.trim().toLowerCase()];
  if (!user || !(await bcrypt.compare(password, user.hash))) {
    return res.status(401).json({ error: "Invalid username or password" });
  }
  res.json({ username: user.username });
});

// --- Message history (JSON file, capped at 200) ---
const MESSAGES_FILE = path.join(__dirname, "messages.json");
const MAX_MESSAGES = 200;

function loadMessages() {
  try {
    return JSON.parse(fs.readFileSync(MESSAGES_FILE, "utf-8"));
  } catch {
    return [];
  }
}

function saveMessage(msg) {
  const messages = loadMessages();
  messages.push(msg);
  if (messages.length > MAX_MESSAGES) {
    messages.splice(0, messages.length - MAX_MESSAGES);
  }
  fs.writeFileSync(MESSAGES_FILE, JSON.stringify(messages));
}

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

wss.on("connection", (ws) => {
  let username = null;
  ws.isAlive = true;

  ws.on("pong", () => { ws.isAlive = true; });

  ws.on("message", (raw) => {
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

      // Send message history to the joining user
      const history = loadMessages();
      if (history.length > 0) {
        ws.send(JSON.stringify({ type: "history", messages: history }));
      }

      broadcast({ type: "system", text: `${username} joined the chat` });
      broadcast({ type: "users", users: getOnlineUsers() });
    }

    if (msg.type === "chat" && username) {
      const text = msg.text.trim().slice(0, 1000);
      if (!text) return;
      const chatMsg = {
        type: "chat",
        username,
        text,
        timestamp: Date.now(),
      };
      saveMessage(chatMsg);
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
server.listen(PORT, () => {
  console.log(`Chat server running on http://localhost:${PORT}`);
});
