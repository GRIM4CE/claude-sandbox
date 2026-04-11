const express = require("express");
const http = require("http");
const { WebSocketServer } = require("ws");
const path = require("path");

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

app.get("/healthz", (req, res) => res.send("ok"));
app.use(express.static(path.join(__dirname, "public")));

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
      broadcast({ type: "system", text: `${username} joined the chat` });
      broadcast({ type: "users", users: getOnlineUsers() });
    }

    if (msg.type === "chat" && username) {
      const text = msg.text.trim().slice(0, 1000);
      if (!text) return;
      broadcast({
        type: "chat",
        username,
        text,
        timestamp: Date.now(),
      });
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

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Chat server running on http://localhost:${PORT}`);
});
