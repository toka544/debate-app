const express = require("express");
const app = express();

app.use(express.json());

// In-memory storage (перезапустишь сервер — очистится)
let messages = [];

/**
 * Health check
 */
app.get("/", (req, res) => {
  res.redirect("/debate");
});

/**
 * Get all messages
 */
app.get("/messages", (req, res) => {
  res.json(messages);
});

/**
 * Post a message
 */
app.post("/messages", (req, res) => {
  const { text, side } = req.body;

  if (typeof text !== "string" || !text.trim()) {
    return res.status(400).json({ error: "text is required" });
  }
  if (side !== "YES" && side !== "NO") {
    return res.status(400).json({ error: "side must be YES or NO" });
  }

  messages.push({
    text: text.trim(),
    side,
    time: Date.now(),
  });

  // keep last 200 to avoid memory growth
  if (messages.length > 200) messages.shift();

  res.json({ success: true });
});

/**
 * Debate page (simple HTML)
 */
app.get("/debate", (req, res) => {
  res.type("html").send(`
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Live Debate</title>
  <style>
    body { font-family: Arial, sans-serif; text-align: center; padding: 32px; }
    .btn { padding: 10px 18px; margin: 8px; cursor: pointer; border: 1px solid #222; background: #fff; border-radius: 10px; }
    .btn:hover { opacity: 0.85; }
    input { padding: 10px; width: min(520px, 90vw); border-radius: 10px; border: 1px solid #aaa; }
    #list { margin: 22px auto 0; width: min(720px, 95vw); text-align: left; }
    .msg { padding: 10px 12px; border: 1px solid #eee; border-radius: 12px; margin: 10px 0; }
    .tag { display: inline-block; font-weight: 700; margin-right: 8px; }
    .yes { color: #0a7a2f; }
    .no { color: #b4002a; }
    .row { margin-top: 14px; }
    .hint { color: #666; font-size: 14px; margin-top: 6px; }
  </style>
</head>
<body>
  <h1>🔥 Live Debate</h1>
  <h2>Is university education still worth it?</h2>

  <div class="row">
    <button class="btn" onclick="vote('YES')">YES</button>
    <button class="btn" onclick="vote('NO')">NO</button>
  </div>
  <div class="hint" id="chosen">Choose a side</div>

  <div class="row">
    <input id="text" placeholder="Your argument..." />
    <button class="btn" onclick="send()">Send</button>
  </div>

  <h3>Arguments</h3>
  <div id="list"></div>

  <script>
    let side = null;

    function vote(s) {
      side = s;
      const el = document.getElementById("chosen");
      el.textContent = "Chosen: " + s;
    }

    async function send() {
      const input = document.getElementById("text");
      const text = input.value;

      if (!side) {
        alert("Choose a side first!");
        return;
      }
      if (!text.trim()) return;

      const res = await fetch("/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, side })
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert(err.error || "Failed to send");
        return;
      }

      input.value = "";
      await load();
    }

    async function load() {
      const res = await fetch("/messages");
      const data = await res.json();

      const html = data
        .slice() // copy
        .reverse() // newest first
        .map(m => {
          const cls = m.side === "YES" ? "yes" : "no";
          const safeText = String(m.text)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;");
          return \`
            <div class="msg">
              <span class="tag \${cls}">\${m.side}:</span>
              <span>\${safeText}</span>
            </div>
          \`;
        })
        .join("");

      document.getElementById("list").innerHTML = html;
    }

    load();
    setInterval(load, 1000);
  </script>
</body>
</html>
  `);
});

/**
 * IMPORTANT: listen must be LAST
 * Render/Heroku/etc provide PORT via env
 */
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
