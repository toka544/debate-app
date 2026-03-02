const express = require("express");
const app = express();

app.use(express.json());

let messages = [];

app.get("/", (req, res) => {
  res.send("🔥 Debate app is running");
});

// получить все аргументы
app.get("/messages", (req, res) => {
  res.json(messages);
});

// отправить аргумент
app.post("/messages", (req, res) => {
  const { text, side } = req.body;

  messages.push({
    text,
    side,
    time: Date.now()
  });

  res.json({ success: true });
});

app.listen(3000, "0.0.0.0", () => {
  console.log("🚀 Server running on http://0.0.0.0:3000");
});
app.get("/debate", (req, res) => {
  res.send(`
    <html>
    <head>
      <title>Live Debate</title>
      <style>
        body { font-family: Arial; text-align: center; }
        .btn { padding: 10px 20px; margin: 10px; cursor: pointer; }
      </style>
    </head>
    <body>
      <h1>🔥 Live Debate</h1>
      <h2>Is university education still worth it?</h2>

      <button class="btn" onclick="vote('YES')">YES</button>
      <button class="btn" onclick="vote('NO')">NO</button>

      <br><br>

      <input id="text" placeholder="Your argument..." />
      <button onclick="send()">Send</button>

      <h3>Arguments:</h3>
      <div id="list"></div>

      <script>
        let side = null;

        function vote(s) {
          side = s;
          alert("You chose " + s);
        }

        function send() {
          const text = document.getElementById("text").value;

          fetch("/messages", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text, side })
          });

          document.getElementById("text").value = "";
        }

        async function load() {
          const res = await fetch("/messages");
          const data = await res.json();

          document.getElementById("list").innerHTML =
            data.map(m => "<p><b>" + m.side + ":</b> " + m.text + "</p>").join("");
        }

        setInterval(load, 1000);
      </script>
    </body>
    </html>
  `);
});