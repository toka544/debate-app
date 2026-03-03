require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const { Pool } = require("pg");

const app = express();
app.use(express.json());
app.use(cookieParser());

// ---------- DB ----------
if (!process.env.DATABASE_URL) {
  console.error("❌ DATABASE_URL is missing. Set it in Render env or .env locally.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("render.com")
    ? { rejectUnauthorized: false }
    : undefined,
});

// Helper: run query
async function q(text, params) {
  const client = await pool.connect();
  try {
    return await client.query(text, params);
  } finally {
    client.release();
  }
}

// ---------- Auth-lite (username only) ----------
async function getMe(req) {
  const username = req.cookies?.username;
  if (!username) return null;
  const r = await q("select id, username, rating from users where username = $1", [username]);
  return r.rows[0] || null;
}

app.post("/auth/login", async (req, res) => {
  const usernameRaw = (req.body?.username || "").trim();
  const username = usernameRaw.replace(/\s+/g, "_");

  if (!username || username.length < 3 || username.length > 20) {
    return res.status(400).json({ error: "username must be 3-20 chars" });
  }
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return res.status(400).json({ error: "username can contain only letters/numbers/_" });
  }

  await q(
    `insert into users (username) values ($1)
     on conflict (username) do nothing`,
    [username]
  );

  res.cookie("username", username, { httpOnly: true, sameSite: "lax" });

  const me = await q("select id, username, rating from users where username = $1", [username]);
  res.json({ success: true, user: me.rows[0] });
});

app.post("/auth/logout", (req, res) => {
  res.clearCookie("username");
  res.json({ success: true });
});

app.get("/me", async (req, res) => {
  const me = await getMe(req);
  res.json({ user: me });
});

// ---------- API ----------
app.get("/", (req, res) => res.redirect("/debate/1"));

app.get("/leaderboard/users", async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || "10", 10), 100);
  const r = await q(
    `select username, rating
     from users
     order by rating desc, id asc
     limit $1`,
    [limit]
  );
  res.json(r.rows);
});

app.get("/debate", async (req, res) => res.redirect("/debate/1"));

app.get("/debate/:id/messages", async (req, res) => {
  const debateId = parseInt(req.params.id, 10);
  if (!Number.isFinite(debateId)) return res.status(400).json({ error: "bad debate id" });

  const sort = (req.query.sort || "new").toLowerCase(); // "new" | "top"
  const orderBy = sort === "top" ? "m.score desc, m.created_at desc" : "m.created_at desc";

  const r = await q(
    `select
        m.id,
        m.side,
        m.text,
        m.score,
        m.created_at,
        u.username
     from messages m
     join users u on u.id = m.user_id
     where m.debate_id = $1
     order by ${orderBy}
     limit 200`,
    [debateId]
  );

  res.json(r.rows);
});

app.post("/debate/:id/messages", async (req, res) => {
  const me = await getMe(req);
  if (!me) return res.status(401).json({ error: "login first" });

  const debateId = parseInt(req.params.id, 10);
  const text = String(req.body?.text || "").trim();
  const side = String(req.body?.side || "").toUpperCase();

  if (!Number.isFinite(debateId)) return res.status(400).json({ error: "bad debate id" });
  if (!text) return res.status(400).json({ error: "text is required" });
  if (text.length > 300) return res.status(400).json({ error: "max 300 chars" });
  if (side !== "YES" && side !== "NO") return res.status(400).json({ error: "side must be YES or NO" });

  const r = await q(
    `insert into messages (debate_id, user_id, side, text)
     values ($1, $2, $3, $4)
     returning id`,
    [debateId, me.id, side, text]
  );

  res.json({ success: true, id: r.rows[0].id });
});

// Voting logic with weight:
// - can't vote own message
// - toggle (same vote) removes it
// - change (+1 -> -1) updates it
// deltaVote affects message.score
// deltaRating affects author's users.rating (deltaVote * 3)
app.post("/messages/:id/vote", async (req, res) => {
  const me = await getMe(req);
  if (!me) return res.status(401).json({ error: "login first" });

  const messageId = parseInt(req.params.id, 10);
  const value = parseInt(req.body?.value, 10);

  if (!Number.isFinite(messageId)) return res.status(400).json({ error: "bad message id" });
  if (value !== 1 && value !== -1) return res.status(400).json({ error: "value must be 1 or -1" });

  const client = await pool.connect();
  try {
    await client.query("begin");

    // weight от рейтинга голосующего (1..5)
    const voterR = await client.query(`select rating from users where id = $1`, [me.id]);
    const voterRating = voterR.rows[0]?.rating ?? 0;
    const weight = Math.min(5, 1 + Math.floor(voterRating / 50));

    // lock message row
    const msgR = await client.query(
      `select m.id, m.user_id, m.score
       from messages m
       where m.id = $1
       for update`,
      [messageId]
    );
    const msg = msgR.rows[0];
    if (!msg) {
      await client.query("rollback");
      return res.status(404).json({ error: "message not found" });
    }

    if (msg.user_id === me.id) {
      await client.query("rollback");
      return res.status(400).json({ error: "cannot vote your own message" });
    }

    const existingR = await client.query(
      `select id, value, weight from votes where message_id = $1 and user_id = $2`,
      [messageId, me.id]
    );
    const existing = existingR.rows[0];

    let deltaVote = 0;

    if (!existing) {
      await client.query(
        `insert into votes (message_id, user_id, value, weight) values ($1, $2, $3, $4)`,
        [messageId, me.id, value, weight]
      );
      deltaVote = value * weight;
    } else if (existing.value === value) {
      await client.query(`delete from votes where id = $1`, [existing.id]);
      deltaVote = -(existing.value * existing.weight);
    } else {
      await client.query(`update votes set value = $1, weight = $2 where id = $3`, [
        value,
        weight,
        existing.id,
      ]);
      const oldWeighted = existing.value * existing.weight;
      const newWeighted = value * weight;
      deltaVote = newWeighted - oldWeighted;
    }

    const deltaRating = deltaVote * 3;

    if (deltaVote !== 0) {
      await client.query(`update messages set score = score + $1 where id = $2`, [deltaVote, messageId]);
      await client.query(`update users set rating = rating + $1 where id = $2`, [deltaRating, msg.user_id]);
    }

    await client.query("commit");
    res.json({ success: true, deltaVote, deltaRating, weightUsed: weight });
  } catch (e) {
    try {
      await client.query("rollback");
    } catch (_) {}
    console.error(e);
    res.status(500).json({ error: "server error" });
  } finally {
    client.release();
  }
});

// ---------- HTML UI ----------
app.get("/debate/:id", async (req, res) => {
  const debateId = parseInt(req.params.id, 10);
  const debateR = await q("select id, question from debates where id = $1", [debateId]);
  const debate = debateR.rows[0];
  if (!debate) return res.status(404).type("text").send("Debate not found");

  res.type("html").send(`
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Live Debate</title>
  <style>
    body {
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
      background: #f6f7fb;
      color: #111;
      margin: 0;
      padding: 28px 16px;
    }
    .wrap { max-width: 980px; margin: 0 auto; }

    .hero {
      display: grid;
      grid-template-columns: 1fr 320px;
      gap: 18px;
      align-items: start;
      margin-bottom: 18px;
    }
    @media (max-width: 920px) {
      .hero { grid-template-columns: 1fr; }
    }

    .brand h1 { margin: 0; font-size: 44px; letter-spacing: -0.02em; display:flex; gap:10px; align-items:center; }

    .questionCard {
      margin-top: 10px;
      background: #fff;
      border: 1px solid #e8e8ee;
      border-radius: 18px;
      padding: 14px 16px;
      box-shadow: 0 8px 24px rgba(0,0,0,0.06);
    }
    .questionTitle { font-size: 12px; color: #666; text-transform: uppercase; letter-spacing: .08em; margin-bottom: 8px; }
    .questionText { font-size: 18px; font-weight: 650; line-height: 1.25; }

    .card {
      background: #fff;
      border: 1px solid #e8e8ee;
      border-radius: 18px;
      padding: 14px;
      box-shadow: 0 8px 24px rgba(0,0,0,0.06);
    }

    .pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      border-radius: 999px;
      background: #111;
      color: #fff;
      font-weight: 650;
      font-size: 12px;
      margin-bottom: 10px;
    }

    .row { margin-top: 10px; }
    .muted { color: #666; font-size: 13px; }

    .btn {
      padding: 10px 14px;
      border-radius: 14px;
      border: 1px solid #d7d7de;
      background: #fff;
      cursor: pointer;
      font-weight: 650;
    }
    .btn:hover { transform: translateY(-1px); }
    .btn:active { transform: translateY(0px); }
    .btnSelected { background:#111; color:#fff; border-color:#111; }

    input {
      padding: 12px 14px;
      width: 100%;
      border-radius: 14px;
      border: 1px solid #d7d7de;
      outline: none;
      background: #fff;
      box-sizing: border-box;
    }
    input:focus { border-color: #111; }

    .composer {
      margin-top: 10px;
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 10px;
      align-items: center;
    }

    #list { margin-top: 18px; }

    .msg {
      border: 1px solid #ececf2;
      border-radius: 18px;
      padding: 14px;
      margin: 12px 0;
      display: grid;
      grid-template-columns: 120px 1fr;
      gap: 14px;
      background: #fff;
      box-shadow: 0 8px 24px rgba(0,0,0,0.04);
    }

    .scorebox { text-align: center; }
    .score { font-size: 22px; font-weight: 800; }
    .meta { font-size: 12px; color: #777; margin-top: 6px; }

    .tag {
      display: inline-flex;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 750;
      border: 1px solid #e3e3ea;
    }
    .tagYes { background: #ecfff0; border-color: #bfe9c8; color: #0c7a2a; }
    .tagNo  { background: #fff1f1; border-color: #f1bebe; color: #a21a1a; }

    .voteBtns { display:flex; gap:8px; justify-content:center; margin-top:10px; }
    .voteBtn { width:46px; height:40px; border-radius:14px; border:1px solid #d7d7de; background:#fff; cursor:pointer; font-size:18px; }

    .sectionTitle { margin: 20px 0 10px; font-size: 20px; letter-spacing: -0.01em; }

    .topLine { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
    .sortRow { display:flex; gap:8px; align-items:center; margin-top:10px; font-size:13px; color:#666; }

    a { color: inherit; text-decoration: none; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <div>
        <div class="brand">
          <h1>🔥 Live Debate</h1>
        </div>
        <div class="questionCard">
          <div class="questionTitle">Question</div>
          <div class="questionText">${escapeHtml(debate.question)}</div>
        </div>
      </div>

      <div>
        <div class="card">
          <div class="pill">Top users</div>
          <div class="muted" id="lb">loading...</div>
        </div>

        <div class="card" style="margin-top:14px;">
          <div class="pill">Account</div>
          <div class="muted" id="meBox">loading...</div>

          <div class="row" id="loginBox" style="display:none;">
            <input id="username" placeholder="username (3-20, letters/numbers/_)" />
            <div class="row">
              <button class="btn btnSelected" id="loginBtn">Login</button>
            </div>
          </div>

          <div class="row" id="logoutBox" style="display:none;">
            <button class="btn" id="logoutBtn">Logout</button>
          </div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="topLine">
        <span class="pill" id="chosenPill">Chosen: YES</span>
        <button class="btn btnSelected" id="yesBtn">YES</button>
        <button class="btn" id="noBtn">NO</button>
      </div>

      <div class="composer">
        <input id="text" placeholder="Write your argument (max 300 chars)..." />
        <button class="btn btnSelected" id="sendBtn">Send</button>
      </div>

      <div class="sortRow">
        Sort:
        <button class="btn btnSelected" id="sortNew">New</button>
        <button class="btn" id="sortTop">Top</button>
        <span id="sortHint">(current: new)</span>
      </div>
    </div>

    <div class="sectionTitle">Arguments</div>
    <div id="list"></div>
  </div>

<script>
  const debateId = ${debateId};

  let side = "YES";
  let sort = "new";

  const yesBtn = document.getElementById("yesBtn");
  const noBtn = document.getElementById("noBtn");
  const chosenPill = document.getElementById("chosenPill");

  function setSide(next) {
    side = next;
    chosenPill.textContent = "Chosen: " + side;
    yesBtn.classList.toggle("btnSelected", side === "YES");
    noBtn.classList.toggle("btnSelected", side === "NO");
  }

  yesBtn.addEventListener("click", () => setSide("YES"));
  noBtn.addEventListener("click", () => setSide("NO"));

  const sortNew = document.getElementById("sortNew");
  const sortTop = document.getElementById("sortTop");
  const sortHint = document.getElementById("sortHint");

  function setSort(next) {
    sort = next;
    sortHint.textContent = "(current: " + sort + ")";
    sortNew.classList.toggle("btnSelected", sort === "new");
    sortTop.classList.toggle("btnSelected", sort === "top");
    loadMessages();
  }

  sortNew.addEventListener("click", () => setSort("new"));
  sortTop.addEventListener("click", () => setSort("top"));

  function escapeHtml(s) {
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;");
  }

  // leaderboard
  function loadLeaderboard() {
    fetch('/leaderboard/users?limit=5')
      .then(r => r.json())
      .then(rows => {
        document.getElementById('lb').innerHTML =
          rows.map((u, i) => \`#\${i+1} \${u.username} — \${u.rating}\`).join('<br>');
      })
      .catch(() => document.getElementById('lb').textContent = 'failed to load');
  }

  // me
  function loadMe() {
    fetch('/me').then(r => r.json()).then(data => {
      const me = data.user;
      const meBox = document.getElementById("meBox");
      const loginBox = document.getElementById("loginBox");
      const logoutBox = document.getElementById("logoutBox");

      if (!me) {
        meBox.textContent = "Not logged in";
        loginBox.style.display = "block";
        logoutBox.style.display = "none";
      } else {
        meBox.textContent = "Logged in as " + me.username + " (rating: " + me.rating + ")";
        loginBox.style.display = "none";
        logoutBox.style.display = "block";
      }
    });
  }

  document.getElementById("loginBtn").addEventListener("click", () => {
    const username = document.getElementById("username").value.trim();
    fetch("/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username })
    }).then(r => r.json()).then(resp => {
      if (resp.error) return alert(resp.error);
      loadMe();
      loadLeaderboard();
      loadMessages();
    });
  });

  document.getElementById("logoutBtn").addEventListener("click", () => {
    fetch("/auth/logout", { method: "POST" }).then(() => {
      loadMe();
      loadLeaderboard();
      loadMessages();
    });
  });

  // send message
  document.getElementById("sendBtn").addEventListener("click", () => {
    const text = document.getElementById("text").value.trim();
    fetch(\`/debate/\${debateId}/messages\`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text, side })
    }).then(r => r.json()).then(resp => {
      if (resp.error) return alert(resp.error);
      document.getElementById("text").value = "";
      loadMessages();
    });
  });

  // render messages
  function render(rows) {
    const list = document.getElementById("list");
    list.innerHTML = "";

    for (const m of rows) {
      const el = document.createElement("div");
      el.className = "msg";

      const tagClass = m.side === "YES" ? "tag tagYes" : "tag tagNo";
      const tagText = m.side === "YES" ? "YES" : "NO";

      el.innerHTML = \`
        <div class="scorebox">
          <div class="score">\${m.score}</div>

          <div class="voteBtns">
            <button class="voteBtn" data-id="\${m.id}" data-v="1">👍</button>
            <button class="voteBtn" data-id="\${m.id}" data-v="-1">👎</button>
          </div>

          <div class="meta">\${new Date(m.created_at).toLocaleString()}</div>
        </div>

        <div class="content">
          <div>
            <span class="\${tagClass}">\${tagText}</span>
            <b>\${escapeHtml(m.username)}</b>
          </div>
          <div style="margin-top:8px;">\${escapeHtml(m.text)}</div>
        </div>
      \`;

      list.appendChild(el);
    }

    // handlers for vote buttons
    list.querySelectorAll(".voteBtn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = btn.getAttribute("data-id");
        const v = parseInt(btn.getAttribute("data-v"), 10);

        fetch(\`/messages/\${id}/vote\`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ value: v })
        })
          .then(r => r.json())
          .then(resp => {
            if (resp.error) return alert(resp.error);
            loadLeaderboard();
            loadMe();
            loadMessages();
          });
      });
    });
  }

  function loadMessages() {
    fetch(\`/debate/\${debateId}/messages\`)
      .then(r => r.json())
      .then(render)
      .catch(() => {
        document.getElementById("list").textContent = "failed to load messages";
      });
  }

  // init
  setSide("YES");
  loadLeaderboard();
  loadMe();
  loadMessages();
</script>
</body>
</html>
  `);
});

function escapeHtml(s) {
  return String(s).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

// ---------- PORT ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log("Server listening on port " + PORT);
});