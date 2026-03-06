require("dotenv").config();
const express    = require("express");
const cookieParser = require("cookie-parser");
const rateLimit  = require("express-rate-limit");
const { Pool }   = require("pg");

// ─────────────────────────────────────────────────────────
// Setup
// ─────────────────────────────────────────────────────────
const app = express();
app.set("trust proxy", 1);
app.use(express.json());
app.use(cookieParser());

if (!process.env.DATABASE_URL) {
  console.error("❌ DATABASE_URL is not set.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("render.com")
    ? { rejectUnauthorized: false }
    : undefined,
  max: 20,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
});

pool.on("error", (err) => console.error("🔴 DB pool error:", err.message));

// ─────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────
const wrap = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

function esc(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

async function getMe(req) {
  const username = req.cookies?.username;
  if (!username) return null;
  const r = await pool.query(
    "SELECT id, username, rating FROM users WHERE username = $1",
    [username]
  );
  return r.rows[0] ?? null;
}

// ─────────────────────────────────────────────────────────
// Rate limiters
// ─────────────────────────────────────────────────────────
const loginLimiter   = rateLimit({ windowMs: 60_000, max: 20,  message: { error: "Too many login attempts" } });
const messageLimiter = rateLimit({ windowMs: 60_000, max: 10,  message: { error: "Posting too fast — max 10 per minute" } });
const voteLimiter    = rateLimit({ windowMs: 60_000, max: 60,  message: { error: "Voting too fast" } });

// ─────────────────────────────────────────────────────────
// Auth
// ─────────────────────────────────────────────────────────
app.post("/auth/login", loginLimiter, wrap(async (req, res) => {
  const username = (req.body?.username || "").trim().replace(/\s+/g, "_");
  if (!username || username.length < 3 || username.length > 20)
    return res.status(400).json({ error: "Username must be 3–20 characters" });
  if (!/^[a-zA-Z0-9_]+$/.test(username))
    return res.status(400).json({ error: "Only letters, numbers and _ allowed" });

  await pool.query(
    "INSERT INTO users (username) VALUES ($1) ON CONFLICT (username) DO NOTHING",
    [username]
  );
  res.cookie("username", username, { httpOnly: true, sameSite: "lax" });
  const r = await pool.query(
    "SELECT id, username, rating FROM users WHERE username = $1", [username]
  );
  res.json({ success: true, user: r.rows[0] });
}));

app.post("/auth/logout", (req, res) => {
  res.clearCookie("username");
  res.json({ success: true });
});

app.get("/me", wrap(async (req, res) => {
  res.json({ user: await getMe(req) });
}));

// ─────────────────────────────────────────────────────────
// API: debates list
// ─────────────────────────────────────────────────────────
app.get("/api/debates", wrap(async (req, res) => {
  const r = await pool.query(`
    SELECT d.id, d.question, d.category,
           COUNT(m.id)::int AS arg_count,
           COUNT(CASE WHEN m.side='YES' THEN 1 END)::int AS yes_count,
           COUNT(CASE WHEN m.side='NO'  THEN 1 END)::int AS no_count
    FROM   debates d
    LEFT   JOIN messages m ON m.debate_id = d.id
    GROUP  BY d.id
    ORDER  BY d.id ASC
  `);
  res.json(r.rows);
}));

// ─────────────────────────────────────────────────────────
// API: leaderboard
// ─────────────────────────────────────────────────────────
app.get("/leaderboard/users", wrap(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || "10", 10), 100);
  const r = await pool.query(
    "SELECT username, rating FROM users ORDER BY rating DESC, id ASC LIMIT $1",
    [limit]
  );
  res.json(r.rows);
}));

// ─────────────────────────────────────────────────────────
// API: messages
// ─────────────────────────────────────────────────────────
app.get("/debate/:id/messages", wrap(async (req, res) => {
  const debateId = parseInt(req.params.id, 10);
  if (!Number.isFinite(debateId)) return res.status(400).json({ error: "Bad debate id" });

  const sort    = req.query.sort === "top" ? "top" : "new";
  const orderBy = sort === "top"
    ? "m.score DESC, m.created_at DESC"
    : "m.created_at DESC";
  const limit = Math.min(parseInt(req.query.limit || "50", 10), 200);

  const r = await pool.query(`
    SELECT m.id, m.side, m.text, m.score, m.created_at, u.username
    FROM   messages m
    JOIN   users u ON u.id = m.user_id
    WHERE  m.debate_id = $1
    ORDER  BY ${orderBy}
    LIMIT  $2
  `, [debateId, limit]);

  res.json(r.rows);
}));

app.post("/debate/:id/messages", messageLimiter, wrap(async (req, res) => {
  const me = await getMe(req);
  if (!me) return res.status(401).json({ error: "Login first" });

  const debateId = parseInt(req.params.id, 10);
  if (!Number.isFinite(debateId)) return res.status(400).json({ error: "Bad debate id" });

  const exists = await pool.query("SELECT 1 FROM debates WHERE id = $1", [debateId]);
  if (!exists.rows[0]) return res.status(404).json({ error: "Debate not found" });

  const text = String(req.body?.text || "").trim();
  const side = String(req.body?.side || "").toUpperCase();

  if (!text)             return res.status(400).json({ error: "Text is required" });
  if (text.length > 300) return res.status(400).json({ error: "Max 300 characters" });
  if (side !== "YES" && side !== "NO")
    return res.status(400).json({ error: "Side must be YES or NO" });

  const r = await pool.query(
    "INSERT INTO messages (debate_id, user_id, side, text) VALUES ($1,$2,$3,$4) RETURNING id",
    [debateId, me.id, side, text]
  );
  res.status(201).json({ success: true, id: r.rows[0].id });
}));

// ─────────────────────────────────────────────────────────
// API: voting
// ─────────────────────────────────────────────────────────
app.post("/messages/:id/vote", voteLimiter, wrap(async (req, res) => {
  const me = await getMe(req);
  if (!me) return res.status(401).json({ error: "Login first" });

  const messageId = parseInt(req.params.id, 10);
  if (!Number.isFinite(messageId)) return res.status(400).json({ error: "Bad message id" });

  const value = parseInt(req.body?.value, 10);
  if (value !== 1 && value !== -1) return res.status(400).json({ error: "Value must be 1 or -1" });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Vote weight based on voter rating (1–5)
    const voterR = await client.query("SELECT rating FROM users WHERE id = $1", [me.id]);
    const weight = Math.min(5, 1 + Math.floor((voterR.rows[0]?.rating ?? 0) / 50));

    const msgR = await client.query(
      "SELECT id, user_id FROM messages WHERE id = $1 FOR UPDATE",
      [messageId]
    );
    const msg = msgR.rows[0];
    if (!msg) { await client.query("ROLLBACK"); return res.status(404).json({ error: "Message not found" }); }
    if (msg.user_id === me.id) { await client.query("ROLLBACK"); return res.status(400).json({ error: "Cannot vote your own message" }); }

    const existR   = await client.query(
      "SELECT id, value, weight FROM votes WHERE message_id = $1 AND user_id = $2",
      [messageId, me.id]
    );
    const existing = existR.rows[0];
    let deltaVote  = 0;

    if (!existing) {
      await client.query(
        "INSERT INTO votes (message_id, user_id, value, weight) VALUES ($1,$2,$3,$4)",
        [messageId, me.id, value, weight]
      );
      deltaVote = value * weight;
    } else if (existing.value === value) {
      await client.query("DELETE FROM votes WHERE id = $1", [existing.id]);
      deltaVote = -(existing.value * existing.weight);
    } else {
      await client.query(
        "UPDATE votes SET value = $1, weight = $2 WHERE id = $3",
        [value, weight, existing.id]
      );
      deltaVote = (value * weight) - (existing.value * existing.weight);
    }

    if (deltaVote !== 0) {
      await client.query("UPDATE messages SET score = score + $1 WHERE id = $2", [deltaVote, messageId]);
      await client.query("UPDATE users SET rating = rating + $1 WHERE id = $2", [deltaVote * 3, msg.user_id]);
    }

    await client.query("COMMIT");
    res.json({ success: true, deltaVote, weightUsed: weight });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}));

// ─────────────────────────────────────────────────────────
// Pages
// ─────────────────────────────────────────────────────────
app.get("/", wrap(async (req, res) => {
  res.type("html").send(homePage());
}));

app.get("/debate", (req, res) => res.redirect("/"));

app.get("/debate/:id", wrap(async (req, res) => {
  const debateId = parseInt(req.params.id, 10);
  const r = await pool.query("SELECT id, question, category FROM debates WHERE id = $1", [debateId]);
  const debate = r.rows[0];
  if (!debate) return res.status(404).type("text").send("Debate not found");
  res.type("html").send(debatePage(debateId, debate.question, debate.category));
}));

// ─────────────────────────────────────────────────────────
// Error handler
// ─────────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error("🔴", err.message);
  res.status(500).json({ error: "Internal server error" });
});

// ─────────────────────────────────────────────────────────
// Shared CSS + nav snippet
// ─────────────────────────────────────────────────────────
const SHARED_HEAD = `
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link href="https://fonts.googleapis.com/css2?family=Unbounded:wght@400;600;700;900&family=Manrope:wght@300;400;500;600&display=swap" rel="stylesheet"/>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg:      #0b0c10;
      --bg2:     #111318;
      --bg3:     #181b22;
      --border:  rgba(255,255,255,0.06);
      --border2: rgba(255,255,255,0.13);
      --yes:     #3b82f6;
      --yes-dim: rgba(59,130,246,0.13);
      --no:      #ef4444;
      --no-dim:  rgba(239,68,68,0.13);
      --accent:  #3b82f6;
      --gold:    #f59e0b;
      --text:    #eaedf3;
      --muted:   #55596a;
      --muted2:  #8891a4;
      --r:       14px;
    }
    html { scroll-behavior: smooth; }
    body {
      font-family: 'Manrope', sans-serif;
      background: var(--bg); color: var(--text);
      min-height: 100vh; overflow-x: hidden;
    }
    body::before {
      content: ''; position: fixed; top: -300px; left: 50%;
      transform: translateX(-50%);
      width: 900px; height: 600px;
      background: radial-gradient(ellipse, rgba(59,130,246,0.06) 0%, transparent 65%);
      pointer-events: none; z-index: 0;
    }
    /* Nav */
    nav {
      position: sticky; top: 0; z-index: 100;
      border-bottom: 1px solid var(--border);
      background: rgba(11,12,16,0.88);
      backdrop-filter: blur(18px);
    }
    .nav-inner {
      max-width: 1100px; margin: 0 auto;
      display: flex; align-items: center; justify-content: space-between;
      padding: 0 24px; height: 58px;
    }
    .logo {
      font-family: 'Unbounded', sans-serif;
      font-weight: 900; font-size: 16px; letter-spacing: .04em;
      color: var(--text); text-decoration: none;
    }
    .logo span { color: var(--accent); }
    .nav-right { display: flex; align-items: center; gap: 12px; font-size: 13px; color: var(--muted2); }
    .nav-right strong { color: var(--text); font-weight: 600; }
    .nav-right .pts { color: var(--gold); font-weight: 600; }
    /* Cards */
    .card {
      background: var(--bg2); border: 1px solid var(--border);
      border-radius: var(--r); padding: 20px;
    }
    .card-label {
      font-size: 10px; font-weight: 700; letter-spacing: .12em;
      text-transform: uppercase; color: var(--muted); margin-bottom: 14px;
    }
    a { color: inherit; text-decoration: none; }
  </style>
`;

// ─────────────────────────────────────────────────────────
// HOME PAGE
// ─────────────────────────────────────────────────────────
function homePage() {
  return `<!doctype html>
<html lang="en">
<head>
  ${SHARED_HEAD}
  <title>ARGU — Live Debates</title>
  <style>
    .page { max-width: 1100px; margin: 0 auto; padding: 48px 24px 80px; position: relative; z-index: 1; }

    .hero-home { text-align: center; padding: 20px 0 52px; }
    .hero-home h1 {
      font-family: 'Unbounded', sans-serif;
      font-size: clamp(32px, 5vw, 58px); font-weight: 900;
      letter-spacing: -0.03em; line-height: 1.08;
      margin-bottom: 16px;
    }
    .hero-home h1 span { color: var(--accent); }
    .hero-home p { font-size: 16px; color: var(--muted2); max-width: 480px; margin: 0 auto; }

    /* Auth bar */
    .auth-bar {
      display: flex; align-items: center; justify-content: center;
      gap: 10px; margin-top: 28px; flex-wrap: wrap;
    }
    .auth-input {
      padding: 11px 16px; border-radius: 12px; border: 1px solid var(--border);
      background: var(--bg2); color: var(--text);
      font-family: 'Manrope', sans-serif; font-size: 14px;
      width: 220px; outline: none; transition: border-color .18s;
    }
    .auth-input:focus { border-color: rgba(59,130,246,0.5); }
    .auth-input::placeholder { color: var(--muted); }
    .btn-join {
      padding: 11px 22px; border-radius: 12px; border: none;
      background: var(--accent); color: #fff;
      font-family: 'Unbounded', sans-serif; font-weight: 700; font-size: 11px;
      letter-spacing: .04em; cursor: pointer; transition: opacity .18s;
    }
    .btn-join:hover { opacity: .85; }
    .btn-out {
      padding: 10px 18px; border-radius: 12px;
      border: 1px solid var(--border); background: var(--bg2);
      color: var(--muted2); font-size: 13px; cursor: pointer; transition: all .15s;
    }
    .btn-out:hover { border-color: var(--border2); color: var(--text); }
    .me-greeting { font-size: 14px; color: var(--muted2); }
    .me-greeting strong { color: var(--text); }

    /* Category filter */
    .filter-row { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 28px; }
    .filter-btn {
      padding: 7px 16px; border-radius: 999px; font-size: 12px; font-weight: 600;
      border: 1px solid var(--border); background: transparent; color: var(--muted2);
      cursor: pointer; transition: all .15s;
    }
    .filter-btn:hover, .filter-btn.on {
      background: var(--bg3); border-color: var(--border2); color: var(--text);
    }

    /* Debate grid */
    .debates-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: 16px;
    }
    .debate-card {
      background: var(--bg2); border: 1px solid var(--border);
      border-radius: 18px; padding: 22px;
      display: flex; flex-direction: column; gap: 12px;
      cursor: pointer; transition: border-color .2s, transform .18s;
      text-decoration: none; color: inherit;
    }
    .debate-card:hover { border-color: var(--border2); transform: translateY(-2px); }
    .debate-card-top { display: flex; align-items: center; justify-content: space-between; }
    .cat-tag {
      font-size: 10px; font-weight: 700; letter-spacing: .1em;
      text-transform: uppercase; color: var(--accent);
      background: var(--yes-dim); border: 1px solid rgba(59,130,246,.2);
      padding: 3px 9px; border-radius: 999px;
    }
    .arg-count { font-size: 12px; color: var(--muted); }
    .debate-q {
      font-family: 'Unbounded', sans-serif;
      font-size: 15px; font-weight: 700; line-height: 1.3;
      letter-spacing: -0.01em;
    }
    .vote-bar { display: flex; gap: 0; border-radius: 6px; overflow: hidden; height: 5px; background: var(--bg3); }
    .bar-yes { background: var(--yes); transition: width .4s ease; }
    .bar-no  { background: var(--no);  transition: width .4s ease; }
    .vote-nums { display: flex; justify-content: space-between; font-size: 11px; }
    .vote-yes { color: var(--yes); font-weight: 600; }
    .vote-no  { color: var(--no);  font-weight: 600; }
    .open-btn {
      margin-top: auto; padding: 10px; border-radius: 10px; text-align: center;
      background: var(--bg3); border: 1px solid var(--border);
      font-size: 12px; font-weight: 600; color: var(--muted2);
      transition: all .15s;
    }
    .debate-card:hover .open-btn { background: var(--accent); border-color: var(--accent); color: #fff; }
  </style>
</head>
<body>
<nav>
  <div class="nav-inner">
    <a class="logo" href="/">ARGU<span>.</span></a>
    <div class="nav-right" id="navRight">Loading…</div>
  </div>
</nav>

<div class="page">
  <div class="hero-home">
    <h1>Argue.<br/>Vote. <span>Win.</span></h1>
    <p>Real debates on the topics that matter. Pick a side and make your case.</p>

    <div class="auth-bar">
      <div id="authArea">Loading…</div>
    </div>
  </div>

  <div class="filter-row" id="filterRow">
    <button class="filter-btn on" data-cat="All">All</button>
  </div>

  <div class="debates-grid" id="grid">
    <div style="color:var(--muted);font-size:14px;grid-column:1/-1;text-align:center;padding:40px">Loading debates…</div>
  </div>
</div>

<script>
  let allDebates = [];
  let currentCat = "All";

  function esc(s) {
    return String(s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");
  }

  async function api(url, opts = {}) {
    const r = await fetch(url, { headers: {"content-type":"application/json"}, ...opts });
    return r.json();
  }

  async function loadMe() {
    const data = await api("/me").catch(() => ({user:null}));
    const me   = data.user;
    const navRight  = document.getElementById("navRight");
    const authArea  = document.getElementById("authArea");

    if (!me) {
      navRight.innerHTML = 'Not signed in';
      authArea.innerHTML = \`
        <input class="auth-input" id="username" placeholder="Pick a username…" maxlength="20"/>
        <button class="btn-join" id="loginBtn">JOIN DEBATE</button>
      \`;
      document.getElementById("loginBtn").addEventListener("click", async () => {
        const username = document.getElementById("username").value.trim();
        if (!username) return;
        const resp = await api("/auth/login", { method:"POST", body: JSON.stringify({username}) });
        if (resp.error) return alert(resp.error);
        await loadMe();
      });
    } else {
      navRight.innerHTML = \`<strong>\${esc(me.username)}</strong> <span class="pts">★\${me.rating}</span>\`;
      authArea.innerHTML = \`
        <span class="me-greeting">Welcome back, <strong>\${esc(me.username)}</strong> — pick a debate below</span>
        <button class="btn-out" id="logoutBtn">Sign out</button>
      \`;
      document.getElementById("logoutBtn").addEventListener("click", async () => {
        await api("/auth/logout", {method:"POST"});
        await loadMe();
      });
    }
  }

  async function loadDebates() {
    allDebates = await api("/api/debates").catch(() => []);
    buildFilters();
    renderGrid();
  }

  function buildFilters() {
    const cats = ["All", ...new Set(allDebates.map(d => d.category))];
    document.getElementById("filterRow").innerHTML = cats.map(c =>
      \`<button class="filter-btn \${c === currentCat ? 'on' : ''}" data-cat="\${esc(c)}">\${esc(c)}</button>\`
    ).join("");
    document.getElementById("filterRow").querySelectorAll(".filter-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        currentCat = btn.getAttribute("data-cat");
        document.querySelectorAll(".filter-btn").forEach(b => b.classList.toggle("on", b.getAttribute("data-cat") === currentCat));
        renderGrid();
      });
    });
  }

  function renderGrid() {
    const debates = currentCat === "All" ? allDebates : allDebates.filter(d => d.category === currentCat);
    const grid = document.getElementById("grid");
    if (!debates.length) { grid.innerHTML = '<div style="color:var(--muted);grid-column:1/-1;text-align:center;padding:40px">No debates yet</div>'; return; }

    grid.innerHTML = debates.map(d => {
      const total  = d.yes_count + d.no_count;
      const yesPct = total > 0 ? Math.round(d.yes_count / total * 100) : 50;
      const noPct  = 100 - yesPct;
      return \`
        <a class="debate-card" href="/debate/\${d.id}">
          <div class="debate-card-top">
            <span class="cat-tag">\${esc(d.category)}</span>
            <span class="arg-count">\${d.arg_count} argument\${d.arg_count !== 1 ? 's' : ''}</span>
          </div>
          <div class="debate-q">\${esc(d.question)}</div>
          <div class="vote-bar">
            <div class="bar-yes" style="width:\${yesPct}%"></div>
            <div class="bar-no"  style="width:\${noPct}%"></div>
          </div>
          <div class="vote-nums">
            <span class="vote-yes">YES \${yesPct}%</span>
            <span class="vote-no">\${noPct}% NO</span>
          </div>
          <div class="open-btn">Open debate →</div>
        </a>
      \`;
    }).join("");
  }

  loadMe();
  loadDebates();
</script>
</body>
</html>`;
}

// ─────────────────────────────────────────────────────────
// DEBATE PAGE
// ─────────────────────────────────────────────────────────
function debatePage(debateId, question, category) {
  return `<!doctype html>
<html lang="en">
<head>
  ${SHARED_HEAD}
  <title>${esc(question)} — ARGU</title>
  <style>
    .page { max-width: 1100px; margin: 0 auto; padding: 0 24px 80px; position: relative; z-index: 1; }

    /* Hero */
    .hero { padding: 44px 0 32px; }
    .back-link { font-size: 13px; color: var(--muted2); display: inline-flex; align-items: center; gap: 6px; margin-bottom: 20px; transition: color .15s; }
    .back-link:hover { color: var(--text); }
    .eyebrow {
      display: inline-flex; align-items: center; gap: 6px;
      font-size: 10px; font-weight: 700; letter-spacing: .12em; text-transform: uppercase;
      color: var(--accent); border: 1px solid rgba(59,130,246,0.3);
      background: rgba(59,130,246,0.07); padding: 4px 12px; border-radius: 999px;
      margin-bottom: 16px;
    }
    .live-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--accent); animation: blink 1.4s ease-in-out infinite; }
    @keyframes blink { 0%,100%{opacity:1} 50%{opacity:.2} }
    .hero-q {
      font-family: 'Unbounded', sans-serif;
      font-size: clamp(22px, 3.5vw, 40px); font-weight: 700; line-height: 1.15;
      letter-spacing: -0.02em; max-width: 780px; margin-bottom: 18px;
    }
    /* YES/NO mega counter */
    .scoreboard {
      display: flex; gap: 12px; align-items: stretch; margin-bottom: 8px;
    }
    .score-side {
      flex: 1; padding: 16px 20px; border-radius: 14px; border: 1px solid var(--border);
      display: flex; align-items: center; justify-content: space-between;
    }
    .score-side.yes { background: var(--yes-dim); border-color: rgba(59,130,246,.25); }
    .score-side.no  { background: var(--no-dim);  border-color: rgba(239,68,68,.25);  }
    .score-label { font-family: 'Unbounded', sans-serif; font-size: 12px; font-weight: 700; }
    .score-label.yes { color: var(--yes); }
    .score-label.no  { color: var(--no); }
    .score-num-big { font-family: 'Unbounded', sans-serif; font-size: 26px; font-weight: 900; line-height: 1; }
    .score-num-big.yes { color: var(--yes); }
    .score-num-big.no  { color: var(--no); }
    .score-pct { font-size: 12px; color: var(--muted2); }
    .progress-bar { height: 5px; background: var(--bg3); border-radius: 999px; overflow: hidden; margin-bottom: 24px; }
    .progress-yes { height: 100%; background: var(--yes); transition: width .5s ease; }

    /* Grid */
    .main { display: grid; grid-template-columns: 1fr 280px; gap: 24px; align-items: start; }
    @media (max-width: 820px) { .main { grid-template-columns: 1fr; } }

    /* Compose */
    .side-row { display: flex; gap: 8px; margin-bottom: 12px; }
    .side-btn {
      flex: 1; padding: 10px; border-radius: 10px; border: 1px solid var(--border);
      background: var(--bg3); color: var(--muted2);
      font-family: 'Unbounded', sans-serif; font-size: 11px; font-weight: 700;
      letter-spacing: .06em; cursor: pointer; transition: all .18s;
    }
    .side-btn:hover { color: var(--text); border-color: var(--border2); }
    .side-btn.yes-on { background: var(--yes-dim); border-color: var(--yes); color: var(--yes); }
    .side-btn.no-on  { background: var(--no-dim);  border-color: var(--no);  color: var(--no);  }
    textarea {
      width: 100%; min-height: 86px; resize: vertical; padding: 13px 14px;
      border-radius: 10px; border: 1px solid var(--border);
      background: var(--bg3); color: var(--text);
      font-family: 'Manrope', sans-serif; font-size: 14px; line-height: 1.55;
      outline: none; transition: border-color .18s;
    }
    textarea:focus { border-color: rgba(59,130,246,0.5); }
    textarea::placeholder { color: var(--muted); }
    .char-hint { font-size: 11px; color: var(--muted); text-align: right; margin-top: 5px; }
    .char-hint.warn { color: var(--no); }
    .post-btn {
      margin-top: 12px; width: 100%; padding: 13px; border-radius: 10px; border: none;
      background: var(--accent); color: #fff;
      font-family: 'Unbounded', sans-serif; font-weight: 700; font-size: 11px;
      letter-spacing: .04em; cursor: pointer; transition: opacity .18s, transform .12s;
    }
    .post-btn:hover { opacity: .88; transform: translateY(-1px); }
    .post-btn:active { transform: none; }

    /* Account */
    .me-info { font-size: 13px; color: var(--muted2); margin-bottom: 14px; line-height: 1.7; }
    .me-info strong { color: var(--text); }
    .auth-input {
      width: 100%; padding: 11px 13px; border-radius: 10px; border: 1px solid var(--border);
      background: var(--bg3); color: var(--text);
      font-family: 'Manrope', sans-serif; font-size: 13px; outline: none; transition: border-color .18s;
    }
    .auth-input:focus { border-color: rgba(59,130,246,.5); }
    .auth-input::placeholder { color: var(--muted); }
    .join-btn {
      margin-top: 10px; width: 100%; padding: 11px; border-radius: 10px;
      border: 1px solid var(--accent); background: var(--yes-dim); color: var(--accent);
      font-size: 13px; font-weight: 600; cursor: pointer; transition: background .18s;
    }
    .join-btn:hover { background: rgba(59,130,246,.22); }
    .leave-btn {
      margin-top: 10px; width: 100%; padding: 11px; border-radius: 10px;
      border: 1px solid var(--border); background: var(--bg3); color: var(--muted2);
      font-size: 13px; cursor: pointer; transition: all .15s;
    }
    .leave-btn:hover { border-color: var(--border2); color: var(--text); }

    /* Leaderboard */
    .lb-item { display: flex; align-items: center; gap: 10px; padding: 8px 0; border-bottom: 1px solid var(--border); font-size: 13px; }
    .lb-item:last-child { border-bottom: none; }
    .lb-num { font-family: 'Unbounded', sans-serif; font-size: 10px; font-weight: 700; color: var(--muted); width: 18px; text-align: center; }
    .lb-num.top { color: var(--gold); }
    .lb-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .lb-pts { font-size: 11px; color: var(--muted2); font-weight: 500; }

    /* Sort bar */
    .sort-bar { display: flex; align-items: center; gap: 6px; margin-bottom: 18px; }
    .sort-lbl { font-size: 12px; color: var(--muted); margin-right: 4px; }
    .sort-btn { padding: 6px 14px; border-radius: 8px; border: 1px solid var(--border); background: transparent; color: var(--muted); font-size: 12px; font-weight: 600; cursor: pointer; transition: all .15s; }
    .sort-btn.on { background: var(--bg3); color: var(--text); border-color: var(--border2); }

    /* Section header */
    .sec-hdr { font-family: 'Unbounded', sans-serif; font-size: 13px; font-weight: 700; letter-spacing: .02em; margin-bottom: 14px; }

    /* Message */
    .msg {
      display: grid; grid-template-columns: 56px 1fr; gap: 14px;
      background: var(--bg2); border: 1px solid var(--border);
      border-radius: var(--r); padding: 16px; margin-bottom: 10px;
      animation: slideUp .22s ease both; transition: border-color .18s;
    }
    .msg:hover { border-color: var(--border2); }
    @keyframes slideUp { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:none} }
    .vcol { display: flex; flex-direction: column; align-items: center; gap: 5px; }
    .vscore { font-family: 'Unbounded', sans-serif; font-weight: 800; font-size: 17px; line-height: 1; }
    .vscore.pos { color: var(--yes); }
    .vscore.neg { color: var(--no); }
    .vscore.zero { color: var(--muted); }
    .vbtn {
      width: 34px; height: 30px; border-radius: 8px; border: 1px solid var(--border);
      background: var(--bg3); color: var(--muted); font-size: 12px; cursor: pointer;
      display: flex; align-items: center; justify-content: center; transition: all .15s;
    }
    .vbtn.up:hover   { background: var(--yes-dim); border-color: var(--yes); color: var(--yes); }
    .vbtn.down:hover { background: var(--no-dim);  border-color: var(--no);  color: var(--no);  }
    .msg-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }
    .pill { display: inline-flex; padding: 3px 9px; border-radius: 999px; font-size: 10px; font-weight: 700; letter-spacing: .08em; }
    .pill.yes { background: var(--yes-dim); color: var(--yes); border: 1px solid rgba(59,130,246,.3); }
    .pill.no  { background: var(--no-dim);  color: var(--no);  border: 1px solid rgba(239,68,68,.3);  }
    .msg-author { font-size: 13px; font-weight: 600; }
    .msg-time { margin-left: auto; font-size: 11px; color: var(--muted); }
    .msg-body { font-size: 14px; color: rgba(234,237,243,0.82); line-height: 1.6; }

    .refresh-hint { text-align: center; font-size: 11px; color: var(--muted); margin-top: 16px; }

    /* Empty */
    .empty { text-align: center; padding: 48px 20px; color: var(--muted); font-size: 14px; }
  </style>
</head>
<body>
<nav>
  <div class="nav-inner">
    <a class="logo" href="/">ARGU<span>.</span></a>
    <div class="nav-right" id="navRight"></div>
  </div>
</nav>

<div class="page">
  <div class="hero">
    <a class="back-link" href="/">← All debates</a>
    <div class="eyebrow"><span class="live-dot"></span> ${esc(category)}</div>
    <h1 class="hero-q">${esc(question)}</h1>

    <div class="scoreboard">
      <div class="score-side yes">
        <span class="score-label yes">YES</span>
        <div>
          <div class="score-num-big yes" id="yesCount">0</div>
          <div class="score-pct" id="yesPct">—</div>
        </div>
      </div>
      <div class="score-side no">
        <div>
          <div class="score-num-big no" id="noCount">0</div>
          <div class="score-pct" id="noPct">—</div>
        </div>
        <span class="score-label no">NO</span>
      </div>
    </div>
    <div class="progress-bar"><div class="progress-yes" id="progressYes" style="width:50%"></div></div>
  </div>

  <div class="main">
    <div>
      <div class="card" style="margin-bottom:22px;">
        <div class="card-label">Your argument</div>
        <div class="side-row">
          <button class="side-btn yes-on" id="yesBtn">✓ YES</button>
          <button class="side-btn" id="noBtn">✗ NO</button>
        </div>
        <textarea id="text" placeholder="Make your case… (max 300 chars)" maxlength="300"></textarea>
        <div class="char-hint" id="charHint">0 / 300</div>
        <button class="post-btn" id="sendBtn">POST ARGUMENT</button>
      </div>

      <div class="sec-hdr">Arguments</div>
      <div class="sort-bar">
        <span class="sort-lbl">Sort by</span>
        <button class="sort-btn on" id="sortNew">Newest</button>
        <button class="sort-btn"   id="sortTop">Top rated</button>
      </div>
      <div id="list"><div class="empty">Loading…</div></div>
      <div class="refresh-hint" id="refreshHint"></div>
    </div>

    <div>
      <div class="card">
        <div class="card-label">Account</div>
        <div class="me-info" id="meBox">Loading…</div>
        <div id="loginBox" style="display:none">
          <input class="auth-input" id="username" placeholder="Pick a username…" maxlength="20"/>
          <button class="join-btn" id="loginBtn">Join debate</button>
        </div>
        <div id="logoutBox" style="display:none">
          <button class="leave-btn" id="logoutBtn">Sign out</button>
        </div>
      </div>

      <div class="card" style="margin-top:16px;">
        <div class="card-label">Top Debaters</div>
        <div id="lb"></div>
      </div>
    </div>
  </div>
</div>

<script>
  const DEBATE_ID = ${debateId};
  let side = "YES";
  let sort = "new";
  let refreshTimer;

  // ── Escape
  function esc(s) {
    return String(s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");
  }

  // ── Relative time
  function ago(ts) {
    const s = Math.floor((Date.now() - new Date(ts)) / 1000);
    if (s < 60)   return s + "s ago";
    if (s < 3600) return Math.floor(s/60) + "m ago";
    if (s < 86400)return Math.floor(s/3600) + "h ago";
    return Math.floor(s/86400) + "d ago";
  }

  // ── Fetch helper
  async function api(url, opts = {}) {
    const r = await fetch(url, { headers:{"content-type":"application/json"}, ...opts });
    return r.json();
  }

  // ── Side toggle
  const yesBtnEl = document.getElementById("yesBtn");
  const noBtnEl  = document.getElementById("noBtn");
  function setSide(s) {
    side = s;
    yesBtnEl.className = "side-btn" + (s==="YES" ? " yes-on" : "");
    noBtnEl.className  = "side-btn" + (s==="NO"  ? " no-on"  : "");
  }
  yesBtnEl.addEventListener("click", () => setSide("YES"));
  noBtnEl.addEventListener("click",  () => setSide("NO"));
  setSide("YES");

  // ── Sort toggle
  document.getElementById("sortNew").addEventListener("click", () => {
    sort = "new";
    document.getElementById("sortNew").classList.add("on");
    document.getElementById("sortTop").classList.remove("on");
    loadMessages();
  });
  document.getElementById("sortTop").addEventListener("click", () => {
    sort = "top";
    document.getElementById("sortTop").classList.add("on");
    document.getElementById("sortNew").classList.remove("on");
    loadMessages();
  });

  // ── Char counter
  const textEl = document.getElementById("text");
  textEl.addEventListener("input", () => {
    const n = textEl.value.length;
    const h = document.getElementById("charHint");
    h.textContent = n + " / 300";
    h.className = "char-hint" + (n > 260 ? " warn" : "");
  });

  // ── Me / leaderboard
  async function loadMe() {
    const data = await api("/me").catch(() => ({user:null}));
    const me   = data.user;
    const navRight  = document.getElementById("navRight");
    const meBox     = document.getElementById("meBox");
    const loginBox  = document.getElementById("loginBox");
    const logoutBox = document.getElementById("logoutBox");

    if (!me) {
      navRight.innerHTML  = '';
      meBox.innerHTML     = 'Not signed in — join to post & vote.';
      loginBox.style.display  = "block";
      logoutBox.style.display = "none";
    } else {
      navRight.innerHTML  = \`<strong>\${esc(me.username)}</strong> <span style="color:var(--gold)">★\${me.rating}</span>\`;
      meBox.innerHTML     = \`<strong>\${esc(me.username)}</strong><br><span style="color:var(--gold);font-size:12px">★ \${me.rating} rating pts</span>\`;
      loginBox.style.display  = "none";
      logoutBox.style.display = "block";
    }
  }

  async function loadLeaderboard() {
    const rows = await api("/leaderboard/users?limit=7").catch(() => []);
    const el = document.getElementById("lb");
    if (!rows.length) { el.innerHTML = '<div style="color:var(--muted);font-size:13px">No users yet</div>'; return; }
    el.innerHTML = rows.map((u,i) => \`
      <div class="lb-item">
        <span class="lb-num \${i===0?'top':''}">#\${i+1}</span>
        <span class="lb-name">\${esc(u.username)}</span>
        <span class="lb-pts">\${u.rating}pts</span>
      </div>\`).join("");
  }

  document.getElementById("loginBtn").addEventListener("click", async () => {
    const username = document.getElementById("username").value.trim();
    if (!username) return;
    const resp = await api("/auth/login", { method:"POST", body: JSON.stringify({username}) });
    if (resp.error) return alert(resp.error);
    await Promise.all([loadMe(), loadLeaderboard()]);
  });

  document.getElementById("logoutBtn").addEventListener("click", async () => {
    await api("/auth/logout", {method:"POST"});
    await Promise.all([loadMe(), loadLeaderboard()]);
  });

  // ── Post argument
  document.getElementById("sendBtn").addEventListener("click", async () => {
    const text = textEl.value.trim();
    if (!text) return;
    const resp = await api(\`/debate/\${DEBATE_ID}/messages\`, {
      method:"POST", body: JSON.stringify({text, side})
    });
    if (resp.error) return alert(resp.error);
    textEl.value = "";
    document.getElementById("charHint").textContent = "0 / 300";
    document.getElementById("charHint").className = "char-hint";
    await loadMessages();
  });

  // ── Render
  function renderMessages(rows) {
    // Update scoreboard
    const yes = rows.filter(m => m.side === "YES").length;
    const no  = rows.filter(m => m.side === "NO").length;
    const total = yes + no;
    const yesPct = total > 0 ? Math.round(yes/total*100) : 50;
    document.getElementById("yesCount").textContent = yes;
    document.getElementById("noCount").textContent  = no;
    document.getElementById("yesPct").textContent   = total > 0 ? yesPct + "% of arguments" : "—";
    document.getElementById("noPct").textContent    = total > 0 ? (100-yesPct) + "% of arguments" : "—";
    document.getElementById("progressYes").style.width = yesPct + "%";

    const list = document.getElementById("list");
    if (!rows.length) {
      list.innerHTML = '<div class="empty">No arguments yet — be the first!</div>';
      return;
    }

    list.innerHTML = rows.map((m,i) => {
      const sc = m.score > 0 ? "pos" : m.score < 0 ? "neg" : "zero";
      const pc = m.side === "YES" ? "yes" : "no";
      return \`
        <div class="msg" style="animation-delay:\${Math.min(i,8)*0.03}s">
          <div class="vcol">
            <div class="vscore \${sc}">\${m.score}</div>
            <button class="vbtn up"   data-id="\${m.id}" data-v="1">▲</button>
            <button class="vbtn down" data-id="\${m.id}" data-v="-1">▼</button>
          </div>
          <div>
            <div class="msg-head">
              <span class="pill \${pc}">\${m.side}</span>
              <span class="msg-author">\${esc(m.username)}</span>
              <span class="msg-time">\${ago(m.created_at)}</span>
            </div>
            <div class="msg-body">\${esc(m.text)}</div>
          </div>
        </div>\`;
    }).join("");

    list.querySelectorAll(".vbtn").forEach(btn => {
      btn.addEventListener("click", async () => {
        const id = btn.getAttribute("data-id");
        const v  = parseInt(btn.getAttribute("data-v"), 10);
        const resp = await api(\`/messages/\${id}/vote\`, {
          method:"POST", body: JSON.stringify({value:v})
        });
        if (resp.error) return alert(resp.error);
        await Promise.all([loadMe(), loadLeaderboard(), loadMessages()]);
      });
    });
  }

  async function loadMessages() {
    const rows = await api(\`/debate/\${DEBATE_ID}/messages?sort=\${sort}\`).catch(() => []);
    renderMessages(Array.isArray(rows) ? rows : []);
  }

  // ── Auto-refresh every 30 seconds
  function startAutoRefresh() {
    clearInterval(refreshTimer);
    let secs = 30;
    document.getElementById("refreshHint").textContent = "Auto-refresh in " + secs + "s";
    refreshTimer = setInterval(() => {
      secs--;
      if (secs <= 0) {
        secs = 30;
        loadMessages();
      }
      document.getElementById("refreshHint").textContent = "Auto-refresh in " + secs + "s";
    }, 1000);
  }

  // ── Init
  Promise.all([loadMe(), loadLeaderboard(), loadMessages()]);
  startAutoRefresh();
</script>
</body>
</html>`;
}

// ─────────────────────────────────────────────────────────
// Start
// ─────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () =>
  console.log(`✅ Server running on port ${PORT}`)
);