require("dotenv").config();
const express    = require("express");
const cookieParser = require("cookie-parser");
const rateLimit  = require("express-rate-limit");
const { Pool }   = require("pg");

// ─────────────────────────────────────────────────────────
// App bootstrap
// ─────────────────────────────────────────────────────────
const app = express();
app.set("trust proxy", 1); // needed for rate-limit behind Render's proxy
app.use(express.json());
app.use(cookieParser());

// ─────────────────────────────────────────────────────────
// Database
// ─────────────────────────────────────────────────────────
if (!process.env.DATABASE_URL) {
  console.error("❌  DATABASE_URL is not set. Add it to your Render env vars.");
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

pool.on("error", (err) => console.error("🔴 Unexpected DB error:", err.message));

// ─────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────

/** Wrap async route — forwards errors to Express error handler */
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

/** Escape HTML for server-rendered strings */
function esc(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

/** Resolve current user from cookie (one DB call) */
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
const loginLimiter = rateLimit({
  windowMs: 60_000, max: 20,
  standardHeaders: true, legacyHeaders: false,
  message: { error: "Too many login attempts — try again in a minute" },
});
const messageLimiter = rateLimit({
  windowMs: 60_000, max: 10,
  standardHeaders: true, legacyHeaders: false,
  message: { error: "Posting too fast — max 10 arguments per minute" },
});
const voteLimiter = rateLimit({
  windowMs: 60_000, max: 60,
  standardHeaders: true, legacyHeaders: false,
  message: { error: "Voting too fast — slow down" },
});

// ─────────────────────────────────────────────────────────
// Auth routes
// ─────────────────────────────────────────────────────────
app.post("/auth/login", loginLimiter, asyncHandler(async (req, res) => {
  const raw      = (req.body?.username || "").trim();
  const username = raw.replace(/\s+/g, "_");

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
    "SELECT id, username, rating FROM users WHERE username = $1",
    [username]
  );
  res.json({ success: true, user: r.rows[0] });
}));

app.post("/auth/logout", (req, res) => {
  res.clearCookie("username");
  res.json({ success: true });
});

app.get("/me", asyncHandler(async (req, res) => {
  res.json({ user: await getMe(req) });
}));

// ─────────────────────────────────────────────────────────
// Leaderboard
// ─────────────────────────────────────────────────────────
app.get("/leaderboard/users", asyncHandler(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || "10", 10), 100);
  const r = await pool.query(
    "SELECT username, rating FROM users ORDER BY rating DESC, id ASC LIMIT $1",
    [limit]
  );
  res.json(r.rows);
}));

// ─────────────────────────────────────────────────────────
// Messages
// ─────────────────────────────────────────────────────────
app.get("/",          (req, res) => res.redirect("/debate/1"));
app.get("/debate",    (req, res) => res.redirect("/debate/1"));

app.get("/debate/:id/messages", asyncHandler(async (req, res) => {
  const debateId = parseInt(req.params.id, 10);
  if (!Number.isFinite(debateId))
    return res.status(400).json({ error: "Bad debate id" });

  const exists = await pool.query("SELECT 1 FROM debates WHERE id = $1", [debateId]);
  if (!exists.rows[0]) return res.status(404).json({ error: "Debate not found" });

  const sort    = req.query.sort === "top" ? "top" : "new";
  const orderBy = sort === "top"
    ? "m.score DESC, m.created_at DESC"
    : "m.created_at DESC";
  const limit   = Math.min(parseInt(req.query.limit || "50", 10), 200);

  const r = await pool.query(
    `SELECT m.id, m.side, m.text, m.score, m.created_at, u.username
     FROM   messages m
     JOIN   users u ON u.id = m.user_id
     WHERE  m.debate_id = $1
     ORDER  BY ${orderBy}
     LIMIT  $2`,
    [debateId, limit]
  );
  res.json(r.rows);
}));

app.post("/debate/:id/messages", messageLimiter, asyncHandler(async (req, res) => {
  const me = await getMe(req);
  if (!me) return res.status(401).json({ error: "Login first" });

  const debateId = parseInt(req.params.id, 10);
  if (!Number.isFinite(debateId))
    return res.status(400).json({ error: "Bad debate id" });

  const exists = await pool.query("SELECT 1 FROM debates WHERE id = $1", [debateId]);
  if (!exists.rows[0]) return res.status(404).json({ error: "Debate not found" });

  const text = String(req.body?.text || "").trim();
  const side = String(req.body?.side || "").toUpperCase();

  if (!text)          return res.status(400).json({ error: "Text is required" });
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
// Voting  (transactional — uses explicit client)
// ─────────────────────────────────────────────────────────
app.post("/messages/:id/vote", voteLimiter, asyncHandler(async (req, res) => {
  const me = await getMe(req);
  if (!me) return res.status(401).json({ error: "Login first" });

  const messageId = parseInt(req.params.id, 10);
  if (!Number.isFinite(messageId))
    return res.status(400).json({ error: "Bad message id" });

  const value = parseInt(req.body?.value, 10);
  if (value !== 1 && value !== -1)
    return res.status(400).json({ error: "Value must be 1 or -1" });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Vote weight: 1–5 based on voter's rating
    const voterR  = await client.query("SELECT rating FROM users WHERE id = $1", [me.id]);
    const weight  = Math.min(5, 1 + Math.floor((voterR.rows[0]?.rating ?? 0) / 50));

    // Lock the message row
    const msgR = await client.query(
      "SELECT id, user_id FROM messages WHERE id = $1 FOR UPDATE",
      [messageId]
    );
    const msg = msgR.rows[0];
    if (!msg) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Message not found" });
    }
    if (msg.user_id === me.id) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Cannot vote your own message" });
    }

    const existR   = await client.query(
      "SELECT id, value, weight FROM votes WHERE message_id = $1 AND user_id = $2",
      [messageId, me.id]
    );
    const existing = existR.rows[0];
    let deltaVote  = 0;

    if (!existing) {
      // New vote
      await client.query(
        "INSERT INTO votes (message_id, user_id, value, weight) VALUES ($1,$2,$3,$4)",
        [messageId, me.id, value, weight]
      );
      deltaVote = value * weight;
    } else if (existing.value === value) {
      // Toggle off
      await client.query("DELETE FROM votes WHERE id = $1", [existing.id]);
      deltaVote = -(existing.value * existing.weight);
    } else {
      // Flip direction
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
// HTML page
// ─────────────────────────────────────────────────────────
app.get("/debate/:id", asyncHandler(async (req, res) => {
  const debateId = parseInt(req.params.id, 10);
  const r = await pool.query("SELECT id, question FROM debates WHERE id = $1", [debateId]);
  const debate = r.rows[0];
  if (!debate) return res.status(404).type("text").send("Debate not found");
  res.type("html").send(buildPage(debateId, debate.question));
}));

// ─────────────────────────────────────────────────────────
// Global error handler
// ─────────────────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  console.error("🔴", err.message);
  res.status(500).json({ error: "Internal server error" });
});

// ─────────────────────────────────────────────────────────
// Page builder
// ─────────────────────────────────────────────────────────
function buildPage(debateId, question) {
  return /* html */`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>${esc(question)} — Debate</title>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link href="https://fonts.googleapis.com/css2?family=Unbounded:wght@400;600;700;900&family=Manrope:wght@300;400;500;600&display=swap" rel="stylesheet"/>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg:       #0b0c10;
      --bg2:      #111318;
      --bg3:      #181b22;
      --border:   rgba(255,255,255,0.06);
      --border2:  rgba(255,255,255,0.12);
      --yes:      #3b82f6;
      --yes-glow: rgba(59,130,246,0.18);
      --no:       #ef4444;
      --no-glow:  rgba(239,68,68,0.18);
      --accent:   #3b82f6;
      --gold:     #f59e0b;
      --text:     #eaedf3;
      --muted:    #5a5f70;
      --muted2:   #8891a4;
      --r:        14px;
    }

    html { scroll-behavior: smooth; }

    body {
      font-family: 'Manrope', sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      overflow-x: hidden;
    }

    /* ── Ambient background glow ── */
    body::before {
      content: '';
      position: fixed; top: -300px; left: 50%;
      transform: translateX(-50%);
      width: 900px; height: 600px;
      background: radial-gradient(ellipse, rgba(59,130,246,0.07) 0%, transparent 65%);
      pointer-events: none; z-index: 0;
    }

    /* ── Nav ── */
    nav {
      position: sticky; top: 0; z-index: 100;
      border-bottom: 1px solid var(--border);
      background: rgba(11,12,16,0.85);
      backdrop-filter: blur(16px);
    }
    .nav-inner {
      max-width: 1100px; margin: 0 auto;
      display: flex; align-items: center; justify-content: space-between;
      padding: 0 24px; height: 58px;
    }
    .logo {
      font-family: 'Unbounded', sans-serif;
      font-weight: 900; font-size: 16px; letter-spacing: .04em;
      color: var(--text);
    }
    .logo span { color: var(--accent); }
    .nav-right { display: flex; align-items: center; gap: 12px; }
    .nav-user {
      font-size: 13px; color: var(--muted2);
      display: flex; align-items: center; gap: 8px;
    }
    .nav-user strong { color: var(--text); font-weight: 600; }

    /* ── Hero ── */
    .hero {
      position: relative; z-index: 1;
      max-width: 1100px; margin: 0 auto;
      padding: 56px 24px 40px;
    }
    .hero-eyebrow {
      display: inline-flex; align-items: center; gap: 6px;
      font-size: 11px; font-weight: 600; letter-spacing: .14em;
      text-transform: uppercase; color: var(--accent);
      border: 1px solid rgba(59,130,246,0.3);
      background: rgba(59,130,246,0.07);
      padding: 5px 12px; border-radius: 999px;
      margin-bottom: 20px;
    }
    .live-dot {
      width: 6px; height: 6px; border-radius: 50%;
      background: var(--accent);
      animation: blink 1.4s ease-in-out infinite;
    }
    @keyframes blink { 0%,100%{opacity:1} 50%{opacity:.2} }

    .hero-question {
      font-family: 'Unbounded', sans-serif;
      font-size: clamp(24px, 4vw, 44px);
      font-weight: 700; line-height: 1.15;
      letter-spacing: -0.02em;
      max-width: 820px;
    }
    .hero-meta {
      margin-top: 18px; font-size: 14px; color: var(--muted2);
      display: flex; gap: 20px; flex-wrap: wrap; align-items: center;
    }
    .hero-meta span { display: flex; align-items: center; gap: 5px; }

    /* ── Main grid ── */
    .main {
      position: relative; z-index: 1;
      max-width: 1100px; margin: 0 auto;
      padding: 0 24px 80px;
      display: grid;
      grid-template-columns: 1fr 290px;
      gap: 28px;
      align-items: start;
    }
    @media (max-width: 840px) {
      .main { grid-template-columns: 1fr; }
    }

    /* ── Cards / panels ── */
    .card {
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: var(--r);
      padding: 20px;
    }
    .card + .card { margin-top: 16px; }
    .card-label {
      font-size: 10px; font-weight: 700; letter-spacing: .12em;
      text-transform: uppercase; color: var(--muted);
      margin-bottom: 14px;
    }

    /* ── Compose ── */
    .side-row { display: flex; gap: 8px; margin-bottom: 14px; }
    .side-btn {
      flex: 1; padding: 10px; border-radius: 10px;
      border: 1px solid var(--border);
      background: var(--bg3); color: var(--muted2);
      font-family: 'Unbounded', sans-serif;
      font-size: 11px; font-weight: 700; letter-spacing: .06em;
      cursor: pointer; transition: all .18s ease;
    }
    .side-btn:hover { border-color: var(--border2); color: var(--text); }
    .side-btn.yes-on {
      background: var(--yes-glow); border-color: var(--yes);
      color: var(--yes);
    }
    .side-btn.no-on {
      background: var(--no-glow); border-color: var(--no);
      color: var(--no);
    }

    textarea {
      width: 100%; min-height: 88px; resize: vertical;
      padding: 13px 14px; border-radius: 10px;
      border: 1px solid var(--border);
      background: var(--bg3); color: var(--text);
      font-family: 'Manrope', sans-serif; font-size: 14px; line-height: 1.55;
      outline: none; transition: border-color .18s;
    }
    textarea:focus { border-color: rgba(59,130,246,0.5); }
    textarea::placeholder { color: var(--muted); }

    .char-row {
      display: flex; align-items: center; justify-content: space-between;
      margin-top: 6px;
    }
    .char-hint { font-size: 11px; color: var(--muted); }
    .char-hint.warn { color: var(--no); }

    .post-btn {
      margin-top: 12px; width: 100%; padding: 13px;
      border-radius: 10px; border: none;
      background: var(--accent); color: #fff;
      font-family: 'Unbounded', sans-serif; font-weight: 700; font-size: 12px;
      letter-spacing: .04em; cursor: pointer;
      transition: opacity .18s, transform .12s;
    }
    .post-btn:hover { opacity: .88; transform: translateY(-1px); }
    .post-btn:active { transform: none; }

    /* ── Auth ── */
    .me-info { font-size: 13px; color: var(--muted2); margin-bottom: 14px; line-height: 1.6; }
    .me-info strong { color: var(--text); font-weight: 600; }
    .rating-badge {
      display: inline-flex; align-items: center; gap: 4px;
      font-size: 11px; color: var(--gold); font-weight: 600;
    }
    .auth-input {
      width: 100%; padding: 11px 13px;
      border-radius: 10px; border: 1px solid var(--border);
      background: var(--bg3); color: var(--text);
      font-family: 'Manrope', sans-serif; font-size: 13px;
      outline: none; transition: border-color .18s;
    }
    .auth-input:focus { border-color: rgba(59,130,246,0.5); }
    .auth-input::placeholder { color: var(--muted); }
    .auth-btn {
      margin-top: 10px; width: 100%; padding: 11px;
      border-radius: 10px; cursor: pointer; font-size: 13px; font-weight: 600;
      transition: all .18s;
    }
    .join-btn {
      border: 1px solid var(--accent); background: var(--yes-glow);
      color: var(--accent);
    }
    .join-btn:hover { background: rgba(59,130,246,0.25); }
    .leave-btn {
      border: 1px solid var(--border); background: var(--bg3);
      color: var(--muted2);
    }
    .leave-btn:hover { border-color: var(--border2); color: var(--text); }

    /* ── Leaderboard ── */
    .lb-item {
      display: flex; align-items: center; gap: 10px;
      padding: 8px 0; border-bottom: 1px solid var(--border);
      font-size: 13px;
    }
    .lb-item:last-child { border-bottom: none; padding-bottom: 0; }
    .lb-num {
      font-family: 'Unbounded', sans-serif;
      font-size: 10px; font-weight: 700;
      color: var(--muted); width: 18px; text-align: center;
      flex-shrink: 0;
    }
    .lb-num.top { color: var(--gold); }
    .lb-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .lb-pts { font-size: 11px; color: var(--muted2); font-weight: 500; flex-shrink: 0; }

    /* ── Sort bar ── */
    .sort-bar {
      display: flex; align-items: center; gap: 6px;
      margin-bottom: 20px;
    }
    .sort-lbl { font-size: 12px; color: var(--muted); margin-right: 4px; }
    .sort-btn {
      padding: 6px 14px; border-radius: 8px;
      border: 1px solid var(--border); background: transparent;
      color: var(--muted); font-size: 12px; font-weight: 600;
      cursor: pointer; transition: all .15s;
    }
    .sort-btn.on {
      background: var(--bg3); color: var(--text);
      border-color: var(--border2);
    }

    /* ── Arguments section title ── */
    .section-hdr {
      font-family: 'Unbounded', sans-serif;
      font-size: 14px; font-weight: 700; letter-spacing: .02em;
      margin-bottom: 16px; color: var(--text);
    }

    /* ── Message card ── */
    .msg {
      display: grid; grid-template-columns: 60px 1fr;
      gap: 14px;
      background: var(--bg2); border: 1px solid var(--border);
      border-radius: var(--r); padding: 16px;
      margin-bottom: 10px;
      animation: slideUp .22s ease both;
      transition: border-color .18s;
    }
    .msg:hover { border-color: var(--border2); }
    @keyframes slideUp {
      from { opacity: 0; transform: translateY(10px); }
      to   { opacity: 1; transform: translateY(0); }
    }

    .vote-col { display: flex; flex-direction: column; align-items: center; gap: 5px; }
    .score {
      font-family: 'Unbounded', sans-serif; font-weight: 700;
      font-size: 18px; line-height: 1;
    }
    .score.pos { color: var(--yes); }
    .score.neg { color: var(--no); }
    .score.zero { color: var(--muted); }

    .vbtn {
      width: 34px; height: 30px; border-radius: 8px;
      border: 1px solid var(--border); background: var(--bg3);
      color: var(--muted); font-size: 12px; cursor: pointer;
      display: flex; align-items: center; justify-content: center;
      transition: all .15s;
    }
    .vbtn:hover { border-color: var(--border2); color: var(--text); }
    .vbtn.up:hover   { background: var(--yes-glow); border-color: var(--yes); color: var(--yes); }
    .vbtn.down:hover { background: var(--no-glow);  border-color: var(--no);  color: var(--no);  }

    .msg-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 9px; }
    .side-pill {
      display: inline-flex; align-items: center;
      padding: 3px 9px; border-radius: 999px;
      font-size: 10px; font-weight: 700; letter-spacing: .08em;
    }
    .pill-yes { background: var(--yes-glow); color: var(--yes); border: 1px solid rgba(59,130,246,.3); }
    .pill-no  { background: var(--no-glow);  color: var(--no);  border: 1px solid rgba(239,68,68,.3);  }
    .msg-author { font-size: 13px; font-weight: 600; }
    .msg-time { margin-left: auto; font-size: 11px; color: var(--muted); }
    .msg-body { font-size: 14px; color: rgba(234,237,243,0.8); line-height: 1.6; }

    /* ── Empty state ── */
    .empty {
      text-align: center; padding: 52px 20px;
      color: var(--muted); font-size: 14px;
    }
    .empty-icon { font-size: 32px; margin-bottom: 12px; }

    a { color: inherit; text-decoration: none; }
  </style>
</head>
<body>

<!-- NAV -->
<nav>
  <div class="nav-inner">
    <div class="logo">ARGU<span>.</span></div>
    <div class="nav-right">
      <div class="nav-user" id="navUser"></div>
    </div>
  </div>
</nav>

<!-- HERO -->
<div class="hero">
  <div class="hero-eyebrow">
    <span class="live-dot"></span>
    LIVE DEBATE
  </div>
  <h1 class="hero-question">${esc(question)}</h1>
  <div class="hero-meta">
    <span id="heroStats">loading…</span>
  </div>
</div>

<!-- MAIN GRID -->
<div class="main">

  <!-- LEFT: compose + feed -->
  <div>

    <!-- Compose -->
    <div class="card" style="margin-bottom:24px;">
      <div class="card-label">Your argument</div>
      <div class="side-row">
        <button class="side-btn yes-on" id="yesBtn">✓ YES</button>
        <button class="side-btn" id="noBtn">✗ NO</button>
      </div>
      <textarea id="text" placeholder="State your case clearly and concisely… (max 300 chars)" maxlength="300"></textarea>
      <div class="char-row">
        <span class="char-hint" id="charHint">0 / 300</span>
      </div>
      <button class="post-btn" id="sendBtn">POST ARGUMENT</button>
    </div>

    <!-- Sort + list -->
    <div class="section-hdr">Arguments</div>
    <div class="sort-bar">
      <span class="sort-lbl">Sort by</span>
      <button class="sort-btn on" id="sortNew">Newest</button>
      <button class="sort-btn"   id="sortTop">Top rated</button>
    </div>
    <div id="list"><div class="empty"><div class="empty-icon">💬</div>Loading arguments…</div></div>

  </div>

  <!-- RIGHT: sidebar -->
  <div>

    <!-- Account -->
    <div class="card">
      <div class="card-label">Account</div>
      <div class="me-info" id="meBox">Loading…</div>
      <div id="loginBox" style="display:none">
        <input class="auth-input" id="username" placeholder="Pick a username…" maxlength="20"/>
        <button class="auth-btn join-btn" id="loginBtn">Join debate</button>
      </div>
      <div id="logoutBox" style="display:none">
        <button class="auth-btn leave-btn" id="logoutBtn">Sign out</button>
      </div>
    </div>

    <!-- Leaderboard -->
    <div class="card">
      <div class="card-label">Top Debaters</div>
      <div id="lb"><div style="color:var(--muted);font-size:13px">Loading…</div></div>
    </div>

  </div>
</div>

<script>
  const DEBATE_ID = ${debateId};
  let side = "YES";
  let sort = "new";

  // ── Side toggle
  const yesBtn = document.getElementById("yesBtn");
  const noBtn  = document.getElementById("noBtn");

  function setSide(s) {
    side = s;
    yesBtn.className = "side-btn" + (s === "YES" ? " yes-on" : "");
    noBtn.className  = "side-btn" + (s === "NO"  ? " no-on"  : "");
  }
  yesBtn.addEventListener("click", () => setSide("YES"));
  noBtn.addEventListener("click",  () => setSide("NO"));
  setSide("YES");

  // ── Sort toggle
  const sortNewBtn = document.getElementById("sortNew");
  const sortTopBtn = document.getElementById("sortTop");

  function setSort(s) {
    sort = s;
    sortNewBtn.classList.toggle("on", s === "new");
    sortTopBtn.classList.toggle("on", s === "top");
    loadMessages();
  }
  sortNewBtn.addEventListener("click", () => setSort("new"));
  sortTopBtn.addEventListener("click", () => setSort("top"));

  // ── Char counter
  const textEl   = document.getElementById("text");
  const charHint = document.getElementById("charHint");
  textEl.addEventListener("input", () => {
    const n = textEl.value.length;
    charHint.textContent = n + " / 300";
    charHint.className = "char-hint" + (n > 260 ? " warn" : "");
  });

  // ── Escape helper
  function esc(s) {
    return String(s)
      .replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");
  }

  // ── Relative time
  function timeAgo(ts) {
    const d = Math.floor((Date.now() - new Date(ts)) / 1000);
    if (d < 60)   return d + "s ago";
    if (d < 3600) return Math.floor(d / 60) + "m ago";
    if (d < 86400)return Math.floor(d / 3600) + "h ago";
    return Math.floor(d / 86400) + "d ago";
  }

  // ── Fetch helper
  async function api(url, opts = {}) {
    const r = await fetch(url, {
      headers: { "content-type": "application/json" },
      ...opts
    });
    return r.json();
  }

  // ── Leaderboard
  async function loadLeaderboard() {
    const rows = await api("/leaderboard/users?limit=7").catch(() => []);
    const el = document.getElementById("lb");
    if (!rows.length) { el.innerHTML = '<div style="color:var(--muted);font-size:13px">No users yet</div>'; return; }
    el.innerHTML = rows.map((u, i) => \`
      <div class="lb-item">
        <span class="lb-num \${i === 0 ? 'top' : ''}">#\${i+1}</span>
        <span class="lb-name">\${esc(u.username)}</span>
        <span class="lb-pts">\${u.rating} pts</span>
      </div>
    \`).join("");
  }

  // ── Me / hero stats
  async function loadMe() {
    const data = await api("/me").catch(() => ({ user: null }));
    const me   = data.user;
    const meBox    = document.getElementById("meBox");
    const loginBox = document.getElementById("loginBox");
    const logoutBox= document.getElementById("logoutBox");
    const navUser  = document.getElementById("navUser");

    if (!me) {
      meBox.innerHTML    = 'Not signed in — join to post and vote.';
      loginBox.style.display  = "block";
      logoutBox.style.display = "none";
      navUser.innerHTML  = '';
    } else {
      meBox.innerHTML    = \`Signed in as <strong>\${esc(me.username)}</strong><br><span class="rating-badge">★ \${me.rating} rating pts</span>\`;
      loginBox.style.display  = "none";
      logoutBox.style.display = "block";
      navUser.innerHTML  = \`<strong>\${esc(me.username)}</strong> <span style="color:var(--gold)">★\${me.rating}</span>\`;
    }
  }

  // ── Auth events
  document.getElementById("loginBtn").addEventListener("click", async () => {
    const username = document.getElementById("username").value.trim();
    if (!username) return;
    const resp = await api("/auth/login", { method: "POST", body: JSON.stringify({ username }) });
    if (resp.error) return alert(resp.error);
    await Promise.all([loadMe(), loadLeaderboard()]);
  });

  document.getElementById("logoutBtn").addEventListener("click", async () => {
    await api("/auth/logout", { method: "POST" });
    await Promise.all([loadMe(), loadLeaderboard()]);
  });

  // ── Post argument
  document.getElementById("sendBtn").addEventListener("click", async () => {
    const text = textEl.value.trim();
    if (!text) return;
    const resp = await api(\`/debate/\${DEBATE_ID}/messages\`, {
      method: "POST",
      body: JSON.stringify({ text, side })
    });
    if (resp.error) return alert(resp.error);
    textEl.value = "";
    charHint.textContent = "0 / 300";
    charHint.className = "char-hint";
    await loadMessages();
  });

  // ── Render messages
  function renderMessages(rows) {
    const list = document.getElementById("list");

    // Update hero stats
    const yes = rows.filter(m => m.side === "YES").length;
    const no  = rows.filter(m => m.side === "NO").length;
    document.getElementById("heroStats").innerHTML =
      \`<span style="color:var(--yes)">YES \${yes}</span>
       <span style="color:var(--muted);margin:0 6px">vs</span>
       <span style="color:var(--no)">NO \${no}</span>
       &nbsp;· \${rows.length} arguments\`;

    if (!rows.length) {
      list.innerHTML = \`<div class="empty"><div class="empty-icon">🗣️</div>No arguments yet — be the first to make your case!</div>\`;
      return;
    }

    list.innerHTML = rows.map((m, i) => {
      const scoreClass = m.score > 0 ? "pos" : m.score < 0 ? "neg" : "zero";
      const pillClass  = m.side === "YES" ? "pill-yes" : "pill-no";
      return \`
        <div class="msg" style="animation-delay:\${Math.min(i,8) * 0.035}s">
          <div class="vote-col">
            <div class="score \${scoreClass}">\${m.score}</div>
            <button class="vbtn up"   data-id="\${m.id}" data-v="1">▲</button>
            <button class="vbtn down" data-id="\${m.id}" data-v="-1">▼</button>
          </div>
          <div>
            <div class="msg-head">
              <span class="side-pill \${pillClass}">\${m.side}</span>
              <span class="msg-author">\${esc(m.username)}</span>
              <span class="msg-time">\${timeAgo(m.created_at)}</span>
            </div>
            <div class="msg-body">\${esc(m.text)}</div>
          </div>
        </div>
      \`;
    }).join("");

    list.querySelectorAll(".vbtn").forEach(btn => {
      btn.addEventListener("click", async () => {
        const id = btn.getAttribute("data-id");
        const v  = parseInt(btn.getAttribute("data-v"), 10);
        const resp = await api(\`/messages/\${id}/vote\`, {
          method: "POST", body: JSON.stringify({ value: v })
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

  // ── Init
  Promise.all([loadMe(), loadLeaderboard(), loadMessages()]);
</script>
</body>
</html>`;
}

// ─────────────────────────────────────────────────────────
// Start server
// ─────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () =>
  console.log(`✅ Server running on port ${PORT}`)
);