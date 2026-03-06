require("dotenv").config();
const express      = require("express");
const cookieParser = require("cookie-parser");
const rateLimit    = require("express-rate-limit");
const crypto       = require("crypto");
const { Pool }     = require("pg");

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

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("render.com")
    ? { rejectUnauthorized: false }
    : undefined,
  max: 20,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
});
pool.on("error", (err) => console.error("🔴 DB error:", err.message));

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

// Assign or read anonymous visitor ID cookie
function getVisitorId(req, res) {
  let vid = req.cookies?.visitor_id;
  if (!vid) {
    vid = crypto.randomBytes(12).toString("hex");
    res.cookie("visitor_id", vid, {
      httpOnly: true,
      sameSite: "lax",
      maxAge: 365 * 24 * 60 * 60 * 1000,
    });
  }
  return vid;
}

// Track page view (fire-and-forget)
function trackView(req, res, path) {
  const vid = getVisitorId(req, res);
  pool.query(
    "INSERT INTO page_views (path, visitor_id) VALUES ($1, $2)",
    [path, vid]
  ).catch(() => {});
}

// Admin auth middleware
function requireAdmin(req, res, next) {
  if (req.cookies?.admin_session === ADMIN_PASSWORD) return next();
  return res.status(401).type("html").send(adminLoginPage(""));
}

// ─────────────────────────────────────────────────────────
// Rate limiters
// ─────────────────────────────────────────────────────────
const loginLimiter    = rateLimit({ windowMs: 60_000, max: 20, message: { error: "Too many login attempts" } });
const messageLimiter  = rateLimit({ windowMs: 60_000, max: 10, message: { error: "Posting too fast — max 10/min" } });
const voteLimiter     = rateLimit({ windowMs: 60_000, max: 60, message: { error: "Voting too fast" } });
const reactionLimiter = rateLimit({ windowMs: 60_000, max: 60, message: { error: "Too many reactions" } });

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
// API: debates
// ─────────────────────────────────────────────────────────
app.get("/api/debates", wrap(async (req, res) => {
  const r = await pool.query(`
    SELECT d.id, d.question, d.category,
           COUNT(m.id)::int                                AS arg_count,
           COUNT(CASE WHEN m.side='YES' THEN 1 END)::int   AS yes_count,
           COUNT(CASE WHEN m.side='NO'  THEN 1 END)::int   AS no_count
    FROM   debates d
    LEFT   JOIN messages m ON m.debate_id = d.id
    WHERE  d.active = TRUE
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
    SELECT m.id, m.side, m.text, m.score, m.created_at, u.username,
           COALESCE(SUM(CASE WHEN r.emoji='fire' THEN 1 END),0)::int AS fire_count,
           COALESCE(SUM(CASE WHEN r.emoji='think' THEN 1 END),0)::int AS think_count,
           COALESCE(SUM(CASE WHEN r.emoji='idea' THEN 1 END),0)::int  AS idea_count
    FROM   messages m
    JOIN   users u ON u.id = m.user_id
    LEFT   JOIN reactions r ON r.message_id = m.id
    WHERE  m.debate_id = $1
    GROUP  BY m.id, u.username
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

  const exists = await pool.query("SELECT 1 FROM debates WHERE id = $1 AND active = TRUE", [debateId]);
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

    const voterR = await client.query("SELECT rating FROM users WHERE id = $1", [me.id]);
    const weight = Math.min(5, 1 + Math.floor((voterR.rows[0]?.rating ?? 0) / 50));

    const msgR = await client.query(
      "SELECT id, user_id FROM messages WHERE id = $1 FOR UPDATE",
      [messageId]
    );
    const msg = msgR.rows[0];
    if (!msg)              { await client.query("ROLLBACK"); return res.status(404).json({ error: "Message not found" }); }
    if (msg.user_id===me.id) { await client.query("ROLLBACK"); return res.status(400).json({ error: "Cannot vote your own message" }); }

    const existR   = await client.query(
      "SELECT id, value, weight FROM votes WHERE message_id=$1 AND user_id=$2",
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
      await client.query("UPDATE votes SET value=$1, weight=$2 WHERE id=$3", [value, weight, existing.id]);
      deltaVote = (value * weight) - (existing.value * existing.weight);
    }

    if (deltaVote !== 0) {
      await client.query("UPDATE messages SET score=score+$1 WHERE id=$2", [deltaVote, messageId]);
      await client.query("UPDATE users SET rating=rating+$1 WHERE id=$2", [deltaVote * 3, msg.user_id]);
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
// API: reactions
// ─────────────────────────────────────────────────────────
app.post("/messages/:id/react", reactionLimiter, wrap(async (req, res) => {
  const me = await getMe(req);
  if (!me) return res.status(401).json({ error: "Login first" });

  const messageId = parseInt(req.params.id, 10);
  if (!Number.isFinite(messageId)) return res.status(400).json({ error: "Bad message id" });

  const emoji = req.body?.emoji;
  if (!["fire", "think", "idea"].includes(emoji))
    return res.status(400).json({ error: "Invalid emoji" });

  // Toggle reaction
  const existing = await pool.query(
    "SELECT id FROM reactions WHERE message_id=$1 AND user_id=$2 AND emoji=$3",
    [messageId, me.id, emoji]
  );

  if (existing.rows[0]) {
    await pool.query("DELETE FROM reactions WHERE id=$1", [existing.rows[0].id]);
    res.json({ success: true, action: "removed" });
  } else {
    await pool.query(
      "INSERT INTO reactions (message_id, user_id, emoji) VALUES ($1,$2,$3)",
      [messageId, me.id, emoji]
    );
    res.json({ success: true, action: "added" });
  }
}));

// ─────────────────────────────────────────────────────────
// User profile API
// ─────────────────────────────────────────────────────────
app.get("/api/user/:username", wrap(async (req, res) => {
  const username = req.params.username;
  const userR = await pool.query(
    "SELECT id, username, rating, created_at FROM users WHERE username=$1",
    [username]
  );
  if (!userR.rows[0]) return res.status(404).json({ error: "User not found" });
  const user = userR.rows[0];

  const statsR = await pool.query(`
    SELECT
      COUNT(*)::int                                          AS total_args,
      COUNT(CASE WHEN side='YES' THEN 1 END)::int           AS yes_args,
      COUNT(CASE WHEN side='NO'  THEN 1 END)::int           AS no_args,
      COALESCE(SUM(CASE WHEN score>0 THEN score END),0)::int AS total_upvotes,
      MAX(score)::int                                        AS best_score
    FROM messages WHERE user_id = $1
  `, [user.id]);

  const msgsR = await pool.query(`
    SELECT m.id, m.side, m.text, m.score, m.created_at, d.question
    FROM   messages m
    JOIN   debates d ON d.id = m.debate_id
    WHERE  m.user_id = $1
    ORDER  BY m.score DESC, m.created_at DESC
    LIMIT  10
  `, [user.id]);

  res.json({ user, stats: statsR.rows[0], top_messages: msgsR.rows });
}));

// ─────────────────────────────────────────────────────────
// Admin API
// ─────────────────────────────────────────────────────────
app.post("/admin/login", (req, res) => {
  const password = req.body?.password || "";
  if (password !== ADMIN_PASSWORD)
    return res.status(401).json({ error: "Wrong password" });
  res.cookie("admin_session", ADMIN_PASSWORD, { httpOnly: true, sameSite: "lax" });
  res.json({ success: true });
});

app.post("/admin/logout", (req, res) => {
  res.clearCookie("admin_session");
  res.redirect("/admin");
});

app.post("/admin/debates", requireAdmin, wrap(async (req, res) => {
  const question = (req.body?.question || "").trim();
  const category = (req.body?.category || "General").trim();
  if (!question) return res.status(400).json({ error: "Question required" });
  await pool.query(
    "INSERT INTO debates (question, category) VALUES ($1, $2)",
    [question, category]
  );
  res.json({ success: true });
}));

app.post("/admin/debates/:id/toggle", requireAdmin, wrap(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  await pool.query(
    "UPDATE debates SET active = NOT active WHERE id=$1",
    [id]
  );
  res.json({ success: true });
}));

app.delete("/admin/debates/:id", requireAdmin, wrap(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  await pool.query("DELETE FROM debates WHERE id=$1", [id]);
  res.json({ success: true });
}));

app.delete("/admin/messages/:id", requireAdmin, wrap(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  await pool.query("DELETE FROM messages WHERE id=$1", [id]);
  res.json({ success: true });
}));

app.get("/admin/api/stats", requireAdmin, wrap(async (req, res) => {
  const [debates, users, messages, views, daily, topDebates, recentUsers] = await Promise.all([
    pool.query("SELECT COUNT(*)::int AS count FROM debates WHERE active=TRUE"),
    pool.query("SELECT COUNT(*)::int AS count FROM users"),
    pool.query("SELECT COUNT(*)::int AS count FROM messages"),
    pool.query("SELECT COUNT(*)::int AS total, COUNT(DISTINCT visitor_id)::int AS unique_visitors FROM page_views"),
    pool.query(`
      SELECT DATE(created_at) AS day, COUNT(*)::int AS views, COUNT(DISTINCT visitor_id)::int AS uniq
      FROM page_views
      WHERE created_at > NOW() - INTERVAL '14 days'
      GROUP BY day ORDER BY day DESC
    `),
    pool.query(`
      SELECT d.id, d.question, d.category, d.active,
             COUNT(m.id)::int AS arg_count,
             COALESCE(SUM(pv.cnt),0)::int AS views
      FROM debates d
      LEFT JOIN messages m ON m.debate_id = d.id
      LEFT JOIN (
        SELECT path, COUNT(*)::int AS cnt FROM page_views GROUP BY path
      ) pv ON pv.path = '/debate/' || d.id
      GROUP BY d.id
      ORDER BY d.id ASC
    `),
    pool.query(`
      SELECT username, rating, created_at,
             (SELECT COUNT(*)::int FROM messages WHERE user_id=users.id) AS arg_count
      FROM users ORDER BY created_at DESC LIMIT 20
    `),
  ]);

  res.json({
    debates:      debates.rows[0].count,
    users:        users.rows[0].count,
    messages:     messages.rows[0].count,
    total_views:  views.rows[0].total,
    unique_visitors: views.rows[0].unique_visitors,
    daily,
    top_debates:  topDebates.rows,
    recent_users: recentUsers.rows,
  });
}));

// ─────────────────────────────────────────────────────────
// HTML Pages
// ─────────────────────────────────────────────────────────
app.get("/", wrap(async (req, res) => {
  trackView(req, res, "/");
  res.type("html").send(homePage());
}));

app.get("/debate", (req, res) => res.redirect("/"));

app.get("/debate/:id", wrap(async (req, res) => {
  const debateId = parseInt(req.params.id, 10);
  const r = await pool.query(
    "SELECT id, question, category FROM debates WHERE id=$1 AND active=TRUE",
    [debateId]
  );
  const debate = r.rows[0];
  if (!debate) return res.status(404).type("text").send("Debate not found");
  trackView(req, res, `/debate/${debateId}`);
  res.type("html").send(debatePage(debateId, debate.question, debate.category));
}));

app.get("/u/:username", wrap(async (req, res) => {
  res.type("html").send(profilePage(req.params.username));
}));

app.get("/admin", (req, res) => {
  if (req.cookies?.admin_session !== ADMIN_PASSWORD)
    return res.type("html").send(adminLoginPage(""));
  res.type("html").send(adminPage());
});

// ─────────────────────────────────────────────────────────
// Error handler
// ─────────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error("🔴", err.message);
  res.status(500).json({ error: "Internal server error" });
});

// ─────────────────────────────────────────────────────────
// Shared CSS
// ─────────────────────────────────────────────────────────
const BASE_CSS = `
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link href="https://fonts.googleapis.com/css2?family=Unbounded:wght@400;600;700;900&family=Manrope:wght@300;400;500;600&display=swap" rel="stylesheet"/>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg:      #0b0c10; --bg2: #111318; --bg3: #181b22;
      --border:  rgba(255,255,255,0.06); --border2: rgba(255,255,255,0.13);
      --yes: #3b82f6; --yes-dim: rgba(59,130,246,0.13);
      --no:  #ef4444; --no-dim:  rgba(239,68,68,0.13);
      --accent: #3b82f6; --gold: #f59e0b;
      --text: #eaedf3; --muted: #55596a; --muted2: #8891a4;
      --r: 14px;
    }
    html { scroll-behavior: smooth; }
    body { font-family: 'Manrope', sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; overflow-x: hidden; }
    body::before {
      content: ''; position: fixed; top: -300px; left: 50%; transform: translateX(-50%);
      width: 900px; height: 600px;
      background: radial-gradient(ellipse, rgba(59,130,246,0.055) 0%, transparent 65%);
      pointer-events: none; z-index: 0;
    }
    nav {
      position: sticky; top: 0; z-index: 100;
      border-bottom: 1px solid var(--border);
      background: rgba(11,12,16,0.88); backdrop-filter: blur(18px);
    }
    .nav-inner {
      max-width: 1100px; margin: 0 auto;
      display: flex; align-items: center; justify-content: space-between;
      padding: 0 24px; height: 58px;
    }
    .logo { font-family: 'Unbounded', sans-serif; font-weight: 900; font-size: 16px; letter-spacing: .04em; color: var(--text); text-decoration: none; }
    .logo span { color: var(--accent); }
    .nav-right { display: flex; align-items: center; gap: 12px; font-size: 13px; color: var(--muted2); }
    .nav-right strong { color: var(--text); font-weight: 600; }
    .card { background: var(--bg2); border: 1px solid var(--border); border-radius: var(--r); padding: 20px; }
    .card-label { font-size: 10px; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; color: var(--muted); margin-bottom: 14px; }
    a { color: inherit; text-decoration: none; }
    .btn-primary {
      padding: 11px 22px; border-radius: 12px; border: none;
      background: var(--accent); color: #fff;
      font-family: 'Unbounded', sans-serif; font-weight: 700; font-size: 11px;
      letter-spacing: .04em; cursor: pointer; transition: opacity .18s;
    }
    .btn-primary:hover { opacity: .85; }
  </style>
`;

// ─────────────────────────────────────────────────────────
// HOME PAGE
// ─────────────────────────────────────────────────────────
function homePage() {
  return `<!doctype html><html lang="en">
<head>
  <meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>ARGU — Live Debates</title>
  ${BASE_CSS}
  <style>
    .page { max-width: 1100px; margin: 0 auto; padding: 48px 24px 80px; position: relative; z-index: 1; }
    .hero-home { text-align: center; padding: 16px 0 48px; }
    .hero-home h1 { font-family: 'Unbounded', sans-serif; font-size: clamp(30px,5vw,56px); font-weight: 900; letter-spacing: -0.03em; line-height: 1.08; margin-bottom: 14px; }
    .hero-home h1 span { color: var(--accent); }
    .hero-home p { font-size: 15px; color: var(--muted2); max-width: 420px; margin: 0 auto 28px; }
    .auth-bar { display: flex; align-items: center; justify-content: center; gap: 10px; flex-wrap: wrap; }
    .auth-input { padding: 11px 16px; border-radius: 12px; border: 1px solid var(--border); background: var(--bg2); color: var(--text); font-family: 'Manrope', sans-serif; font-size: 14px; width: 210px; outline: none; transition: border-color .18s; }
    .auth-input:focus { border-color: rgba(59,130,246,0.5); }
    .auth-input::placeholder { color: var(--muted); }
    .btn-out { padding: 10px 18px; border-radius: 12px; border: 1px solid var(--border); background: var(--bg2); color: var(--muted2); font-size: 13px; cursor: pointer; transition: all .15s; }
    .btn-out:hover { border-color: var(--border2); color: var(--text); }
    .filter-row { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 24px; }
    .filter-btn { padding: 7px 16px; border-radius: 999px; font-size: 12px; font-weight: 600; border: 1px solid var(--border); background: transparent; color: var(--muted2); cursor: pointer; transition: all .15s; }
    .filter-btn:hover, .filter-btn.on { background: var(--bg3); border-color: var(--border2); color: var(--text); }
    .debates-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 14px; }
    .debate-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 18px; padding: 22px; display: flex; flex-direction: column; gap: 11px; cursor: pointer; transition: border-color .2s, transform .18s; }
    .debate-card:hover { border-color: var(--border2); transform: translateY(-2px); }
    .cat-tag { font-size: 10px; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; color: var(--accent); background: var(--yes-dim); border: 1px solid rgba(59,130,246,.2); padding: 3px 9px; border-radius: 999px; }
    .arg-count { font-size: 11px; color: var(--muted); }
    .debate-q { font-family: 'Unbounded', sans-serif; font-size: 14px; font-weight: 700; line-height: 1.3; letter-spacing: -0.01em; flex: 1; }
    .vote-bar { height: 4px; background: var(--bg3); border-radius: 999px; overflow: hidden; }
    .bar-yes { height: 100%; background: var(--yes); transition: width .4s ease; float: left; }
    .bar-no  { height: 100%; background: var(--no);  float: right; }
    .vote-nums { display: flex; justify-content: space-between; font-size: 11px; }
    .vote-yes { color: var(--yes); font-weight: 700; }
    .vote-no  { color: var(--no);  font-weight: 700; }
    .open-btn { padding: 9px; border-radius: 10px; text-align: center; background: var(--bg3); border: 1px solid var(--border); font-size: 12px; font-weight: 600; color: var(--muted2); transition: all .15s; }
    .debate-card:hover .open-btn { background: var(--accent); border-color: var(--accent); color: #fff; }
    .stats-bar { display: flex; gap: 24px; justify-content: center; margin-bottom: 36px; flex-wrap: wrap; }
    .stat-item { text-align: center; }
    .stat-num { font-family: 'Unbounded', sans-serif; font-size: 22px; font-weight: 900; color: var(--text); }
    .stat-lbl { font-size: 11px; color: var(--muted); margin-top: 2px; }
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
  <div class="hero-home">
    <h1>Argue.<br>Vote. <span>Win.</span></h1>
    <p>Real debates on topics that matter. Pick a side and make your case.</p>
    <div class="auth-bar" id="authArea">Loading…</div>
  </div>

  <div class="stats-bar" id="statsBar"></div>

  <div class="filter-row" id="filterRow"></div>
  <div class="debates-grid" id="grid">
    <div style="color:var(--muted);font-size:14px;grid-column:1/-1;text-align:center;padding:40px">Loading…</div>
  </div>
</div>
<script>
  let allDebates = [], currentCat = "All";
  function esc(s){return String(s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");}
  async function api(url,opts={}){const r=await fetch(url,{headers:{"content-type":"application/json"},...opts});return r.json();}

  async function loadMe(){
    const {user:me} = await api("/me").catch(()=>({user:null}));
    const navRight = document.getElementById("navRight");
    const authArea = document.getElementById("authArea");
    if(!me){
      navRight.innerHTML='';
      authArea.innerHTML=\`
        <input class="auth-input" id="username" placeholder="Pick a username…" maxlength="20"/>
        <button class="btn-primary" id="loginBtn">JOIN</button>\`;
      document.getElementById("loginBtn").addEventListener("click", async()=>{
        const username=document.getElementById("username").value.trim();
        if(!username)return;
        const r=await api("/auth/login",{method:"POST",body:JSON.stringify({username})});
        if(r.error)return alert(r.error);
        await loadMe();
      });
    } else {
      navRight.innerHTML=\`<strong>\${esc(me.username)}</strong><span style="color:var(--gold)"> ★\${me.rating}</span>\`;
      authArea.innerHTML=\`
        <span style="font-size:14px;color:var(--muted2)">Welcome back, <strong style="color:var(--text)">\${esc(me.username)}</strong></span>
        <a href="/u/\${esc(me.username)}" class="btn-out">My Profile</a>
        <button class="btn-out" id="logoutBtn">Sign out</button>\`;
      document.getElementById("logoutBtn").addEventListener("click",async()=>{
        await api("/auth/logout",{method:"POST"});await loadMe();
      });
    }
  }

  async function loadDebates(){
    allDebates = await api("/api/debates").catch(()=>[]);

    // stats
    const total = allDebates.reduce((s,d)=>s+d.arg_count,0);
    document.getElementById("statsBar").innerHTML=\`
      <div class="stat-item"><div class="stat-num">\${allDebates.length}</div><div class="stat-lbl">DEBATES</div></div>
      <div class="stat-item"><div class="stat-num">\${total}</div><div class="stat-lbl">ARGUMENTS</div></div>
    \`;

    const cats=["All",...new Set(allDebates.map(d=>d.category))];
    document.getElementById("filterRow").innerHTML=cats.map(c=>
      \`<button class="filter-btn \${c===currentCat?'on':''}" data-cat="\${esc(c)}">\${esc(c)}</button>\`
    ).join("");
    document.getElementById("filterRow").querySelectorAll(".filter-btn").forEach(btn=>{
      btn.addEventListener("click",()=>{
        currentCat=btn.getAttribute("data-cat");
        document.querySelectorAll(".filter-btn").forEach(b=>b.classList.toggle("on",b.getAttribute("data-cat")===currentCat));
        renderGrid();
      });
    });
    renderGrid();
  }

  function renderGrid(){
    const list = currentCat==="All" ? allDebates : allDebates.filter(d=>d.category===currentCat);
    const grid = document.getElementById("grid");
    if(!list.length){grid.innerHTML='<div style="color:var(--muted);grid-column:1/-1;text-align:center;padding:40px">No debates</div>';return;}
    grid.innerHTML=list.map(d=>{
      const total=d.yes_count+d.no_count;
      const yp = total>0 ? Math.round(d.yes_count/total*100) : 50;
      return \`<a class="debate-card" href="/debate/\${d.id}">
        <div style="display:flex;align-items:center;justify-content:space-between">
          <span class="cat-tag">\${esc(d.category)}</span>
          <span class="arg-count">\${d.arg_count} args</span>
        </div>
        <div class="debate-q">\${esc(d.question)}</div>
        <div class="vote-bar">
          <div class="bar-yes" style="width:\${yp}%"></div>
          <div class="bar-no"  style="width:\${100-yp}%"></div>
        </div>
        <div class="vote-nums">
          <span class="vote-yes">YES \${yp}%</span>
          <span class="vote-no">\${100-yp}% NO</span>
        </div>
        <div class="open-btn">Open debate →</div>
      </a>\`;
    }).join("");
  }

  loadMe(); loadDebates();
</script>
</body></html>`;
}

// ─────────────────────────────────────────────────────────
// DEBATE PAGE
// ─────────────────────────────────────────────────────────
function debatePage(debateId, question, category) {
  return `<!doctype html><html lang="en">
<head>
  <meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>${esc(question)} — ARGU</title>
  ${BASE_CSS}
  <style>
    .page { max-width: 1100px; margin: 0 auto; padding: 0 24px 80px; position: relative; z-index: 1; }
    .hero { padding: 40px 0 28px; }
    .back-link { font-size: 13px; color: var(--muted2); display: inline-flex; align-items: center; gap: 6px; margin-bottom: 18px; transition: color .15s; }
    .back-link:hover { color: var(--text); }
    .eyebrow { display: inline-flex; align-items: center; gap: 6px; font-size: 10px; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; color: var(--accent); border: 1px solid rgba(59,130,246,0.3); background: rgba(59,130,246,0.07); padding: 4px 12px; border-radius: 999px; margin-bottom: 14px; }
    .live-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--accent); animation: blink 1.4s ease-in-out infinite; }
    @keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}
    .hero-q { font-family: 'Unbounded', sans-serif; font-size: clamp(20px,3.2vw,36px); font-weight: 700; line-height: 1.15; letter-spacing: -0.02em; max-width: 760px; margin-bottom: 20px; }
    .scoreboard { display: flex; gap: 10px; margin-bottom: 8px; }
    .score-side { flex: 1; padding: 14px 18px; border-radius: 14px; border: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
    .score-side.yes { background: var(--yes-dim); border-color: rgba(59,130,246,.25); }
    .score-side.no  { background: var(--no-dim);  border-color: rgba(239,68,68,.25); }
    .score-lbl { font-family: 'Unbounded', sans-serif; font-size: 12px; font-weight: 700; }
    .score-lbl.yes{color:var(--yes);} .score-lbl.no{color:var(--no);}
    .score-big { font-family: 'Unbounded', sans-serif; font-size: 28px; font-weight: 900; line-height: 1; }
    .score-big.yes{color:var(--yes);} .score-big.no{color:var(--no);}
    .score-pct { font-size: 11px; color: var(--muted2); margin-top: 2px; }
    .progress-bar { height: 4px; background: var(--bg3); border-radius: 999px; overflow: hidden; margin-bottom: 28px; }
    .progress-yes { height: 100%; background: var(--yes); transition: width .5s ease; }
    .main { display: grid; grid-template-columns: 1fr 278px; gap: 22px; align-items: start; }
    @media(max-width:820px){.main{grid-template-columns:1fr;}}
    .side-row { display: flex; gap: 8px; margin-bottom: 12px; }
    .side-btn { flex: 1; padding: 10px; border-radius: 10px; border: 1px solid var(--border); background: var(--bg3); color: var(--muted2); font-family: 'Unbounded', sans-serif; font-size: 11px; font-weight: 700; letter-spacing: .06em; cursor: pointer; transition: all .18s; }
    .side-btn:hover{color:var(--text);border-color:var(--border2);}
    .side-btn.yes-on{background:var(--yes-dim);border-color:var(--yes);color:var(--yes);}
    .side-btn.no-on{background:var(--no-dim);border-color:var(--no);color:var(--no);}
    textarea { width: 100%; min-height: 84px; resize: vertical; padding: 13px 14px; border-radius: 10px; border: 1px solid var(--border); background: var(--bg3); color: var(--text); font-family: 'Manrope', sans-serif; font-size: 14px; line-height: 1.55; outline: none; transition: border-color .18s; }
    textarea:focus{border-color:rgba(59,130,246,.5);}
    textarea::placeholder{color:var(--muted);}
    .char-hint{font-size:11px;color:var(--muted);text-align:right;margin-top:4px;}
    .char-hint.warn{color:var(--no);}
    .post-btn { margin-top: 11px; width: 100%; padding: 12px; border-radius: 10px; border: none; background: var(--accent); color: #fff; font-family: 'Unbounded', sans-serif; font-weight: 700; font-size: 11px; letter-spacing: .04em; cursor: pointer; transition: opacity .18s, transform .12s; }
    .post-btn:hover{opacity:.88;transform:translateY(-1px);}
    .me-info{font-size:13px;color:var(--muted2);margin-bottom:12px;line-height:1.7;}
    .me-info strong{color:var(--text);}
    .auth-input { width: 100%; padding: 11px 13px; border-radius: 10px; border: 1px solid var(--border); background: var(--bg3); color: var(--text); font-family: 'Manrope', sans-serif; font-size: 13px; outline: none; transition: border-color .18s; }
    .auth-input:focus{border-color:rgba(59,130,246,.5);}
    .auth-input::placeholder{color:var(--muted);}
    .join-btn { margin-top: 10px; width: 100%; padding: 11px; border-radius: 10px; border: 1px solid var(--accent); background: var(--yes-dim); color: var(--accent); font-size: 13px; font-weight: 600; cursor: pointer; transition: background .18s; }
    .join-btn:hover{background:rgba(59,130,246,.22);}
    .leave-btn { margin-top: 10px; width: 100%; padding: 11px; border-radius: 10px; border: 1px solid var(--border); background: var(--bg3); color: var(--muted2); font-size: 13px; cursor: pointer; transition: all .15s; }
    .leave-btn:hover{border-color:var(--border2);color:var(--text);}
    .lb-item{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);font-size:13px;}
    .lb-item:last-child{border-bottom:none;}
    .lb-num{font-family:'Unbounded',sans-serif;font-size:10px;font-weight:700;color:var(--muted);width:18px;text-align:center;}
    .lb-num.top{color:var(--gold);}
    .lb-name{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
    .lb-pts{font-size:11px;color:var(--muted2);}
    .sort-bar{display:flex;align-items:center;gap:6px;margin-bottom:16px;}
    .sort-lbl{font-size:12px;color:var(--muted);margin-right:4px;}
    .sort-btn{padding:6px 14px;border-radius:8px;border:1px solid var(--border);background:transparent;color:var(--muted);font-size:12px;font-weight:600;cursor:pointer;transition:all .15s;}
    .sort-btn.on{background:var(--bg3);color:var(--text);border-color:var(--border2);}
    .sec-hdr{font-family:'Unbounded',sans-serif;font-size:13px;font-weight:700;letter-spacing:.02em;margin-bottom:14px;}
    .msg { display: grid; grid-template-columns: 54px 1fr; gap: 13px; background: var(--bg2); border: 1px solid var(--border); border-radius: var(--r); padding: 15px; margin-bottom: 9px; animation: slideUp .2s ease both; transition: border-color .18s; }
    .msg:hover{border-color:var(--border2);}
    @keyframes slideUp{from{opacity:0;transform:translateY(7px)}to{opacity:1;transform:none}}
    .vcol{display:flex;flex-direction:column;align-items:center;gap:4px;}
    .vscore{font-family:'Unbounded',sans-serif;font-weight:800;font-size:16px;line-height:1;}
    .vscore.pos{color:var(--yes);} .vscore.neg{color:var(--no);} .vscore.zero{color:var(--muted);}
    .vbtn{width:32px;height:28px;border-radius:7px;border:1px solid var(--border);background:var(--bg3);color:var(--muted);font-size:11px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .15s;}
    .vbtn.up:hover{background:var(--yes-dim);border-color:var(--yes);color:var(--yes);}
    .vbtn.down:hover{background:var(--no-dim);border-color:var(--no);color:var(--no);}
    .msg-head{display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-bottom:7px;}
    .pill{display:inline-flex;padding:2px 8px;border-radius:999px;font-size:10px;font-weight:700;letter-spacing:.07em;}
    .pill.yes{background:var(--yes-dim);color:var(--yes);border:1px solid rgba(59,130,246,.3);}
    .pill.no{background:var(--no-dim);color:var(--no);border:1px solid rgba(239,68,68,.3);}
    .msg-author{font-size:13px;font-weight:600;}
    .msg-author a:hover{color:var(--accent);}
    .msg-time{margin-left:auto;font-size:11px;color:var(--muted);}
    .msg-body{font-size:14px;color:rgba(234,237,243,.82);line-height:1.6;margin-bottom:8px;}
    .reactions{display:flex;gap:6px;flex-wrap:wrap;align-items:center;}
    .react-btn{display:inline-flex;align-items:center;gap:4px;padding:4px 9px;border-radius:8px;border:1px solid var(--border);background:var(--bg3);color:var(--muted2);font-size:12px;cursor:pointer;transition:all .15s;}
    .react-btn:hover{border-color:var(--border2);color:var(--text);}
    .share-btn{display:inline-flex;align-items:center;gap:4px;padding:4px 9px;border-radius:8px;border:1px solid var(--border);background:var(--bg3);color:var(--muted);font-size:11px;cursor:pointer;margin-left:auto;transition:all .15s;}
    .share-btn:hover{color:var(--text);border-color:var(--border2);}
    .empty{text-align:center;padding:48px 20px;color:var(--muted);font-size:14px;}
    .refresh-hint{text-align:center;font-size:11px;color:var(--muted);margin-top:14px;}
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
    <div class="eyebrow"><span class="live-dot"></span>${esc(category)}</div>
    <h1 class="hero-q">${esc(question)}</h1>
    <div class="scoreboard">
      <div class="score-side yes">
        <span class="score-lbl yes">YES</span>
        <div><div class="score-big yes" id="yesCount">0</div><div class="score-pct" id="yesPct">—</div></div>
      </div>
      <div class="score-side no">
        <div><div class="score-big no" id="noCount">0</div><div class="score-pct" id="noPct">—</div></div>
        <span class="score-lbl no">NO</span>
      </div>
    </div>
    <div class="progress-bar"><div class="progress-yes" id="progressYes" style="width:50%"></div></div>
  </div>

  <div class="main">
    <div>
      <div class="card" style="margin-bottom:20px;">
        <div class="card-label">Your argument</div>
        <div class="side-row">
          <button class="side-btn yes-on" id="yesBtn">✓ YES</button>
          <button class="side-btn" id="noBtn">✗ NO</button>
        </div>
        <textarea id="text" placeholder="Make your case clearly… (max 300 chars)" maxlength="300"></textarea>
        <div class="char-hint" id="charHint">0 / 300</div>
        <button class="post-btn" id="sendBtn">POST ARGUMENT</button>
      </div>
      <div class="sec-hdr">Arguments</div>
      <div class="sort-bar">
        <span class="sort-lbl">Sort by</span>
        <button class="sort-btn on" id="sortNew">Newest</button>
        <button class="sort-btn" id="sortTop">Top rated</button>
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
      <div class="card" style="margin-top:14px;">
        <div class="card-label">Top Debaters</div>
        <div id="lb"></div>
      </div>
    </div>
  </div>
</div>
<script>
  const DEBATE_ID=${debateId};
  let side="YES", sort="new", refreshTimer;
  const EMOJI_MAP={fire:"🔥",think:"🤔",idea:"💡"};

  function esc(s){return String(s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");}
  function ago(ts){const s=Math.floor((Date.now()-new Date(ts))/1000);if(s<60)return s+"s ago";if(s<3600)return Math.floor(s/60)+"m ago";if(s<86400)return Math.floor(s/3600)+"h ago";return Math.floor(s/86400)+"d ago";}
  async function api(url,opts={}){const r=await fetch(url,{headers:{"content-type":"application/json"},...opts});return r.json();}

  const yesEl=document.getElementById("yesBtn"), noEl=document.getElementById("noBtn");
  function setSide(s){side=s;yesEl.className="side-btn"+(s==="YES"?" yes-on":"");noEl.className="side-btn"+(s==="NO"?" no-on":"");}
  yesEl.addEventListener("click",()=>setSide("YES"));
  noEl.addEventListener("click",()=>setSide("NO"));
  setSide("YES");

  document.getElementById("sortNew").addEventListener("click",()=>{sort="new";document.getElementById("sortNew").classList.add("on");document.getElementById("sortTop").classList.remove("on");loadMessages();});
  document.getElementById("sortTop").addEventListener("click",()=>{sort="top";document.getElementById("sortTop").classList.add("on");document.getElementById("sortNew").classList.remove("on");loadMessages();});

  const textEl=document.getElementById("text");
  textEl.addEventListener("input",()=>{const n=textEl.value.length;const h=document.getElementById("charHint");h.textContent=n+" / 300";h.className="char-hint"+(n>260?" warn":"");});

  async function loadMe(){
    const {user:me}=await api("/me").catch(()=>({user:null}));
    const navRight=document.getElementById("navRight");
    const meBox=document.getElementById("meBox");
    const lb=document.getElementById("loginBox");
    const lo=document.getElementById("logoutBox");
    if(!me){
      navRight.innerHTML='';
      meBox.innerHTML='Not signed in — join to post & vote.';
      lb.style.display="block";lo.style.display="none";
    } else {
      navRight.innerHTML=\`<a href="/u/\${esc(me.username)}" style="font-weight:600">\${esc(me.username)}</a><span style="color:var(--gold)"> ★\${me.rating}</span>\`;
      meBox.innerHTML=\`<strong>\${esc(me.username)}</strong><br><span style="color:var(--gold);font-size:12px">★ \${me.rating} pts</span>\`;
      lb.style.display="none";lo.style.display="block";
    }
  }

  async function loadLeaderboard(){
    const rows=await api("/leaderboard/users?limit=7").catch(()=>[]);
    document.getElementById("lb").innerHTML=rows.length
      ? rows.map((u,i)=>\`<div class="lb-item"><span class="lb-num \${i===0?"top":""}">#\${i+1}</span><a class="lb-name" href="/u/\${esc(u.username)}">\${esc(u.username)}</a><span class="lb-pts">\${u.rating}pts</span></div>\`).join("")
      : '<div style="color:var(--muted);font-size:13px">No users yet</div>';
  }

  document.getElementById("loginBtn").addEventListener("click",async()=>{
    const username=document.getElementById("username").value.trim();
    if(!username)return;
    const r=await api("/auth/login",{method:"POST",body:JSON.stringify({username})});
    if(r.error)return alert(r.error);
    await Promise.all([loadMe(),loadLeaderboard()]);
  });
  document.getElementById("logoutBtn").addEventListener("click",async()=>{
    await api("/auth/logout",{method:"POST"});
    await Promise.all([loadMe(),loadLeaderboard()]);
  });

  document.getElementById("sendBtn").addEventListener("click",async()=>{
    const text=textEl.value.trim();if(!text)return;
    const r=await api(\`/debate/\${DEBATE_ID}/messages\`,{method:"POST",body:JSON.stringify({text,side})});
    if(r.error)return alert(r.error);
    textEl.value="";document.getElementById("charHint").textContent="0 / 300";
    await loadMessages();
  });

  function renderMessages(rows){
    const yes=rows.filter(m=>m.side==="YES").length;
    const no=rows.filter(m=>m.side==="NO").length;
    const total=yes+no, yp=total>0?Math.round(yes/total*100):50;
    document.getElementById("yesCount").textContent=yes;
    document.getElementById("noCount").textContent=no;
    document.getElementById("yesPct").textContent=total>0?yp+"% of arguments":"—";
    document.getElementById("noPct").textContent=total>0?(100-yp)+"% of arguments":"—";
    document.getElementById("progressYes").style.width=yp+"%";

    const list=document.getElementById("list");
    if(!rows.length){list.innerHTML='<div class="empty">No arguments yet — be the first!</div>';return;}

    list.innerHTML=rows.map((m,i)=>{
      const sc=m.score>0?"pos":m.score<0?"neg":"zero";
      const pc=m.side==="YES"?"yes":"no";
      const shareUrl=encodeURIComponent(window.location.href+"#msg-"+m.id);
      return \`<div class="msg" id="msg-\${m.id}" style="animation-delay:\${Math.min(i,8)*0.03}s">
        <div class="vcol">
          <div class="vscore \${sc}">\${m.score}</div>
          <button class="vbtn up" data-id="\${m.id}" data-v="1">▲</button>
          <button class="vbtn down" data-id="\${m.id}" data-v="-1">▼</button>
        </div>
        <div>
          <div class="msg-head">
            <span class="pill \${pc}">\${m.side}</span>
            <a class="msg-author" href="/u/\${esc(m.username)}">\${esc(m.username)}</a>
            <span class="msg-time">\${ago(m.created_at)}</span>
          </div>
          <div class="msg-body">\${esc(m.text)}</div>
          <div class="reactions">
            \${["fire","think","idea"].map(e=>\`<button class="react-btn" data-id="\${m.id}" data-emoji="\${e}">\${EMOJI_MAP[e]} \${m[e+"_count"]||0}</button>\`).join("")}
            <button class="share-btn" data-url="\${window.location.origin}/debate/${debateId}#msg-\${m.id}">🔗 Share</button>
          </div>
        </div>
      </div>\`;
    }).join("");

    list.querySelectorAll(".vbtn").forEach(btn=>{
      btn.addEventListener("click",async()=>{
        const id=btn.getAttribute("data-id");
        const v=parseInt(btn.getAttribute("data-v"),10);
        const r=await api(\`/messages/\${id}/vote\`,{method:"POST",body:JSON.stringify({value:v})});
        if(r.error)return alert(r.error);
        await Promise.all([loadMe(),loadLeaderboard(),loadMessages()]);
      });
    });

    list.querySelectorAll(".react-btn").forEach(btn=>{
      btn.addEventListener("click",async()=>{
        const id=btn.getAttribute("data-id");
        const emoji=btn.getAttribute("data-emoji");
        const r=await api(\`/messages/\${id}/react\`,{method:"POST",body:JSON.stringify({emoji})});
        if(r.error)return alert(r.error);
        await loadMessages();
      });
    });

    list.querySelectorAll(".share-btn").forEach(btn=>{
      btn.addEventListener("click",()=>{
        navigator.clipboard.writeText(btn.getAttribute("data-url"))
          .then(()=>{btn.textContent="✅ Copied!";setTimeout(()=>{btn.textContent="🔗 Share";},2000);})
          .catch(()=>alert("Copy: "+btn.getAttribute("data-url")));
      });
    });
  }

  async function loadMessages(){
    const rows=await api(\`/debate/\${DEBATE_ID}/messages?sort=\${sort}\`).catch(()=>[]);
    renderMessages(Array.isArray(rows)?rows:[]);
  }

  function startAutoRefresh(){
    clearInterval(refreshTimer);
    let secs=30;
    document.getElementById("refreshHint").textContent="Auto-refresh in "+secs+"s";
    refreshTimer=setInterval(()=>{
      secs--;
      if(secs<=0){secs=30;loadMessages();}
      document.getElementById("refreshHint").textContent="Auto-refresh in "+secs+"s";
    },1000);
  }

  Promise.all([loadMe(),loadLeaderboard(),loadMessages()]);
  startAutoRefresh();
</script>
</body></html>`;
}

// ─────────────────────────────────────────────────────────
// PROFILE PAGE
// ─────────────────────────────────────────────────────────
function profilePage(username) {
  return `<!doctype html><html lang="en">
<head>
  <meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>${esc(username)} — ARGU Profile</title>
  ${BASE_CSS}
  <style>
    .page{max-width:800px;margin:0 auto;padding:40px 24px 80px;position:relative;z-index:1;}
    .back-link{font-size:13px;color:var(--muted2);display:inline-flex;align-items:center;gap:6px;margin-bottom:24px;transition:color .15s;}
    .back-link:hover{color:var(--text);}
    .profile-header{display:flex;align-items:center;gap:20px;margin-bottom:32px;}
    .avatar{width:64px;height:64px;border-radius:50%;background:var(--bg3);border:2px solid var(--border);display:flex;align-items:center;justify-content:center;font-family:'Unbounded',sans-serif;font-size:22px;font-weight:900;color:var(--accent);flex-shrink:0;}
    .profile-name{font-family:'Unbounded',sans-serif;font-size:22px;font-weight:900;}
    .profile-joined{font-size:12px;color:var(--muted);margin-top:4px;}
    .rating-big{font-family:'Unbounded',sans-serif;font-size:18px;font-weight:700;color:var(--gold);}
    .stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px;margin-bottom:28px;}
    .stat-card{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:16px;text-align:center;}
    .stat-card .n{font-family:'Unbounded',sans-serif;font-size:24px;font-weight:900;}
    .stat-card .l{font-size:11px;color:var(--muted);margin-top:4px;}
    .msg-item{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:14px;margin-bottom:10px;}
    .msg-item-head{display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap;}
    .msg-item-q{font-size:12px;color:var(--muted2);margin-bottom:4px;}
    .msg-item-text{font-size:14px;color:rgba(234,237,243,.82);line-height:1.55;}
    .pill{display:inline-flex;padding:2px 8px;border-radius:999px;font-size:10px;font-weight:700;}
    .pill.yes{background:var(--yes-dim);color:var(--yes);border:1px solid rgba(59,130,246,.3);}
    .pill.no{background:var(--no-dim);color:var(--no);border:1px solid rgba(239,68,68,.3);}
    .score-badge{font-family:'Unbounded',sans-serif;font-size:13px;font-weight:800;margin-left:auto;}
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
  <a class="back-link" href="/">← Back</a>
  <div id="content"><div style="color:var(--muted);text-align:center;padding:60px">Loading profile…</div></div>
</div>
<script>
  const USERNAME="${esc(username)}";
  function esc(s){return String(s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");}
  async function api(url,opts={}){const r=await fetch(url,{headers:{"content-type":"application/json"},...opts});return r.json();}

  async function load(){
    const [profileData, meData] = await Promise.all([
      api("/api/user/"+USERNAME).catch(()=>null),
      api("/me").catch(()=>({user:null}))
    ]);
    const me = meData.user;
    if(me) document.getElementById("navRight").innerHTML=\`<a href="/u/\${esc(me.username)}" style="font-weight:600">\${esc(me.username)}</a><span style="color:var(--gold)"> ★\${me.rating}</span>\`;

    if(!profileData||profileData.error){
      document.getElementById("content").innerHTML='<div style="color:var(--muted);text-align:center;padding:60px">User not found</div>';
      return;
    }
    const {user,stats,top_messages}=profileData;
    const initial=user.username[0].toUpperCase();
    const joined=new Date(user.created_at).toLocaleDateString("en-US",{month:"long",year:"numeric"});

    document.getElementById("content").innerHTML=\`
      <div class="profile-header">
        <div class="avatar">\${initial}</div>
        <div>
          <div class="profile-name">\${esc(user.username)}</div>
          <div class="profile-joined">Joined \${joined}</div>
          <div class="rating-big">★ \${user.rating} pts</div>
        </div>
      </div>
      <div class="stats-grid">
        <div class="stat-card"><div class="n">\${stats.total_args}</div><div class="l">ARGUMENTS</div></div>
        <div class="stat-card"><div class="n" style="color:var(--yes)">\${stats.yes_args}</div><div class="l">YES SIDE</div></div>
        <div class="stat-card"><div class="n" style="color:var(--no)">\${stats.no_args}</div><div class="l">NO SIDE</div></div>
        <div class="stat-card"><div class="n" style="color:var(--gold)">\${stats.total_upvotes}</div><div class="l">UPVOTES</div></div>
        <div class="stat-card"><div class="n">\${stats.best_score}</div><div class="l">BEST SCORE</div></div>
      </div>
      <div style="font-family:'Unbounded',sans-serif;font-size:13px;font-weight:700;margin-bottom:14px;">Top Arguments</div>
      \${top_messages.length ? top_messages.map(m=>{
        const pc=m.side==="YES"?"yes":"no";
        const sc=m.score>0?"var(--yes)":m.score<0?"var(--no)":"var(--muted)";
        return \`<div class="msg-item">
          <div class="msg-item-head">
            <span class="pill \${pc}">\${m.side}</span>
            <a href="/debate/\${m.debate_id||''}" style="font-size:12px;color:var(--muted2)">\${esc(m.question||'')}</a>
            <span class="score-badge" style="color:\${sc}">\${m.score>0?"+":""}\${m.score}</span>
          </div>
          <div class="msg-item-text">\${esc(m.text)}</div>
        </div>\`;
      }).join("") : '<div style="color:var(--muted);font-size:14px;text-align:center;padding:32px">No arguments yet</div>'}
    \`;
  }

  load();
</script>
</body></html>`;
}

// ─────────────────────────────────────────────────────────
// ADMIN LOGIN PAGE
// ─────────────────────────────────────────────────────────
function adminLoginPage(err) {
  return `<!doctype html><html lang="en">
<head>
  <meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Admin Login — ARGU</title>
  ${BASE_CSS}
  <style>
    .center{display:flex;align-items:center;justify-content:center;min-height:100vh;}
    .box{background:var(--bg2);border:1px solid var(--border);border-radius:20px;padding:36px;width:100%;max-width:360px;position:relative;z-index:1;}
    h2{font-family:'Unbounded',sans-serif;font-size:18px;font-weight:800;margin-bottom:24px;}
    .field{margin-bottom:14px;}
    .field label{display:block;font-size:12px;color:var(--muted);margin-bottom:6px;}
    .field input{width:100%;padding:11px 14px;border-radius:10px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-size:14px;outline:none;transition:border-color .18s;}
    .field input:focus{border-color:rgba(59,130,246,.5);}
    .err{background:var(--no-dim);border:1px solid rgba(239,68,68,.3);border-radius:8px;padding:10px 12px;font-size:13px;color:var(--no);margin-bottom:14px;}
  </style>
</head>
<body>
<div class="center">
  <div class="box">
    <h2>🛡️ Admin Login</h2>
    ${err ? `<div class="err">${esc(err)}</div>` : ""}
    <div class="field">
      <label>Password</label>
      <input type="password" id="pw" placeholder="Enter admin password…"/>
    </div>
    <button class="btn-primary" style="width:100%;padding:13px;" id="loginBtn">Enter Admin</button>
  </div>
</div>
<script>
  document.getElementById("loginBtn").addEventListener("click", async()=>{
    const pw=document.getElementById("pw").value;
    const r=await fetch("/admin/login",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({password:pw})});
    const d=await r.json();
    if(d.error)return alert(d.error);
    window.location="/admin";
  });
  document.getElementById("pw").addEventListener("keydown",e=>{if(e.key==="Enter")document.getElementById("loginBtn").click();});
</script>
</body></html>`;
}

// ─────────────────────────────────────────────────────────
// ADMIN DASHBOARD PAGE
// ─────────────────────────────────────────────────────────
function adminPage() {
  return `<!doctype html><html lang="en">
<head>
  <meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Admin — ARGU</title>
  ${BASE_CSS}
  <style>
    .page{max-width:1100px;margin:0 auto;padding:32px 24px 80px;position:relative;z-index:1;}
    h2{font-family:'Unbounded',sans-serif;font-size:20px;font-weight:800;margin-bottom:20px;}
    h3{font-family:'Unbounded',sans-serif;font-size:14px;font-weight:700;margin-bottom:14px;}
    .admin-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;}
    @media(max-width:700px){.admin-grid{grid-template-columns:1fr;}}
    .stats-row{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:24px;}
    .kpi{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:16px 20px;min-width:130px;}
    .kpi-n{font-family:'Unbounded',sans-serif;font-size:26px;font-weight:900;}
    .kpi-l{font-size:11px;color:var(--muted);margin-top:3px;}
    .field{margin-bottom:10px;}
    .field label{display:block;font-size:11px;color:var(--muted);margin-bottom:5px;}
    .field input, .field select{width:100%;padding:10px 12px;border-radius:9px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-family:'Manrope',sans-serif;font-size:13px;outline:none;}
    .field input:focus,.field select:focus{border-color:rgba(59,130,246,.5);}
    .table{width:100%;border-collapse:collapse;font-size:13px;}
    .table th{text-align:left;font-size:10px;font-weight:700;letter-spacing:.08em;color:var(--muted);text-transform:uppercase;padding:8px 10px;border-bottom:1px solid var(--border);}
    .table td{padding:9px 10px;border-bottom:1px solid var(--border);vertical-align:middle;}
    .table tr:last-child td{border-bottom:none;}
    .table tr:hover td{background:rgba(255,255,255,.02);}
    .badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:10px;font-weight:700;}
    .badge.on{background:rgba(34,197,94,.15);color:#22c55e;border:1px solid rgba(34,197,94,.3);}
    .badge.off{background:var(--bg3);color:var(--muted);border:1px solid var(--border);}
    .btn-sm{padding:5px 12px;border-radius:7px;font-size:11px;font-weight:600;cursor:pointer;border:1px solid var(--border);background:var(--bg3);color:var(--muted2);transition:all .15s;}
    .btn-sm:hover{border-color:var(--border2);color:var(--text);}
    .btn-danger{border-color:rgba(239,68,68,.4);color:var(--no);}
    .btn-danger:hover{background:var(--no-dim);border-color:var(--no);}
    .chart-bar{height:120px;display:flex;align-items:flex-end;gap:4px;margin-top:8px;}
    .chart-col{flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;}
    .chart-fill{width:100%;background:var(--accent);border-radius:4px 4px 0 0;min-height:2px;transition:height .3s;}
    .chart-lbl{font-size:9px;color:var(--muted);writing-mode:vertical-rl;transform:rotate(180deg);}
    .logout-btn{padding:8px 16px;border-radius:9px;border:1px solid var(--border);background:transparent;color:var(--muted2);font-size:12px;cursor:pointer;}
    .logout-btn:hover{color:var(--text);}
  </style>
</head>
<body>
<nav>
  <div class="nav-inner">
    <a class="logo" href="/">ARGU<span>.</span></a>
    <div class="nav-right">
      <span style="font-size:12px;color:var(--muted2)">Admin Panel</span>
      <form action="/admin/logout" method="POST" style="display:inline">
        <button class="logout-btn">Sign out</button>
      </form>
    </div>
  </div>
</nav>
<div class="page">
  <h2>🛡️ Admin Dashboard</h2>

  <!-- KPIs -->
  <div class="stats-row" id="kpiRow"><div style="color:var(--muted)">Loading…</div></div>

  <!-- Chart -->
  <div class="card" style="margin-bottom:20px;">
    <h3>📈 Daily Visitors (last 14 days)</h3>
    <div class="chart-bar" id="chart"></div>
  </div>

  <div class="admin-grid">
    <!-- Left: add debate + debates table -->
    <div>
      <div class="card" style="margin-bottom:16px;">
        <h3>➕ Add New Debate</h3>
        <div class="field"><label>Question</label><input id="newQ" placeholder="Should AI have rights?" /></div>
        <div class="field">
          <label>Category</label>
          <select id="newCat">
            <option>Technology</option><option>Economy</option><option>Society</option>
            <option>Politics</option><option>Education</option><option>Life</option>
            <option>Work</option><option>General</option>
          </select>
        </div>
        <button class="btn-primary" style="width:100%;padding:11px;margin-top:4px;" id="addBtn">Add Debate</button>
      </div>

      <div class="card">
        <h3>📋 All Debates</h3>
        <div id="debatesTable"><div style="color:var(--muted);font-size:13px">Loading…</div></div>
      </div>
    </div>

    <!-- Right: users table -->
    <div>
      <div class="card">
        <h3>👥 Recent Users</h3>
        <div id="usersTable"><div style="color:var(--muted);font-size:13px">Loading…</div></div>
      </div>
    </div>
  </div>
</div>

<script>
  function esc(s){return String(s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");}
  async function api(url,opts={}){const r=await fetch(url,{headers:{"content-type":"application/json"},...opts});return r.json();}

  async function loadStats(){
    const d=await api("/admin/api/stats").catch(()=>null);
    if(!d)return;

    // KPIs
    document.getElementById("kpiRow").innerHTML=\`
      <div class="kpi"><div class="kpi-n">\${d.debates}</div><div class="kpi-l">DEBATES</div></div>
      <div class="kpi"><div class="kpi-n">\${d.users}</div><div class="kpi-l">USERS</div></div>
      <div class="kpi"><div class="kpi-n">\${d.messages}</div><div class="kpi-l">ARGUMENTS</div></div>
      <div class="kpi"><div class="kpi-n">\${d.total_views}</div><div class="kpi-l">PAGE VIEWS</div></div>
      <div class="kpi"><div class="kpi-n" style="color:var(--accent)">\${d.unique_visitors}</div><div class="kpi-l">UNIQUE VISITORS</div></div>
    \`;

    // Chart
    const daily=d.daily.slice().reverse();
    const maxV=Math.max(...daily.map(r=>r.uniq),1);
    document.getElementById("chart").innerHTML=daily.map(r=>{
      const h=Math.max(4,Math.round(r.uniq/maxV*110));
      const date=new Date(r.day).toLocaleDateString("en-US",{month:"short",day:"numeric"});
      return \`<div class="chart-col">
        <div class="chart-fill" style="height:\${h}px" title="\${r.uniq} unique, \${r.views} total"></div>
        <div class="chart-lbl">\${date}</div>
      </div>\`;
    }).join("")||'<div style="color:var(--muted);font-size:13px">No data yet</div>';

    // Debates table
    document.getElementById("debatesTable").innerHTML=\`
      <table class="table">
        <tr><th>Question</th><th>Cat</th><th>Args</th><th>Views</th><th>Status</th><th>Actions</th></tr>
        \${d.top_debates.map(dbt=>\`
          <tr>
            <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">\${esc(dbt.question)}</td>
            <td>\${esc(dbt.category)}</td>
            <td>\${dbt.arg_count}</td>
            <td>\${dbt.views}</td>
            <td><span class="badge \${dbt.active?"on":"off"}">\${dbt.active?"Active":"Hidden"}</span></td>
            <td style="display:flex;gap:6px;flex-wrap:wrap">
              <button class="btn-sm" onclick="toggle(\${dbt.id})">\${dbt.active?"Hide":"Show"}</button>
              <button class="btn-sm btn-danger" onclick="del(\${dbt.id})">Delete</button>
            </td>
          </tr>
        \`).join("")}
      </table>
    \`;

    // Users table
    document.getElementById("usersTable").innerHTML=\`
      <table class="table">
        <tr><th>Username</th><th>Rating</th><th>Args</th><th>Joined</th></tr>
        \${d.recent_users.map(u=>\`
          <tr>
            <td><a href="/u/\${esc(u.username)}">\${esc(u.username)}</a></td>
            <td style="color:var(--gold)">\${u.rating}</td>
            <td>\${u.arg_count}</td>
            <td style="color:var(--muted)">\${new Date(u.created_at).toLocaleDateString()}</td>
          </tr>
        \`).join("")}
      </table>
    \`;
  }

  async function toggle(id){
    await api("/admin/debates/"+id+"/toggle",{method:"POST"});
    await loadStats();
  }

  async function del(id){
    if(!confirm("Delete this debate and ALL its arguments?"))return;
    await api("/admin/debates/"+id,{method:"DELETE"});
    await loadStats();
  }

  document.getElementById("addBtn").addEventListener("click",async()=>{
    const question=document.getElementById("newQ").value.trim();
    const category=document.getElementById("newCat").value;
    if(!question)return alert("Enter a question");
    const r=await api("/admin/debates",{method:"POST",body:JSON.stringify({question,category})});
    if(r.error)return alert(r.error);
    document.getElementById("newQ").value="";
    await loadStats();
  });

  loadStats();
</script>
</body></html>`;
}

// ─────────────────────────────────────────────────────────
// Start
// ─────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () =>
  console.log(`✅ Server running on port ${PORT}`)
);