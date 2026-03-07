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
// Google OAuth
// ─────────────────────────────────────────────────────────
const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID     || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const GOOGLE_REDIRECT      = process.env.GOOGLE_REDIRECT_URI  ||
  "https://debate-app-o3qw.onrender.com/auth/google/callback";

// Step 1 — redirect user to Google
app.get("/auth/google", (req, res) => {
  if (!GOOGLE_CLIENT_ID) return res.status(500).send("Google auth not configured");
  const params = new URLSearchParams({
    client_id:     GOOGLE_CLIENT_ID,
    redirect_uri:  GOOGLE_REDIRECT,
    response_type: "code",
    scope:         "openid email profile",
    prompt:        "select_account",
  });
  res.redirect("https://accounts.google.com/o/oauth2/v2/auth?" + params.toString());
});

// Step 2 — Google calls us back with ?code=
app.get("/auth/google/callback", wrap(async (req, res) => {
  const code = req.query.code;
  if (!code) return res.redirect("/?error=no_code");

  // Exchange code for tokens
  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id:     GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri:  GOOGLE_REDIRECT,
      grant_type:    "authorization_code",
    }),
  });
  const tokens = await tokenRes.json();
  if (!tokens.access_token) {
    console.error("Google token error:", tokens);
    return res.redirect("/?error=token_failed");
  }

  // Get user info from Google
  const infoRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
    headers: { Authorization: "Bearer " + tokens.access_token },
  });
  const info = await infoRes.json();
  if (!info.email) return res.redirect("/?error=no_email");

  // Build a clean username from Google name/email
  const base = (info.name || info.email.split("@")[0])
    .replace(/[^a-zA-Z0-9_]/g, "_")
    .replace(/_+/g, "_")
    .slice(0, 18);
  const username = base || "user";

  // Upsert user — if username taken, append short suffix
  let finalUsername = username;
  const existing = await pool.query(
    "SELECT username FROM users WHERE username = $1", [finalUsername]
  );
  // if the username belongs to a DIFFERENT Google account, add suffix
  if (existing.rows[0]) {
    const suffix = info.id ? info.id.slice(-4) : Math.floor(Math.random()*9000+1000).toString();
    finalUsername = (username.slice(0, 14) + "_" + suffix).slice(0, 20);
  }

  await pool.query(
    "INSERT INTO users (username) VALUES ($1) ON CONFLICT (username) DO NOTHING",
    [finalUsername]
  );

  res.cookie("username", finalUsername, { httpOnly: true, sameSite: "lax" });
  res.redirect("/");
}));

// ─────────────────────────────────────────────────────────
// API: debates
// ─────────────────────────────────────────────────────────
app.get("/api/debates", wrap(async (req, res) => {
  const r = await pool.query(`
    SELECT d.id, d.question, d.category, d.type,
           COUNT(m.id)::int                                AS arg_count,
           COUNT(CASE WHEN m.side='YES' THEN 1 END)::int   AS yes_count,
           COUNT(CASE WHEN m.side='NO'  THEN 1 END)::int   AS no_count
    FROM   debates d
    LEFT   JOIN messages m ON m.debate_id = d.id
    WHERE  d.active = TRUE
    GROUP  BY d.id
    ORDER  BY d.id DESC
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
  const type     = req.body?.type === "event" ? "event" : "question";
  if (!question) return res.status(400).json({ error: "Question required" });
  await pool.query(
    "INSERT INTO debates (question, category, type) VALUES ($1, $2, $3)",
    [question, category, type]
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

app.patch("/admin/debates/:id", requireAdmin, wrap(async (req, res) => {
  const id       = parseInt(req.params.id, 10);
  const question = (req.body?.question || "").trim();
  const category = (req.body?.category || "").trim();
  const type     = req.body?.type === "event" ? "event" : "question";
  if (!question || !category) return res.status(400).json({ error: "question and category required" });
  await pool.query(
    "UPDATE debates SET question=$1, category=$2, type=$3 WHERE id=$4",
    [question, category, type, id]
  );
  res.json({ success: true });
}));

// Delete entire category (moves debates to General first, or deletes all)
app.delete("/admin/category/:name", requireAdmin, wrap(async (req, res) => {
  const name   = decodeURIComponent(req.params.name);
  const action = req.body?.action || "move";
  const target = (req.body?.target || "General").trim();
  if (action === "delete") {
    await pool.query("DELETE FROM debates WHERE category=$1", [name]);
  } else {
    await pool.query("UPDATE debates SET category=$1 WHERE category=$2", [target, name]);
  }
  res.json({ success: true });
}));

app.delete("/admin/messages/:id", requireAdmin, wrap(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  await pool.query("DELETE FROM messages WHERE id=$1", [id]);
  res.json({ success: true });
}));

app.delete("/admin/users/:username", requireAdmin, wrap(async (req, res) => {
  const username = req.params.username;
  const user = await pool.query("SELECT id FROM users WHERE username=$1", [username]);
  if (!user.rows[0]) return res.status(404).json({ error: "User not found" });
  const uid = user.rows[0].id;
  await pool.query("DELETE FROM votes    WHERE user_id=$1", [uid]);
  await pool.query("DELETE FROM reactions WHERE user_id=$1", [uid]);
  await pool.query("DELETE FROM messages WHERE user_id=$1", [uid]);
  await pool.query("DELETE FROM users    WHERE id=$1",      [uid]);
  res.json({ success: true });
}));

app.patch("/admin/users/:username/rating", requireAdmin, wrap(async (req, res) => {
  const username = req.params.username;
  const rating   = parseInt(req.body?.rating ?? 0, 10);
  if (!Number.isFinite(rating)) return res.status(400).json({ error: "Bad rating" });
  await pool.query("UPDATE users SET rating=$1 WHERE username=$2", [rating, username]);
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
      SELECT d.id, d.question, d.category, d.type, d.active,
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
    daily:           daily.rows,
    top_debates:  topDebates.rows,
    recent_users: recentUsers.rows,
  });
}));

// ─────────────────────────────────────────────────────────
// HTML Pages
// ─────────────────────────────────────────────────────────
app.get("/", wrap(async (req, res) => {
  trackView(req, res, "/");
  res.type("html").send(landingPage());
}));

app.get("/explore", wrap(async (req, res) => {
  trackView(req, res, "/explore");
  res.type("html").send(explorePage());
}));

app.get("/live", wrap(async (req, res) => {
  res.type("html").send(livePage());
}));

// ── Server-side live debate clock
// Phases: READ=15s, ARGUE=60s, VOTE=45s → total 120s per debate
const LIVE_PHASES = [
  { name: "read",  duration: 15  },
  { name: "argue", duration: 60  },
  { name: "vote",  duration: 45  },
];
const ROUND_TOTAL = LIVE_PHASES.reduce((s,p)=>s+p.duration,0); // 120s

let liveDebateIds  = [];  // shuffled list, refilled as needed
let liveRoundStart = Date.now(); // when this round started

async function refreshLiveDebates() {
  try {
    const r = await pool.query("SELECT id FROM debates WHERE active=TRUE ORDER BY id");
    const ids = r.rows.map(x=>x.id);
    // Fisher-Yates shuffle
    for(let i=ids.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[ids[i],ids[j]]=[ids[j],ids[i]];}
    liveDebateIds = ids;
  } catch(e){ console.error("live refresh err:", e.message); }
}
refreshLiveDebates();

app.get("/api/live-state", wrap(async (req, res) => {
  if(!liveDebateIds.length) await refreshLiveDebates();
  if(!liveDebateIds.length) return res.json({ error: "no debates" });

  const elapsed    = (Date.now() - liveRoundStart) / 1000;
  const roundIndex = Math.floor(elapsed / ROUND_TOTAL);
  const withinRound= elapsed % ROUND_TOTAL;

  // which debate
  const debateIdx  = roundIndex % liveDebateIds.length;
  const debateId   = liveDebateIds[debateIdx];
  const nextIdx    = (debateIdx + 1) % liveDebateIds.length;
  const nextId     = liveDebateIds[nextIdx];

  // which phase
  let phaseIdx = 0, phaseElapsed = withinRound;
  for(let i=0;i<LIVE_PHASES.length;i++){
    if(phaseElapsed < LIVE_PHASES[i].duration){ phaseIdx=i; break; }
    phaseElapsed -= LIVE_PHASES[i].duration;
    phaseIdx = i+1;
  }
  if(phaseIdx >= LIVE_PHASES.length) phaseIdx = LIVE_PHASES.length-1;
  const phase    = LIVE_PHASES[phaseIdx];
  const phaseRemaining = Math.max(0, Math.ceil(phase.duration - phaseElapsed));

  // fetch debate details
  const [curR, nextR] = await Promise.all([
    pool.query(`SELECT d.id,d.question,d.category,
      COUNT(CASE WHEN m.side='YES' THEN 1 END)::int AS yes_count,
      COUNT(CASE WHEN m.side='NO'  THEN 1 END)::int AS no_count
      FROM debates d LEFT JOIN messages m ON m.debate_id=d.id
      WHERE d.id=$1 GROUP BY d.id`, [debateId]),
    pool.query("SELECT id,question FROM debates WHERE id=$1",[nextId]),
  ]);

  res.json({
    debate:    curR.rows[0]  || null,
    next:      nextR.rows[0] || null,
    phase:     phase.name,
    remaining: phaseRemaining,
    duration:  phase.duration,
  });
}));

app.get("/debate", (req, res) => res.redirect("/explore"));

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
// LANDING PAGE (/)
// ─────────────────────────────────────────────────────────
function landingPage() {
  return `<!doctype html><html lang="en">
<head>
  <meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>ARGU — Where the world debates</title>
  <meta name="description" content="Pick a side. Make your case. Let the world decide. Real debates on the events and questions that define our time."/>
  ${BASE_CSS}
  <style>
    .page{max-width:1100px;margin:0 auto;padding:0 24px;position:relative;z-index:1;}

    /* NAV CTA */
    .nav-cta{display:flex;align-items:center;gap:10px;}
    .nav-link{font-size:13px;color:var(--muted2);transition:color .15s;padding:4px 8px;}
    .nav-link:hover{color:var(--text);}
    .nav-btn{padding:8px 18px;border-radius:10px;background:var(--accent);color:#fff;font-family:'Unbounded',sans-serif;font-size:11px;font-weight:700;letter-spacing:.04em;border:none;cursor:pointer;text-decoration:none;transition:opacity .15s;}
    .nav-btn:hover{opacity:.85;}

    /* HERO */
    .hero{min-height:88vh;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:60px 0 40px;}
    .hero-eyebrow{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--accent);border:1px solid rgba(59,130,246,.3);background:rgba(59,130,246,.07);padding:5px 14px;border-radius:999px;margin-bottom:28px;}
    .live-dot{width:6px;height:6px;border-radius:50%;background:var(--accent);animation:blink 1.4s infinite;}
    @keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}
    .hero h1{font-family:'Unbounded',sans-serif;font-size:clamp(36px,6vw,76px);font-weight:900;letter-spacing:-0.04em;line-height:1.02;margin-bottom:22px;}
    .hero h1 .yes{color:var(--yes);}
    .hero h1 .no{color:var(--no);}
    .hero-sub{font-size:clamp(15px,2vw,19px);color:var(--muted2);max-width:560px;line-height:1.6;margin-bottom:36px;}
    .hero-actions{display:flex;align-items:center;gap:12px;flex-wrap:wrap;justify-content:center;}
    .btn-big{padding:14px 30px;border-radius:14px;font-family:'Unbounded',sans-serif;font-size:12px;font-weight:700;letter-spacing:.04em;cursor:pointer;transition:all .18s;text-decoration:none;}
    .btn-big-primary{background:var(--accent);color:#fff;border:none;}
    .btn-big-primary:hover{opacity:.88;transform:translateY(-1px);}
    .btn-big-outline{background:transparent;color:var(--text);border:1px solid var(--border2);}
    .btn-big-outline:hover{background:var(--bg2);}

    /* LIVE TICKER */
    .ticker{background:var(--bg2);border-top:1px solid var(--border);border-bottom:1px solid var(--border);padding:12px 0;overflow:hidden;margin:0 -24px;}
    .ticker-inner{display:flex;gap:48px;animation:scroll 30s linear infinite;white-space:nowrap;width:max-content;}
    .ticker-inner:hover{animation-play-state:paused;}
    @keyframes scroll{from{transform:translateX(0)}to{transform:translateX(-50%)}}
    .ticker-item{display:inline-flex;align-items:center;gap:8px;font-size:13px;color:var(--muted2);}
    .ticker-dot{width:5px;height:5px;border-radius:50%;background:var(--accent);flex-shrink:0;}

    /* HOW IT WORKS */
    .section{padding:80px 0;}
    .section-label{font-size:10px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--accent);margin-bottom:14px;text-align:center;}
    .section h2{font-family:'Unbounded',sans-serif;font-size:clamp(22px,3.5vw,38px);font-weight:800;letter-spacing:-0.02em;text-align:center;margin-bottom:48px;line-height:1.15;}
    .how-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:16px;}
    .how-card{background:var(--bg2);border:1px solid var(--border);border-radius:20px;padding:28px 24px;}
    .how-icon{font-size:28px;margin-bottom:14px;}
    .how-title{font-family:'Unbounded',sans-serif;font-size:14px;font-weight:700;margin-bottom:8px;}
    .how-desc{font-size:13px;color:var(--muted2);line-height:1.6;}

    /* STATS */
    .stats-section{background:var(--bg2);border-top:1px solid var(--border);border-bottom:1px solid var(--border);padding:48px 0;margin:0 -24px;}
    .stats-inner{max-width:800px;margin:0 auto;display:flex;justify-content:center;gap:60px;flex-wrap:wrap;padding:0 24px;}
    .stat-big{text-align:center;}
    .stat-big-n{font-family:'Unbounded',sans-serif;font-size:48px;font-weight:900;line-height:1;background:linear-gradient(135deg,var(--text),var(--muted2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
    .stat-big-l{font-size:12px;color:var(--muted);margin-top:6px;letter-spacing:.08em;text-transform:uppercase;}

    /* PREVIEW DEBATES */
    .preview-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;margin-top:0;}
    .preview-card{background:var(--bg2);border:1px solid var(--border);border-radius:16px;padding:18px;transition:border-color .18s,transform .18s;text-decoration:none;display:block;}
    .preview-card:hover{border-color:var(--border2);transform:translateY(-2px);}
    .preview-type{font-size:9px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;margin-bottom:8px;}
    .preview-type.event{color:#f59e0b;}
    .preview-type.question{color:var(--accent);}
    .preview-q{font-family:'Unbounded',sans-serif;font-size:13px;font-weight:700;line-height:1.3;margin-bottom:12px;}
    .preview-bar{height:3px;background:var(--bg3);border-radius:999px;overflow:hidden;}
    .preview-yes{height:100%;background:var(--yes);}

    /* CTA BOTTOM */
    .cta-bottom{text-align:center;padding:80px 0 100px;}
    .cta-bottom h2{font-family:'Unbounded',sans-serif;font-size:clamp(24px,4vw,44px);font-weight:900;letter-spacing:-0.03em;margin-bottom:16px;line-height:1.1;}
    .cta-bottom p{font-size:16px;color:var(--muted2);margin-bottom:32px;}

    /* FOOTER */
    footer{border-top:1px solid var(--border);padding:28px 24px;text-align:center;font-size:12px;color:var(--muted);}
  </style>
</head>
<body>
<nav>
  <div class="nav-inner">
    <a class="logo" href="/">ARGU<span>.</span></a>
    <div class="nav-cta">
      <a class="nav-link" href="/explore">Debates</a>
      <div id="navAuth"></div>
    </div>
  </div>
</nav>

<!-- HERO -->
<div class="page">
  <div class="hero">
    <div class="hero-eyebrow"><span class="live-dot"></span>Live debates happening now</div>
    <h1>The world<br>says <span class="yes">YES</span><br>or <span class="no">NO</span></h1>
    <!-- Quick Take — loads dynamically -->
    <div id="quickWidget" style="width:100%;max-width:560px;background:var(--bg2);border:1px solid var(--border2);border-radius:24px;padding:28px;margin-bottom:28px;">
      <div style="color:var(--muted);font-size:13px;text-align:center">Loading debate…</div>
    </div>
    <div class="hero-actions">
      <a href="/explore" class="btn-big btn-big-primary">See all debates →</a>
      <a href="/live" class="btn-big btn-big-outline">⚡ Live now</a>
    </div>
  </div>
</div>

<!-- TICKER -->
<div class="ticker">
  <div class="ticker-inner" id="ticker">
    <span class="ticker-item"><span class="ticker-dot"></span>Is college a scam?</span>
    <span class="ticker-item"><span class="ticker-dot"></span>Should billionaires exist?</span>
    <span class="ticker-item"><span class="ticker-dot"></span>Will AI replace programmers?</span>
    <span class="ticker-item"><span class="ticker-dot"></span>Is democracy failing?</span>
    <span class="ticker-item"><span class="ticker-dot"></span>Is hustle culture toxic?</span>
    <span class="ticker-item"><span class="ticker-dot"></span>Should AI have legal rights?</span>
    <span class="ticker-item"><span class="ticker-dot"></span>Is capitalism broken?</span>
    <span class="ticker-item"><span class="ticker-dot"></span>Is college a scam?</span>
    <span class="ticker-item"><span class="ticker-dot"></span>Should billionaires exist?</span>
    <span class="ticker-item"><span class="ticker-dot"></span>Will AI replace programmers?</span>
    <span class="ticker-item"><span class="ticker-dot"></span>Is democracy failing?</span>
    <span class="ticker-item"><span class="ticker-dot"></span>Is hustle culture toxic?</span>
    <span class="ticker-item"><span class="ticker-dot"></span>Should AI have legal rights?</span>
    <span class="ticker-item"><span class="ticker-dot"></span>Is capitalism broken?</span>
  </div>
</div>

<!-- STATS -->
<div class="stats-section">
  <div class="stats-inner" id="statsRow">
    <div class="stat-big"><div class="stat-big-n">—</div><div class="stat-big-l">Debates</div></div>
    <div class="stat-big"><div class="stat-big-n">—</div><div class="stat-big-l">Arguments posted</div></div>
    <div class="stat-big"><div class="stat-big-n">—</div><div class="stat-big-l">Debaters</div></div>
  </div>
</div>

<!-- HOW IT WORKS -->
<div class="page">
  <div class="section" id="how">
    <div class="section-label">How it works</div>
    <h2>Debate like it matters.</h2>
    <div class="how-grid">
      <div class="how-card">
        <div class="how-icon">🌍</div>
        <div class="how-title">Real events & questions</div>
        <div class="how-desc">We cover breaking world events and the big philosophical questions that humanity keeps arguing about.</div>
      </div>
      <div class="how-card">
        <div class="how-icon">⚔️</div>
        <div class="how-title">Pick your side</div>
        <div class="how-desc">Every debate is binary — YES or NO. No fence-sitting. Make a choice and defend it with your best argument.</div>
      </div>
      <div class="how-card">
        <div class="how-icon">🗳️</div>
        <div class="how-title">The crowd votes</div>
        <div class="how-desc">Other users vote on your argument. The better your case, the higher your score — and your rating grows.</div>
      </div>
      <div class="how-card">
        <div class="how-icon">🏆</div>
        <div class="how-title">Rise the leaderboard</div>
        <div class="how-desc">The best debaters earn rating points. Make compelling arguments, gain influence, become a top voice.</div>
      </div>
    </div>
  </div>

  <!-- PREVIEW -->
  <div class="section" style="padding-top:0">
    <div class="section-label">Trending now</div>
    <h2>Jump into a debate</h2>
    <div class="preview-grid" id="previewGrid">
      <div style="color:var(--muted);font-size:13px;grid-column:1/-1">Loading debates…</div>
    </div>
    <div style="text-align:center;margin-top:28px">
      <a href="/explore" class="btn-big btn-big-outline">See all debates →</a>
    </div>
  </div>

  <!-- CTA -->
  <div class="cta-bottom">
    <h2>Join the debate.</h2>
    <p>Real questions. Real arguments. The crowd decides who wins.</p>
    <div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap">
      <a href="/explore" class="btn-big btn-big-primary">Browse all debates →</a>
      <a href="/live" class="btn-big btn-big-outline">⚡ Live now</a>
    </div>
  </div>
</div>

<footer>
  <span>ARGU. — Where the world debates</span>
  &nbsp;·&nbsp;
  <a href="/explore" style="color:var(--muted2)">Debates</a>
</footer>

<script>
  function esc(s){return String(s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");}
  async function api(url,opts={}){try{const r=await fetch(url,{headers:{"content-type":"application/json"},...opts});return r.json();}catch{return null;}}

  async function loadNav(){
    const d = await api("/me");
    const me = d?.user;
    const el = document.getElementById("navAuth");
    if(!me){
      el.innerHTML=\`<a href="/explore" class="nav-btn">Join debate</a>\`;
    } else {
      el.innerHTML=\`<a href="/u/\${esc(me.username)}" style="font-size:13px;color:var(--muted2);margin-right:4px"><strong style="color:var(--text)">\${esc(me.username)}</strong> ★\${me.rating}</a>\`;
    }
  }

  let quickDebate = null, quickSide = null;

  async function loadStats(){
    const debates = await api("/api/debates");
    if(!debates || !debates.length) return;

    const totalArgs = debates.reduce((s,d)=>s+(d.arg_count||0),0);
    const nums = document.querySelectorAll(".stat-big-n");
    nums[0].textContent = debates.length;
    nums[1].textContent = totalArgs;

    const lb = await api("/leaderboard/users?limit=1000");
    if(lb) nums[2].textContent = lb.length;

    // Preview — show 6 most active
    const top = [...debates].sort((a,b)=>b.arg_count-a.arg_count).slice(0,6);
    document.getElementById("previewGrid").innerHTML = top.map(d=>{
      const total=d.yes_count+d.no_count;
      const yp=total>0?Math.round(d.yes_count/total*100):50;
      const typeLabel = d.type==="event" ? "🌍 Event" : "💭 Question";
      return \`<a class="preview-card" href="/debate/\${d.id}">
        <div class="preview-type \${d.type||'question'}">\${typeLabel}</div>
        <div class="preview-q">\${esc(d.question)}</div>
        <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--muted);margin-bottom:6px">
          <span style="color:var(--yes);font-weight:700">YES \${yp}%</span>
          <span>\${d.arg_count} arguments</span>
          <span style="color:var(--no);font-weight:700">\${100-yp}% NO</span>
        </div>
        <div class="preview-bar"><div class="preview-yes" style="width:\${yp}%"></div></div>
      </a>\`;
    }).join("");

    // Quick take — pick a random debate
    quickDebate = debates[Math.floor(Math.random()*debates.length)];
    renderQuick("pick");
  }

  function renderQuick(step){
    const w = document.getElementById("quickWidget");
    const d = quickDebate;
    if(!d){ w.innerHTML=''; return; }
    const total = d.yes_count+d.no_count;
    const yp = total>0?Math.round(d.yes_count/total*100):50;

    if(step==="pick"){
      w.innerHTML=\`
        <div style="font-family:'Unbounded',sans-serif;font-size:16px;font-weight:700;line-height:1.3;margin-bottom:22px;letter-spacing:-0.01em">\${esc(d.question)}</div>
        <div style="display:flex;gap:10px;margin-bottom:14px;">
          <button onclick="pickSide('YES')" style="flex:1;padding:14px;border-radius:14px;border:2px solid rgba(59,130,246,.35);background:var(--yes-dim);color:var(--yes);font-family:'Unbounded',sans-serif;font-size:13px;font-weight:700;cursor:pointer;transition:all .15s;" onmouseover="this.style.borderColor='var(--yes)'" onmouseout="this.style.borderColor='rgba(59,130,246,.35)'">✓ YES</button>
          <button onclick="pickSide('NO')" style="flex:1;padding:14px;border-radius:14px;border:2px solid rgba(239,68,68,.35);background:var(--no-dim);color:var(--no);font-family:'Unbounded',sans-serif;font-size:13px;font-weight:700;cursor:pointer;transition:all .15s;" onmouseover="this.style.borderColor='var(--no)'" onmouseout="this.style.borderColor='rgba(239,68,68,.35)'">✗ NO</button>
        </div>
        <div style="font-size:11px;color:var(--muted);text-align:center">\${(total||0).toLocaleString()} people have weighed in · <a href="/debate/\${d.id}" style="color:var(--accent)">See all arguments →</a></div>
      \`;
    } else if(step==="write"){
      const sc = quickSide==="YES"?"var(--yes)":"var(--no)";
      const bg = quickSide==="YES"?"var(--yes-dim)":"var(--no-dim)";
      w.innerHTML=\`
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:14px">
          <span style="font-size:10px;font-weight:700;letter-spacing:.1em;background:\${bg};color:\${sc};padding:3px 10px;border-radius:999px">\${quickSide}</span>
          <span style="font-family:'Unbounded',sans-serif;font-size:14px;font-weight:700;letter-spacing:-0.01em">\${esc(d.question)}</span>
        </div>
        <textarea id="quickText" placeholder="Make your case in a sentence or two…" maxlength="300"
          style="width:100%;min-height:80px;padding:12px 14px;border-radius:10px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-family:'Manrope',sans-serif;font-size:14px;resize:none;outline:none;margin-bottom:10px;"
          oninput="document.getElementById('qHint').textContent=this.value.length+' / 300'"></textarea>
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span id="qHint" style="font-size:11px;color:var(--muted)">0 / 300</span>
          <div style="display:flex;gap:8px">
            <button onclick="renderQuick('pick')" style="padding:9px 16px;border-radius:10px;border:1px solid var(--border);background:transparent;color:var(--muted2);font-size:12px;cursor:pointer">← Back</button>
            <button onclick="submitQuick()" style="padding:9px 20px;border-radius:10px;border:none;background:var(--accent);color:#fff;font-family:'Unbounded',sans-serif;font-size:11px;font-weight:700;cursor:pointer;">Post argument →</button>
          </div>
        </div>
      \`;
    } else if(step==="done"){
      w.innerHTML=\`
        <div style="text-align:center;padding:12px 0">
          <div style="font-size:28px;margin-bottom:12px">🔥</div>
          <div style="font-family:'Unbounded',sans-serif;font-size:16px;font-weight:700;margin-bottom:8px">Argument posted!</div>
          <div style="font-size:13px;color:var(--muted2);margin-bottom:20px">Others are already voting. See how you stack up.</div>
          <a href="/debate/\${d.id}" style="display:inline-block;padding:11px 24px;border-radius:12px;background:var(--accent);color:#fff;font-family:'Unbounded',sans-serif;font-size:11px;font-weight:700">See the full debate →</a>
        </div>
      \`;
    } else if(step==="login"){
      w.innerHTML=\`
        <div style="margin-bottom:14px">
          <div style="font-size:11px;color:var(--muted);margin-bottom:6px">You picked <strong style="color:\${quickSide==='YES'?'var(--yes)':'var(--no)'}">\${quickSide}</strong>. Choose how to post:</div>
        </div>
        <a href="/auth/google" style="display:flex;align-items:center;justify-content:center;gap:8px;padding:12px;border-radius:12px;border:1px solid var(--border2);background:var(--bg3);color:var(--text);font-size:13px;font-weight:600;text-decoration:none;margin-bottom:10px;">
          <svg width="16" height="16" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.31-8.16 2.31-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>
          Continue with Google
        </a>
        <div style="text-align:center;font-size:11px;color:var(--muted);margin-bottom:8px">or just pick a username</div>
        <div style="display:flex;gap:8px">
          <input id="quickUser" placeholder="username…" maxlength="20" style="flex:1;padding:10px 12px;border-radius:10px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-size:13px;outline:none;"/>
          <button onclick="quickLogin()" style="padding:10px 18px;border-radius:10px;border:none;background:var(--accent);color:#fff;font-family:'Unbounded',sans-serif;font-size:11px;font-weight:700;cursor:pointer;">Join & Post</button>
        </div>
      \`;
    }
  }

  function pickSide(side){
    quickSide = side;
    // check if already logged in
    api("/me").then(d=>{
      if(d?.user) renderQuick("write");
      else renderQuick("login");
    });
  }

  async function quickLogin(){
    const username = document.getElementById("quickUser").value.trim();
    if(!username) return;
    const r = await api("/auth/login",{method:"POST",body:JSON.stringify({username})});
    if(r?.error) return alert(r.error);
    renderQuick("write");
    loadNav();
  }

  async function submitQuick(){
    const text = document.getElementById("quickText").value.trim();
    if(!text) return;
    const r = await api("/debate/"+quickDebate.id+"/messages",{method:"POST",body:JSON.stringify({text,side:quickSide})});
    if(r?.error) return alert(r.error);
    renderQuick("done");
  }

  loadNav(); loadStats();
</script>
</body></html>`;
}

// ─────────────────────────────────────────────────────────
// EXPLORE PAGE (/explore)
// ─────────────────────────────────────────────────────────
function explorePage() {
  return `<!doctype html><html lang="en">
<head>
  <meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Explore Debates — ARGU</title>
  ${BASE_CSS}
  <style>
    .page{max-width:1200px;margin:0 auto;padding:40px 24px 80px;position:relative;z-index:1;}
    /* Auth bar */
    .auth-strip{background:var(--bg2);border:1px solid var(--border);border-radius:14px;padding:16px 20px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:32px;}
    .auth-input{padding:10px 14px;border-radius:10px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-family:'Manrope',sans-serif;font-size:13px;outline:none;width:180px;transition:border-color .18s;}
    .auth-input:focus{border-color:rgba(59,130,246,.5);}
    .auth-input::placeholder{color:var(--muted);}
    .btn-out{padding:9px 16px;border-radius:10px;border:1px solid var(--border);background:transparent;color:var(--muted2);font-size:13px;cursor:pointer;transition:all .15s;}
    .btn-out:hover{border-color:var(--border2);color:var(--text);}
    /* Two columns */
    .explore-header{margin-bottom:28px;}
    .explore-header h1{font-family:'Unbounded',sans-serif;font-size:clamp(22px,3vw,32px);font-weight:800;letter-spacing:-0.02em;margin-bottom:6px;}
    .explore-header p{font-size:14px;color:var(--muted2);}
    .columns{display:grid;grid-template-columns:1fr 1fr;gap:24px;align-items:start;}
    @media(max-width:720px){.columns{grid-template-columns:1fr;}}
    .col-header{display:flex;align-items:center;gap:10px;margin-bottom:16px;padding-bottom:14px;border-bottom:1px solid var(--border);}
    .col-icon{font-size:20px;}
    .col-title{font-family:'Unbounded',sans-serif;font-size:14px;font-weight:800;}
    .col-title.event{color:#f59e0b;}
    .col-title.question{color:var(--accent);}
    .col-sub{font-size:11px;color:var(--muted);margin-top:2px;}
    /* Debate card */
    .dcard{background:var(--bg2);border:1px solid var(--border);border-radius:16px;padding:18px;margin-bottom:10px;display:flex;flex-direction:column;gap:10px;transition:border-color .18s,transform .16s;text-decoration:none;color:inherit;display:block;}
    .dcard:hover{border-color:var(--border2);transform:translateY(-1px);}
    .dcard-top{display:flex;align-items:center;justify-content:space-between;}
    .cat-tag{font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;padding:3px 8px;border-radius:999px;}
    .cat-tag.event{color:#f59e0b;background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.25);}
    .cat-tag.question{color:var(--accent);background:var(--yes-dim);border:1px solid rgba(59,130,246,.2);}
    .arg-ct{font-size:11px;color:var(--muted);}
    .dcard-q{font-family:'Unbounded',sans-serif;font-size:13px;font-weight:700;line-height:1.3;letter-spacing:-0.01em;}
    .dcard-bar{height:3px;background:var(--bg3);border-radius:999px;overflow:hidden;}
    .dcard-yes{height:100%;background:var(--yes);}
    .dcard-nums{display:flex;justify-content:space-between;font-size:10px;font-weight:700;}
    .dcard-open{padding:8px;border-radius:8px;text-align:center;background:var(--bg3);border:1px solid var(--border);font-size:11px;font-weight:600;color:var(--muted2);transition:all .15s;}
    .dcard:hover .dcard-open{background:var(--accent);border-color:var(--accent);color:#fff;}
    /* Filter */
    .filter-row{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:20px;}
    .filter-btn{padding:6px 14px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid var(--border);background:transparent;color:var(--muted2);cursor:pointer;transition:all .15s;}
    .filter-btn.on,.filter-btn:hover{background:var(--bg3);border-color:var(--border2);color:var(--text);}
    .empty-col{text-align:center;padding:40px 20px;color:var(--muted);font-size:13px;background:var(--bg2);border:1px dashed var(--border);border-radius:16px;}
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

  <!-- Auth strip -->
  <div class="auth-strip" id="authStrip">Loading…</div>

  <div class="explore-header">
    <h1>The Arena</h1>
    <p>World events on the left. Timeless questions on the right. Pick a debate and make your case.</p>
  </div>

  <!-- Category filter -->
  <div class="filter-row" id="filterRow"></div>

  <!-- Two columns -->
  <div class="columns">
    <div>
      <div class="col-header">
        <span class="col-icon">🌍</span>
        <div>
          <div class="col-title event">World Events</div>
          <div class="col-sub">Breaking topics, current affairs</div>
        </div>
      </div>
      <div id="eventsCol"><div style="color:var(--muted);font-size:13px">Loading…</div></div>
    </div>
    <div>
      <div class="col-header">
        <span class="col-icon">💭</span>
        <div>
          <div class="col-title question">Questions</div>
          <div class="col-sub">Society, life, the future</div>
        </div>
      </div>
      <div id="questionsCol"><div style="color:var(--muted);font-size:13px">Loading…</div></div>
    </div>
  </div>

</div>
<script>
  let allDebates=[], currentCat="All";
  function esc(s){return String(s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");}
  async function api(url,opts={}){const r=await fetch(url,{headers:{"content-type":"application/json"},...opts});return r.json();}

  async function loadNav(){
    const {user:me}=await api("/me").catch(()=>({user:null}));
    const navRight=document.getElementById("navRight");
    const strip=document.getElementById("authStrip");
    if(!me){
      navRight.innerHTML='';
      strip.innerHTML=\`
        <a href="/auth/google" style="display:inline-flex;align-items:center;gap:7px;padding:9px 16px;border-radius:10px;border:1px solid var(--border2);background:var(--bg3);color:var(--text);font-size:13px;font-weight:600;text-decoration:none;">
          <svg width="15" height="15" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.31-8.16 2.31-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>
          Continue with Google
        </a>
        <span style="font-size:12px;color:var(--muted)">or enter username:</span>
        <input class="auth-input" id="usernameIn" placeholder="username…" maxlength="20"/>
        <button class="btn-primary" id="joinBtn" style="padding:9px 18px">Join</button>
        <span style="font-size:12px;color:var(--muted);margin-left:auto">Sign in to post arguments & vote</span>
      \`;
      document.getElementById("joinBtn").addEventListener("click",async()=>{
        const username=document.getElementById("usernameIn").value.trim();
        if(!username)return;
        const r=await api("/auth/login",{method:"POST",body:JSON.stringify({username})});
        if(r.error)return alert(r.error);
        await loadNav();
      });
    } else {
      navRight.innerHTML=\`<a href="/u/\${esc(me.username)}" style="font-weight:600">\${esc(me.username)}</a><span style="color:var(--gold)"> ★\${me.rating}</span>\`;
      strip.innerHTML=\`
        <span style="font-size:13px">👋 Logged in as <strong>\${esc(me.username)}</strong> — <span style="color:var(--gold)">★ \${me.rating} pts</span></span>
        <a href="/u/\${esc(me.username)}" class="btn-out" style="margin-left:auto">My Profile</a>
        <button class="btn-out" id="logoutBtn">Sign out</button>
      \`;
      document.getElementById("logoutBtn").addEventListener("click",async()=>{
        await api("/auth/logout",{method:"POST"});await loadNav();
      });
    }
  }

  function debateCard(d){
    const total=d.yes_count+d.no_count;
    const yp=total>0?Math.round(d.yes_count/total*100):50;
    const t=d.type||"question";
    return \`<a class="dcard" href="/debate/\${d.id}">
      <div class="dcard-top">
        <span class="cat-tag \${t}">\${esc(d.category)}</span>
        <span class="arg-ct">\${d.arg_count} args</span>
      </div>
      <div class="dcard-q">\${esc(d.question)}</div>
      <div class="dcard-bar"><div class="dcard-yes" style="width:\${yp}%"></div></div>
      <div class="dcard-nums">
        <span style="color:var(--yes)">YES \${yp}%</span>
        <span style="color:var(--no)">\${100-yp}% NO</span>
      </div>
      <div class="dcard-open">Debate this →</div>
    </a>\`;
  }

  function renderColumns(){
    const cat=currentCat==="All";
    const events = allDebates.filter(d=>(d.type||"question")==="event" && (cat||d.category===currentCat));
    const questions = allDebates.filter(d=>(d.type||"question")==="question" && (cat||d.category===currentCat));
    document.getElementById("eventsCol").innerHTML = events.length
      ? events.map(debateCard).join("")
      : \`<div class="empty-col">No events yet — check back soon or add some in the admin panel.</div>\`;
    document.getElementById("questionsCol").innerHTML = questions.length
      ? questions.map(debateCard).join("")
      : \`<div class="empty-col">No questions yet.</div>\`;
  }

  async function loadDebates(){
    allDebates=await api("/api/debates").catch(()=>[]);
    const cats=["All",...new Set(allDebates.map(d=>d.category))];
    document.getElementById("filterRow").innerHTML=cats.map(c=>
      \`<button class="filter-btn \${c===currentCat?"on":""}" data-cat="\${esc(c)}">\${esc(c)}</button>\`
    ).join("");
    document.getElementById("filterRow").querySelectorAll(".filter-btn").forEach(btn=>{
      btn.addEventListener("click",()=>{
        currentCat=btn.getAttribute("data-cat");
        document.querySelectorAll(".filter-btn").forEach(b=>b.classList.toggle("on",b.getAttribute("data-cat")===currentCat));
        renderColumns();
      });
    });
    renderColumns();
  }

  loadNav(); loadDebates();
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
    <a class="back-link" href="/explore">← All debates</a>
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
          <a href="/auth/google" style="display:flex;align-items:center;justify-content:center;gap:8px;padding:10px;border-radius:10px;border:1px solid var(--border2);background:var(--bg3);color:var(--text);font-size:13px;font-weight:600;text-decoration:none;margin-bottom:10px;transition:background .18s;" onmouseover="this.style.background='#1e2028'" onmouseout="this.style.background='var(--bg3)'">
            <svg width="16" height="16" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.31-8.16 2.31-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>
            Continue with Google
          </a>
          <div style="text-align:center;font-size:11px;color:var(--muted);margin-bottom:8px;">or just pick a username</div>
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
  const CATS = ["Technology","Economy","Society","Politics","Education","Life","Work","General"];
  const catOpts = CATS.map(c=>`<option value="${c}">${c}</option>`).join("");
  return `<!doctype html><html lang="en">
<head>
  <meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Admin — ARGU</title>
  ${BASE_CSS}
  <style>
    .page{max-width:1200px;margin:0 auto;padding:32px 24px 80px;position:relative;z-index:1;}
    h2{font-family:'Unbounded',sans-serif;font-size:20px;font-weight:800;margin-bottom:20px;}
    h3{font-family:'Unbounded',sans-serif;font-size:13px;font-weight:700;margin-bottom:14px;}
    .tabs{display:flex;gap:4px;margin-bottom:24px;background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:4px;width:fit-content;}
    .tab{padding:8px 18px;border-radius:9px;font-size:12px;font-weight:700;cursor:pointer;color:var(--muted2);border:none;background:transparent;transition:all .15s;font-family:'Unbounded',sans-serif;letter-spacing:.03em;}
    .tab.active{background:var(--bg3);color:var(--text);border:1px solid var(--border2);}
    .panel{display:none;} .panel.active{display:block;}
    .modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:200;display:flex;align-items:center;justify-content:center;padding:20px;}
    .modal-bg.hidden{display:none;}
    .modal{background:var(--bg2);border:1px solid var(--border2);border-radius:20px;padding:28px;width:100%;max-width:500px;}
    .modal-actions{display:flex;gap:8px;margin-top:18px;justify-content:flex-end;}
    .stats-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:22px;}
    .kpi{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:16px 20px;min-width:120px;}
    .kpi-n{font-family:'Unbounded',sans-serif;font-size:24px;font-weight:900;}
    .kpi-l{font-size:10px;color:var(--muted);margin-top:3px;letter-spacing:.06em;text-transform:uppercase;}
    .chart-bar{height:110px;display:flex;align-items:flex-end;gap:3px;margin-top:8px;}
    .chart-col{flex:1;display:flex;flex-direction:column;align-items:center;gap:3px;}
    .chart-fill{width:100%;background:var(--accent);border-radius:3px 3px 0 0;min-height:2px;}
    .chart-lbl{font-size:9px;color:var(--muted);writing-mode:vertical-rl;transform:rotate(180deg);}
    .field{margin-bottom:10px;}
    .field label{display:block;font-size:11px;color:var(--muted);margin-bottom:5px;}
    .field input,.field select{width:100%;padding:10px 12px;border-radius:9px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-family:'Manrope',sans-serif;font-size:13px;outline:none;}
    .tbl{width:100%;border-collapse:collapse;font-size:13px;}
    .tbl th{text-align:left;font-size:10px;font-weight:700;letter-spacing:.08em;color:var(--muted);text-transform:uppercase;padding:8px 10px;border-bottom:1px solid var(--border);}
    .tbl td{padding:9px 10px;border-bottom:1px solid var(--border);vertical-align:middle;}
    .tbl tr:last-child td{border-bottom:none;}
    .badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:10px;font-weight:700;}
    .badge-on{background:rgba(34,197,94,.15);color:#22c55e;border:1px solid rgba(34,197,94,.3);}
    .badge-off{background:var(--bg3);color:var(--muted);border:1px solid var(--border);}
    .badge-event{background:rgba(245,158,11,.12);color:#f59e0b;border:1px solid rgba(245,158,11,.3);}
    .badge-q{background:var(--yes-dim);color:var(--accent);border:1px solid rgba(59,130,246,.3);}
    .btn-sm{padding:5px 11px;border-radius:7px;font-size:11px;font-weight:600;cursor:pointer;border:1px solid var(--border);background:var(--bg3);color:var(--muted2);transition:all .15s;}
    .btn-sm:hover{border-color:var(--border2);color:var(--text);}
    .btn-danger{border-color:rgba(239,68,68,.35);color:var(--no);}
    .btn-danger:hover{background:var(--no-dim);border-color:var(--no);}
    .btn-success{border-color:rgba(34,197,94,.35);color:#22c55e;}
    .btn-success:hover{background:rgba(34,197,94,.1);border-color:#22c55e;}
    .btn-edit{border-color:rgba(59,130,246,.35);color:var(--accent);}
    .btn-edit:hover{background:var(--yes-dim);border-color:var(--accent);}
    .debate-expand-btn{cursor:pointer;background:none;border:none;color:var(--muted);font-size:11px;padding:2px 6px;}
    .args-hidden{display:none;}
    .cat-card{background:var(--bg2);border:1px solid var(--border);border-radius:14px;padding:20px;margin-bottom:12px;}
    .cat-header{display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap;}
    .cat-name{font-family:'Unbounded',sans-serif;font-size:14px;font-weight:700;flex:1;}
    .cat-pills{display:flex;flex-wrap:wrap;gap:5px;}
    .cat-pill{font-size:11px;background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:3px 8px;color:var(--muted2);}
    .two-col{display:grid;grid-template-columns:380px 1fr;gap:20px;align-items:start;}
    @media(max-width:760px){.two-col{grid-template-columns:1fr;}}
    .logout-btn{padding:8px 16px;border-radius:9px;border:1px solid var(--border);background:transparent;color:var(--muted2);font-size:12px;cursor:pointer;}
    .err-box{background:var(--no-dim);border:1px solid rgba(239,68,68,.3);border-radius:8px;padding:10px 14px;font-size:13px;color:var(--no);margin-bottom:14px;}
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
  <div class="tabs">
    <button class="tab active" data-panel="overview">📊 Overview</button>
    <button class="tab" data-panel="debates">💬 Debates</button>
    <button class="tab" data-panel="categories">🗂️ Categories</button>
    <button class="tab" data-panel="users">👥 Users</button>
  </div>

  <div class="panel active" id="panel-overview">
    <div id="kpiRow" class="stats-row"><div style="color:var(--muted)">Loading…</div></div>
    <div class="card">
      <h3>📈 Unique Visitors (14 days)</h3>
      <div class="chart-bar" id="chartBar"><div style="color:var(--muted);font-size:13px">Loading…</div></div>
    </div>
  </div>

  <div class="panel" id="panel-debates">
    <div class="two-col" style="margin-bottom:20px">
      <div class="card">
        <h3>➕ Add New Debate</h3>
        <div class="field"><label>Question</label><input id="newQ" placeholder="Should AI have rights?"/></div>
        <div class="field"><label>Category</label><select id="newCat">${catOpts}</select></div>
        <div class="field">
          <label>Type</label>
          <select id="newType">
            <option value="question">💭 Question</option>
            <option value="event">🌍 Event</option>
          </select>
        </div>
        <button class="btn-primary" id="addBtn" style="width:100%;padding:11px;margin-top:4px">Add Debate</button>
      </div>
      <div></div>
    </div>
    <div class="card">
      <h3>📋 All Debates</h3>
      <div id="debatesTable"><div style="color:var(--muted)">Loading…</div></div>
    </div>
  </div>

  <div class="panel" id="panel-categories">
    <p style="font-size:13px;color:var(--muted2);margin-bottom:20px">Move all debates from one category to another, or delete a category entirely (removes all debates in it).</p>
    <div id="catPanel"><div style="color:var(--muted)">Loading…</div></div>
  </div>

  <div class="panel" id="panel-users">
    <div class="card">
      <h3>👥 Users</h3>
      <div id="usersTable"><div style="color:var(--muted)">Loading…</div></div>
    </div>
  </div>
</div>

<!-- EDIT MODAL -->
<div class="modal-bg hidden" id="editModal">
  <div class="modal">
    <h3 style="font-family:'Unbounded',sans-serif;font-size:14px;font-weight:700;margin-bottom:18px">✏️ Edit Debate</h3>
    <div id="editErr"></div>
    <div class="field"><label>Question</label><input id="editQ"/></div>
    <div class="field"><label>Category</label><select id="editCat">${catOpts}</select></div>
    <div class="field">
      <label>Type</label>
      <select id="editType">
        <option value="question">💭 Question</option>
        <option value="event">🌍 Event</option>
      </select>
    </div>
    <div class="modal-actions">
      <button class="btn-sm" id="editCancel">Cancel</button>
      <button class="btn-primary" id="editSave">Save</button>
    </div>
  </div>
</div>

<script>
  // ── Helpers
  function $(id){ return document.getElementById(id); }
  function esc(s){ return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
  async function req(url, opts){
    const r = await fetch(url, {credentials:"same-origin", headers:{"content-type":"application/json"}, ...opts});
    const text = await r.text();
    try { return JSON.parse(text); } catch(e) { return {error: "Bad response: "+text.slice(0,80)}; }
  }

  // ── Tabs (pure JS, no CSS class dependency for switching)
  document.querySelectorAll(".tab").forEach(function(tab){
    tab.addEventListener("click", function(){
      document.querySelectorAll(".tab").forEach(function(t){ t.classList.remove("active"); });
      document.querySelectorAll(".panel").forEach(function(p){ p.classList.remove("active"); });
      tab.classList.add("active");
      var panel = document.getElementById("panel-"+tab.getAttribute("data-panel"));
      if(panel) panel.classList.add("active");
    });
  });

  // ── Edit modal
  var editModal = $("editModal");
  var currentEditId = null;
  $("editCancel").addEventListener("click", function(){ editModal.classList.add("hidden"); });
  editModal.addEventListener("click", function(e){ if(e.target===editModal) editModal.classList.add("hidden"); });

  function openEdit(id){
    var d = allDebates.find(function(x){ return x.id===id; });
    if(!d) return;
    currentEditId = id;
    $("editQ").value   = d.question;
    $("editCat").value = d.category || "General";
    $("editType").value= d.type     || "question";
    $("editErr").innerHTML = "";
    editModal.classList.remove("hidden");
    $("editQ").focus();
  }

  $("editSave").addEventListener("click", async function(){
    var q   = $("editQ").value.trim();
    var cat = $("editCat").value;
    var typ = $("editType").value;
    if(!q){ $("editErr").innerHTML='<div class="err-box">Question cannot be empty</div>'; return; }
    var r = await req("/admin/debates/"+currentEditId, {method:"PATCH", body:JSON.stringify({question:q,category:cat,type:typ})});
    if(r.error){ $("editErr").innerHTML='<div class="err-box">'+esc(r.error)+'</div>'; return; }
    editModal.classList.add("hidden");
    loadAll();
  });

  // ── State
  var allDebates = [], allUsers = [], statsData = {};

  async function loadAll(){
    var d = await req("/admin/api/stats");
    if(!d || d.error){
      $("kpiRow").innerHTML = '<div style="color:var(--no);font-size:13px">❌ '+(d&&d.error?esc(d.error):"Load failed")+'</div>';
      return;
    }
    allDebates = d.top_debates  || [];
    allUsers   = d.recent_users || [];
    statsData  = d;
    renderOverview();
    renderDebates();
    renderCategories();
    renderUsers();
  }

  function renderOverview(){
    $("kpiRow").innerHTML = [
      [statsData.debates,           "Debates"],
      [statsData.users,             "Users"],
      [statsData.messages,          "Arguments"],
      [statsData.total_views||0,    "Page Views"],
      [statsData.unique_visitors||0,"Unique Visitors"],
    ].map(function(pair){
      return '<div class="kpi"><div class="kpi-n"'+(pair[1]==="Unique Visitors"?' style="color:var(--accent)"':'')+'>'+pair[0]+'</div><div class="kpi-l">'+pair[1]+'</div></div>';
    }).join("");

    var daily = (statsData.daily||[]).slice().reverse();
    if(!daily.length){ $("chartBar").innerHTML='<div style="color:var(--muted);font-size:13px">No data yet</div>'; return; }
    var maxV = Math.max.apply(null, daily.map(function(r){ return Number(r.uniq)||0; }).concat([1]));
    $("chartBar").innerHTML = daily.map(function(r){
      var h    = Math.max(4, Math.round((Number(r.uniq)||0)/maxV*100));
      var date = r.day ? new Date(r.day).toLocaleDateString("en-US",{month:"short",day:"numeric"}) : "?";
      return '<div class="chart-col"><div class="chart-fill" style="height:'+h+'px" title="'+(r.uniq||0)+' unique"></div><div class="chart-lbl">'+date+'</div></div>';
    }).join("");
  }

  function renderDebates(){
    if(!allDebates.length){ $("debatesTable").innerHTML='<div style="color:var(--muted)">No debates yet</div>'; return; }
    var html = '<table class="tbl"><thead><tr><th>Question</th><th>Category</th><th>Type</th><th>Args</th><th>Status</th><th>Actions</th></tr></thead><tbody>';
    allDebates.forEach(function(d){
      var typeBadge = d.type==="event"
        ? '<span class="badge badge-event">🌍 event</span>'
        : '<span class="badge badge-q">💭 question</span>';
      var statusBadge = d.active
        ? '<span class="badge badge-on">Active</span>'
        : '<span class="badge badge-off">Hidden</span>';
      html += '<tr>';
      html += '<td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(d.question)+'</td>';
      html += '<td>'+esc(d.category||"")+'</td>';
      html += '<td>'+typeBadge+'</td>';
      html += '<td>'+(d.arg_count||0)+'</td>';
      html += '<td>'+statusBadge+'</td>';
      html += '<td><div style="display:flex;gap:4px;flex-wrap:wrap">'
        + '<button class="btn-sm btn-edit" onclick="openEdit('+d.id+')">✏️</button>'
        + '<button class="btn-sm btn-success" onclick="toggleDebate('+d.id+')">'+(d.active?"Hide":"Show")+'</button>'
        + '<button class="btn-sm btn-danger" onclick="delDebate('+d.id+')">🗑️</button>'
        + '<button class="btn-sm" onclick="toggleArgs('+d.id+',this)">▶ args</button>'
        + '</div></td>';
      html += '</tr>';
      html += '<tr id="args-row-'+d.id+'" class="args-hidden"><td colspan="6" style="padding:0;background:var(--bg3)">';
      html += '<div id="args-inner-'+d.id+'" style="padding:0 10px 12px"><div style="color:var(--muted);font-size:12px;padding:10px 0">Click ▶ args to load</div></div>';
      html += '</td></tr>';
    });
    html += '</tbody></table>';
    $("debatesTable").innerHTML = html;
  }

  function toggleArgs(id, btn){
    var row = $("args-row-"+id);
    if(row.classList.contains("args-hidden")){
      row.classList.remove("args-hidden");
      btn.textContent = "▼ args";
      loadArgs(id);
    } else {
      row.classList.add("args-hidden");
      btn.textContent = "▶ args";
    }
  }

  async function loadArgs(debateId){
    var inner = $("args-inner-"+debateId);
    if(!inner) return;
    inner.innerHTML = '<div style="color:var(--muted);font-size:12px;padding:10px 0">Loading…</div>';
    var msgs = await req("/debate/"+debateId+"/messages?limit=200&sort=new");
    if(!msgs || msgs.error || !msgs.length){
      inner.innerHTML = '<div style="color:var(--muted);font-size:12px;padding:10px 0">No arguments yet</div>';
      return;
    }
    inner.innerHTML = msgs.map(function(m){
      return '<div style="display:flex;align-items:flex-start;gap:10px;padding:10px 0;border-bottom:1px solid var(--border)">'
        +'<span class="badge '+(m.side==="YES"?"badge-on":"badge-off")+'">'+m.side+'</span>'
        +'<div style="flex:1;font-size:13px;line-height:1.5"><span style="font-weight:600;font-size:12px">'+esc(m.username)+'</span> <span style="color:var(--muted);font-size:11px">score:'+m.score+'</span><br>'+esc(m.text)+'</div>'
        +'<div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px">'
        +'<span style="font-size:11px;color:var(--muted)">'+new Date(m.created_at).toLocaleDateString()+'</span>'
        +'<button class="btn-sm btn-danger" onclick="delMsg('+m.id+','+debateId+')">Del</button>'
        +'</div></div>';
    }).join("");
  }

  function renderCategories(){
    var catMap = {};
    allDebates.forEach(function(d){
      var c = d.category||"General";
      if(!catMap[c]) catMap[c]=[];
      catMap[c].push(d);
    });
    var cats = Object.keys(catMap).sort();
    if(!cats.length){ $("catPanel").innerHTML='<div style="color:var(--muted)">No categories</div>'; return; }
    var ALL_CATS = ["Technology","Economy","Society","Politics","Education","Life","Work","General"];
    var html = cats.map(function(cat){
      var items   = catMap[cat];
      var targets = ALL_CATS.filter(function(c){ return c!==cat; });
      var selId   = "moveSel_"+cat.replace(/\W/g,"_");
      var opts    = targets.map(function(c){ return '<option value="'+esc(c)+'">'+esc(c)+'</option>'; }).join("");
      var pills   = items.map(function(d){
        return '<span class="cat-pill">'+esc(d.question.length>42?d.question.slice(0,42)+"…":d.question)+'</span>';
      }).join("");
      return '<div class="cat-card">'
        +'<div class="cat-header">'
        +'<span class="cat-name">📁 '+esc(cat)+'</span>'
        +'<span style="font-size:12px;color:var(--muted)">'+items.length+' debate'+(items.length!==1?"s":"")+'</span>'
        +'<select id="'+selId+'" style="padding:6px 10px;border-radius:8px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-size:12px;outline:none">'+opts+'</select>'
        +'<button class="btn-sm btn-edit" onclick="moveCategory(\''+esc(cat)+'\',document.getElementById(\''+selId+'\').value)">Move all →</button>'
        +'<button class="btn-sm btn-danger" onclick="deleteCategory(\''+esc(cat)+'\')">Delete</button>'
        +'</div>'
        +'<div class="cat-pills">'+pills+'</div>'
        +'</div>';
    }).join("");
    $("catPanel").innerHTML = html;
  }

  function renderUsers(){
    if(!allUsers.length){ $("usersTable").innerHTML='<div style="color:var(--muted)">No users yet</div>'; return; }
    var html = '<table class="tbl"><thead><tr><th>Username</th><th>Rating</th><th>Args</th><th>Joined</th><th>Actions</th></tr></thead><tbody>';
    allUsers.forEach(function(u){
      var uid = "rat_"+u.username.replace(/\W/g,"_");
      html += '<tr>'
        +'<td><a href="/u/'+esc(u.username)+'" style="font-weight:600">'+esc(u.username)+'</a></td>'
        +'<td><input type="number" id="'+uid+'" value="'+u.rating+'" style="width:70px;padding:4px 8px;border-radius:7px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-size:13px;text-align:center"/></td>'
        +'<td>'+(u.arg_count||0)+'</td>'
        +'<td style="color:var(--muted)">'+(u.created_at?new Date(u.created_at).toLocaleDateString():"—")+'</td>'
        +'<td><div style="display:flex;gap:4px">'
        +'<button class="btn-sm btn-edit" onclick="saveRating(\''+esc(u.username)+'\',\''+uid+'\')">Save</button>'
        +'<button class="btn-sm btn-danger" onclick="delUser(\''+esc(u.username)+'\')">Delete</button>'
        +'</div></td></tr>';
    });
    html += '</tbody></table>';
    $("usersTable").innerHTML = html;
  }

  // ── Actions
  async function toggleDebate(id){ await req("/admin/debates/"+id+"/toggle",{method:"POST"}); loadAll(); }
  async function delDebate(id){
    if(!confirm("Delete debate + all its arguments?")) return;
    await req("/admin/debates/"+id,{method:"DELETE"}); loadAll();
  }
  async function delMsg(msgId, debateId){
    if(!confirm("Delete this argument?")) return;
    await req("/admin/messages/"+msgId,{method:"DELETE"}); loadArgs(debateId);
  }
  async function moveCategory(from, to){
    if(!to) return alert("Pick a target category");
    if(!confirm("Move all debates from \""+from+"\" → \""+to+"\"?")) return;
    var r = await req("/admin/category/"+encodeURIComponent(from),{method:"DELETE",body:JSON.stringify({action:"move",target:to})});
    if(r.error) return alert(r.error);
    loadAll();
  }
  async function deleteCategory(name){
    if(!confirm("Delete category \""+name+"\" AND all its debates? Cannot be undone.")) return;
    var r = await req("/admin/category/"+encodeURIComponent(name),{method:"DELETE",body:JSON.stringify({action:"delete"})});
    if(r.error) return alert(r.error);
    loadAll();
  }
  async function saveRating(username, inputId){
    var val = parseInt(document.getElementById(inputId).value,10);
    if(isNaN(val)) return alert("Invalid number");
    var r = await req("/admin/users/"+encodeURIComponent(username)+"/rating",{method:"PATCH",body:JSON.stringify({rating:val})});
    if(r.error) return alert(r.error);
    loadAll();
  }
  async function delUser(username){
    if(!confirm("Delete user \""+username+"\" and ALL their data? Cannot be undone.")) return;
    var r = await req("/admin/users/"+encodeURIComponent(username),{method:"DELETE"});
    if(r.error) return alert(r.error);
    loadAll();
  }

  // ── Add debate
  $("addBtn").addEventListener("click", async function(){
    var q   = $("newQ").value.trim();
    var cat = $("newCat").value;
    var typ = $("newType").value;
    if(!q) return alert("Enter a question");
    var r = await req("/admin/debates",{method:"POST",body:JSON.stringify({question:q,category:cat,type:typ})});
    if(r.error) return alert(r.error);
    $("newQ").value = "";
    loadAll();
  });

  loadAll();
</script>
</body></html>`;
}

// ─────────────────────────────────────────────────────────
// LIVE PAGE (/live)
// ─────────────────────────────────────────────────────────
function livePage() {
  return `<!doctype html><html lang="en">
<head>
  <meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>⚡ Live — ARGU</title>
  ${BASE_CSS}
  <style>
    body{overflow:hidden;}
    .wrap{position:fixed;inset:0;display:flex;flex-direction:column;}
    /* Nav */
    .live-nav{display:flex;align-items:center;justify-content:space-between;padding:0 24px;height:54px;border-bottom:1px solid var(--border);background:rgba(11,12,16,.9);backdrop-filter:blur(18px);flex-shrink:0;z-index:10;}
    .live-badge{display:inline-flex;align-items:center;gap:6px;font-size:10px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:#ef4444;border:1px solid rgba(239,68,68,.35);background:rgba(239,68,68,.1);padding:4px 12px;border-radius:999px;}
    .rdot{width:6px;height:6px;border-radius:50%;background:#ef4444;animation:rblink 1s infinite;display:inline-block;}
    @keyframes rblink{0%,100%{opacity:1}50%{opacity:.2}}
    /* Body split */
    .live-body{flex:1;display:grid;grid-template-columns:1fr 360px;overflow:hidden;}
    @media(max-width:760px){.live-body{grid-template-columns:1fr;}}
    /* Left */
    .left{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px 40px;text-align:center;border-right:1px solid var(--border);position:relative;overflow:hidden;}
    /* Phase bar */
    .phase-bar{display:flex;gap:0;width:100%;max-width:420px;margin-bottom:28px;border-radius:10px;overflow:hidden;border:1px solid var(--border);}
    .phase-seg{flex:1;padding:6px 4px;font-size:9px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);text-align:center;background:var(--bg3);transition:all .3s;}
    .phase-seg.active{background:var(--accent);color:#fff;}
    .phase-seg.done{background:rgba(59,130,246,.2);color:var(--accent);}
    /* Question */
    .live-cat{font-size:10px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--accent);margin-bottom:14px;}
    .live-q{font-family:'Unbounded',sans-serif;font-size:clamp(20px,3vw,40px);font-weight:900;letter-spacing:-0.03em;line-height:1.1;max-width:640px;margin-bottom:28px;transition:opacity .35s;}
    .live-q.fade{opacity:0;}
    /* Timer */
    .timer-wrap{position:relative;width:72px;height:72px;margin-bottom:24px;}
    .timer-svg{transform:rotate(-90deg);}
    .t-track{fill:none;stroke:var(--border);stroke-width:5;}
    .t-fill{fill:none;stroke-width:5;stroke-linecap:round;transition:stroke-dashoffset 1s linear,stroke .5s;}
    .t-n{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-family:'Unbounded',sans-serif;font-size:20px;font-weight:900;}
    /* Phase content */
    .phase-content{width:100%;max-width:420px;}
    .phase-read-msg{font-size:16px;color:var(--muted2);line-height:1.5;}
    .vote-row{display:flex;gap:12px;margin-bottom:18px;}
    .vbtn{flex:1;max-width:150px;padding:15px;border-radius:14px;border:2px solid;font-family:'Unbounded',sans-serif;font-size:13px;font-weight:700;cursor:pointer;transition:all .18s;}
    .vbtn-yes{border-color:var(--yes);background:var(--yes-dim);color:var(--yes);}
    .vbtn-yes:hover,.vbtn-yes.picked{background:var(--yes);color:#fff;}
    .vbtn-no{border-color:var(--no);background:var(--no-dim);color:var(--no);}
    .vbtn-no:hover,.vbtn-no.picked{background:var(--no);color:#fff;}
    .score-row{display:flex;align-items:center;gap:10px;width:100%;max-width:400px;font-family:'Unbounded',sans-serif;font-size:12px;font-weight:700;margin-bottom:16px;}
    .sc-yes{color:var(--yes);min-width:50px;text-align:right;}
    .sc-no{color:var(--no);min-width:50px;}
    .sc-bar{flex:1;height:5px;background:var(--bg3);border-radius:999px;overflow:hidden;}
    .sc-fill{height:100%;background:var(--yes);border-radius:999px;transition:width .5s;}
    .arg-textarea{width:100%;padding:11px 13px;border-radius:10px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-family:'Manrope',sans-serif;font-size:13px;resize:none;outline:none;min-height:66px;transition:border-color .18s;}
    .arg-textarea:focus{border-color:rgba(59,130,246,.5);}
    /* Vote phase — inline argument voting */
    .arg-vote-item{display:flex;align-items:flex-start;gap:10px;padding:10px 0;border-bottom:1px solid var(--border);}
    .arg-vote-item:last-child{border-bottom:none;}
    .arg-vote-btns{display:flex;flex-direction:column;gap:4px;align-items:center;}
    .avbtn{width:28px;height:24px;border-radius:5px;border:1px solid var(--border);background:var(--bg3);color:var(--muted);font-size:11px;cursor:pointer;transition:all .15s;}
    .avbtn.up:hover{background:var(--yes-dim);color:var(--yes);}
    .avbtn.down:hover{background:var(--no-dim);color:var(--no);}
    .avscore{font-family:'Unbounded',sans-serif;font-size:11px;font-weight:700;}
    /* Login overlay */
    .login-ov{position:absolute;inset:0;background:rgba(11,12,16,.88);backdrop-filter:blur(8px);display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;z-index:5;}
    .login-ov.hidden{display:none;}
    /* Right: feed */
    .right{display:flex;flex-direction:column;overflow:hidden;}
    .feed-hdr{padding:14px 18px;border-bottom:1px solid var(--border);font-family:'Unbounded',sans-serif;font-size:11px;font-weight:700;display:flex;align-items:center;gap:8px;flex-shrink:0;}
    .feed-list{flex:1;overflow-y:auto;padding:10px 14px;display:flex;flex-direction:column;gap:7px;}
    .feed-item{background:var(--bg2);border:1px solid var(--border);border-radius:11px;padding:11px 13px;animation:fIn .2s ease both;font-size:13px;}
    @keyframes fIn{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
    .fi-head{display:flex;align-items:center;gap:6px;margin-bottom:5px;}
    .fi-pill{display:inline-block;padding:2px 7px;border-radius:999px;font-size:9px;font-weight:700;}
    .fi-pill.yes{background:var(--yes-dim);color:var(--yes);border:1px solid rgba(59,130,246,.3);}
    .fi-pill.no{background:var(--no-dim);color:var(--no);border:1px solid rgba(239,68,68,.3);}
    .next-bar{padding:10px 18px;border-top:1px solid var(--border);font-size:11px;color:var(--muted);display:flex;align-items:center;gap:7px;flex-shrink:0;}
    .next-q{color:var(--muted2);font-weight:600;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
  </style>
</head>
<body>
<div class="wrap">
  <nav class="live-nav">
    <div style="display:flex;align-items:center;gap:14px">
      <a href="/" style="font-size:13px;color:var(--muted2);display:flex;align-items:center;gap:5px">← Back</a>
      <a class="logo" href="/">ARGU<span>.</span></a>
    </div>
    <div class="live-badge"><span class="rdot"></span>LIVE</div>
    <div id="navRight" style="font-size:13px;color:var(--muted2)"></div>
  </nav>

  <div class="live-body">
    <!-- LEFT -->
    <div class="left" id="leftPane">
      <!-- Phase indicator -->
      <div class="phase-bar" id="phaseBar">
        <div class="phase-seg" id="seg-read">📖 Read</div>
        <div class="phase-seg" id="seg-argue">⚔️ Argue</div>
        <div class="phase-seg" id="seg-vote">🗳️ Vote</div>
      </div>

      <div class="live-cat" id="liveCategory">Loading…</div>
      <div class="live-q" id="liveQ"></div>

      <div class="timer-wrap">
        <svg class="timer-svg" width="72" height="72" viewBox="0 0 72 72">
          <circle class="t-track" cx="36" cy="36" r="31"/>
          <circle class="t-fill" id="tArc" cx="36" cy="36" r="31" stroke="#3b82f6"
            stroke-dasharray="195" stroke-dashoffset="0"/>
        </svg>
        <div class="t-n" id="tN">—</div>
      </div>

      <!-- Phase-specific content -->
      <div class="phase-content" id="phaseContent">
        <div style="color:var(--muted);font-size:13px">Loading…</div>
      </div>

      <!-- Login overlay -->
      <div class="login-ov hidden" id="loginOv">
        <div style="font-family:'Unbounded',sans-serif;font-size:16px;font-weight:700;margin-bottom:8px">Join to participate</div>
        <a href="/auth/google" style="display:inline-flex;align-items:center;gap:7px;padding:11px 20px;border-radius:12px;border:1px solid var(--border2);background:var(--bg3);color:var(--text);font-size:13px;font-weight:600;text-decoration:none;">
          <svg width="15" height="15" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.31-8.16 2.31-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>
          Continue with Google
        </a>
        <div style="font-size:11px;color:var(--muted)">or</div>
        <div style="display:flex;gap:8px">
          <input id="joinUser" placeholder="username…" maxlength="20" style="padding:10px 12px;border-radius:10px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-size:13px;outline:none;width:140px;"/>
          <button onclick="quickJoin()" style="padding:10px 18px;border-radius:10px;border:none;background:var(--accent);color:#fff;font-family:'Unbounded',sans-serif;font-size:11px;font-weight:700;cursor:pointer;">Join</button>
        </div>
      </div>
    </div>

    <!-- RIGHT: live feed -->
    <div class="right">
      <div class="feed-hdr">
        <span class="rdot"></span>
        Live feed
        <span id="feedCount" style="font-size:10px;color:var(--muted);margin-left:auto">0 args</span>
      </div>
      <div class="feed-list" id="feedList">
        <div style="text-align:center;padding:40px;color:var(--muted);font-size:13px">Waiting for arguments…</div>
      </div>
      <div class="next-bar">
        <span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;flex-shrink:0">Next:</span>
        <span class="next-q" id="nextQ">—</span>
      </div>
    </div>
  </div>
</div>

<script>
  function esc(s){ return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }
  async function api(url,opts){
    try{
      var r = await fetch(url, Object.assign({credentials:"same-origin",headers:{"content-type":"application/json"}},opts||{}));
      return r.json();
    }catch(e){ return null; }
  }

  var me         = null;
  var curDebate  = null;
  var curPhase   = "read";
  var pickedSide = null;
  var tickInt    = null;
  var pollInt    = null;
  var lastDebId  = null;
  var lastPhase  = null;
  var clientRem  = 0;
  var CIRCUM     = 195;

  async function init(){
    var meR = await api("/me");
    me = meR && meR.user ? meR.user : null;
    if(me){
      document.getElementById("navRight").innerHTML =
        '<a href="/u/'+esc(me.username)+'" style="font-weight:600;color:var(--text)">'+esc(me.username)+'</a>'+
        '<span style="color:#f59e0b;margin-left:6px">★'+me.rating+'</span>';
    }
    poll();
    pollInt = setInterval(poll, 4000);
  }

  async function poll(){
    var state = await api("/api/live-state");
    if(!state || state.error){
      document.getElementById("liveCategory").textContent = "No debates available";
      document.getElementById("liveQ").textContent = "Add debates in the admin panel.";
      return;
    }

    var d = state.debate;
    if(!d) return;

    // Detect debate change → reset side pick
    if(d.id !== lastDebId){
      pickedSide = null;
      lastDebId  = d.id;
      var qEl    = document.getElementById("liveQ");
      qEl.classList.add("fade");
      setTimeout(function(){
        qEl.textContent = d.question;
        document.getElementById("liveCategory").textContent = d.category || "General";
        qEl.classList.remove("fade");
      }, 350);
      refreshFeed(d.id);
    }

    // Always update scores, timer, phase
    curDebate = d;
    curPhase  = state.phase;
    clientRem = state.remaining;

    updatePhaseBar(state.phase);
    updateTimer(state.remaining, state.duration, state.phase);
    updateScore(d.yes_count||0, d.no_count||0);

    if(state.phase !== lastPhase){
      lastPhase = state.phase;
      renderPhaseContent(state.phase, d);
      if(state.phase === "vote" || state.phase === "argue") refreshFeed(d.id);
    }

    if(state.next) document.getElementById("nextQ").textContent = state.next.question;
  }

  // Local 1s countdown between polls
  clearInterval(tickInt);
  tickInt = setInterval(function(){
    if(clientRem > 0){
      clientRem--;
      if(curDebate) updateTimer(clientRem, getPhaseDuration(curPhase), curPhase);
    }
  }, 1000);

  function getPhaseDuration(phase){
    return phase==="read"?15:phase==="argue"?60:45;
  }

  function updatePhaseBar(phase){
    ["read","argue","vote"].forEach(function(p, i){
      var seg = document.getElementById("seg-"+p);
      var phases = ["read","argue","vote"];
      var cur    = phases.indexOf(phase);
      seg.classList.remove("active","done");
      if(p === phase) seg.classList.add("active");
      else if(phases.indexOf(p) < cur) seg.classList.add("done");
    });
  }

  function updateTimer(rem, dur, phase){
    var pct    = dur > 0 ? rem/dur : 0;
    var offset = CIRCUM * (1-pct);
    var arc    = document.getElementById("tArc");
    arc.setAttribute("stroke-dashoffset", offset);
    var color  = rem > dur*0.5 ? "#3b82f6" : rem > dur*0.25 ? "#f59e0b" : "#ef4444";
    arc.setAttribute("stroke", color);
    document.getElementById("tN").textContent = rem;
  }

  function updateScore(yes, no){
    var total = yes+no||1;
    var yp    = Math.round(yes/total*100);
    var scY   = document.getElementById("scY");
    var scN   = document.getElementById("scN");
    var scF   = document.getElementById("scF");
    if(scY) scY.textContent = yes+" YES";
    if(scN) scN.textContent = "NO "+no;
    if(scF) scF.style.width = yp+"%";
  }

  function renderPhaseContent(phase, d){
    var c = document.getElementById("phaseContent");
    if(phase === "read"){
      c.innerHTML = '<div class="phase-read-msg">Take a moment to think about both sides of this question. Voting starts in a few seconds.</div>';
    } else if(phase === "argue"){
      c.innerHTML =
        '<div class="score-row"><span class="sc-yes" id="scY">0 YES</span><div class="sc-bar"><div class="sc-fill" id="scF" style="width:50%"></div></div><span class="sc-no" id="scN">NO 0</span></div>'+
        '<div class="vote-row">'+
          '<button class="vbtn vbtn-yes'+(pickedSide==="YES"?" picked":"")+'" id="btnYes" onclick="castVote(\'YES\')">✓ YES</button>'+
          '<button class="vbtn vbtn-no'+(pickedSide==="NO"?" picked":"")+'" id="btnNo"  onclick="castVote(\'NO\')">✗ NO</button>'+
        '</div>'+
        '<div id="argSection" class="'+(pickedSide?'':'hidden')+'" style="width:100%">'+
          '<textarea class="arg-textarea" id="argTxt" placeholder="Add your argument (optional, max 300 chars)" maxlength="300" oninput="document.getElementById(\'argHint\').textContent=this.value.length+\' / 300\'"></textarea>'+
          '<div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px">'+
            '<span style="font-size:11px;color:var(--muted)" id="argHint">0 / 300</span>'+
            '<button onclick="postArg()" style="padding:9px 20px;border-radius:10px;border:none;background:var(--accent);color:#fff;font-family:\'Unbounded\',sans-serif;font-size:10px;font-weight:700;cursor:pointer">Post →</button>'+
          '</div>'+
        '</div>';
      if(d) updateScore(d.yes_count||0, d.no_count||0);
    } else if(phase === "vote"){
      c.innerHTML =
        '<div style="font-family:\'Unbounded\',sans-serif;font-size:13px;font-weight:700;margin-bottom:14px;width:100%;text-align:left">🗳️ Vote on the best arguments</div>'+
        '<div id="voteArgList" style="width:100%;max-height:280px;overflow-y:auto"><div style="color:var(--muted);font-size:13px">Loading…</div></div>';
      loadVoteArgs(d.id);
    }
  }

  async function refreshFeed(debateId){
    var msgs = await api("/debate/"+debateId+"/messages?sort=new&limit=40");
    if(!msgs || !msgs.length) return;
    document.getElementById("feedCount").textContent = msgs.length+" arg"+(msgs.length!==1?"s":"");
    document.getElementById("feedList").innerHTML = msgs.map(function(m){
      return '<div class="feed-item">'+
        '<div class="fi-head">'+
          '<span class="fi-pill '+m.side.toLowerCase()+'">'+m.side+'</span>'+
          '<span style="font-size:11px;font-weight:600;color:var(--muted2)">'+esc(m.username)+'</span>'+
          '<span style="margin-left:auto;font-size:10px;color:var(--muted)">'+(m.score>0?"+":"")+m.score+'</span>'+
        '</div>'+
        '<div style="color:rgba(234,237,243,.82);line-height:1.5">'+esc(m.text)+'</div>'+
      '</div>';
    }).join("");
  }

  async function loadVoteArgs(debateId){
    var msgs = await api("/debate/"+debateId+"/messages?sort=top&limit=20");
    var el   = document.getElementById("voteArgList");
    if(!el) return;
    if(!msgs || !msgs.length){ el.innerHTML='<div style="color:var(--muted);font-size:13px">No arguments yet</div>'; return; }
    el.innerHTML = msgs.map(function(m){
      return '<div class="arg-vote-item">'+
        '<div class="arg-vote-btns">'+
          '<button class="avbtn up" onclick="voteMsg('+m.id+',1,this)">▲</button>'+
          '<span class="avscore" style="color:'+(m.score>0?"var(--yes)":m.score<0?"var(--no)":"var(--muted)")+'">'+m.score+'</span>'+
          '<button class="avbtn down" onclick="voteMsg('+m.id+',-1,this)">▼</button>'+
        '</div>'+
        '<div style="flex:1">'+
          '<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">'+
            '<span class="fi-pill '+m.side.toLowerCase()+'">'+m.side+'</span>'+
            '<span style="font-size:11px;font-weight:600;color:var(--muted2)">'+esc(m.username)+'</span>'+
          '</div>'+
          '<div style="font-size:13px;color:rgba(234,237,243,.82);line-height:1.5">'+esc(m.text)+'</div>'+
        '</div>'+
      '</div>';
    }).join("");
  }

  async function castVote(side){
    if(!me){ document.getElementById("loginOv").classList.remove("hidden"); return; }
    pickedSide = side;
    var btnY = document.getElementById("btnYes");
    var btnN = document.getElementById("btnNo");
    if(btnY) btnY.classList.toggle("picked", side==="YES");
    if(btnN) btnN.classList.toggle("picked", side==="NO");
    var argSec = document.getElementById("argSection");
    if(argSec) argSec.classList.remove("hidden");
    var at = document.getElementById("argTxt"); if(at) at.focus();
  }

  async function postArg(){
    if(!me || !pickedSide || !curDebate) return;
    var text = (document.getElementById("argTxt")||{}).value||"";
    text = text.trim();
    if(!text) return;
    var r = await api("/debate/"+curDebate.id+"/messages",{method:"POST",body:JSON.stringify({text:text,side:pickedSide})});
    if(r && r.error){ alert(r.error); return; }
    document.getElementById("argTxt").value="";
    document.getElementById("argHint").textContent="0 / 300";
    refreshFeed(curDebate.id);
  }

  async function voteMsg(msgId, value, btn){
    if(!me){ document.getElementById("loginOv").classList.remove("hidden"); return; }
    var r = await api("/messages/"+msgId+"/vote",{method:"POST",body:JSON.stringify({value:value})});
    if(r && r.error && !r.error.includes("own")) alert(r.error);
    if(curDebate) loadVoteArgs(curDebate.id);
  }

  async function quickJoin(){
    var username = document.getElementById("joinUser").value.trim();
    if(!username) return;
    var r = await api("/auth/login",{method:"POST",body:JSON.stringify({username:username})});
    if(r && r.error){ alert(r.error); return; }
    me = r && r.user ? r.user : {username:username};
    document.getElementById("loginOv").classList.add("hidden");
    document.getElementById("navRight").innerHTML = '<span style="font-weight:600;color:var(--text)">'+esc(me.username)+'</span>';
    if(curPhase==="argue" && pickedSide){
      var argSec = document.getElementById("argSection");
      if(argSec) argSec.classList.remove("hidden");
    }
  }

  init();
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