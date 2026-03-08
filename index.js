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
  return res.status(401).json({ error: "Unauthorized" });
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
    "SELECT id, username, display_name, bio, avatar, rating, created_at FROM users WHERE username=$1",
    [username]
  );
  if (!userR.rows[0]) return res.status(404).json({ error: "User not found" });
  const user = userR.rows[0];

  const [statsR, msgsR, rankR] = await Promise.all([
    pool.query(`SELECT
      COUNT(*)::int AS total_args,
      COUNT(CASE WHEN side='YES' THEN 1 END)::int AS yes_args,
      COUNT(CASE WHEN side='NO' THEN 1 END)::int AS no_args,
      COALESCE(SUM(CASE WHEN score>0 THEN score END),0)::int AS total_upvotes,
      COALESCE(MAX(score),0)::int AS best_score
      FROM messages WHERE user_id=$1`, [user.id]),
    pool.query(`SELECT m.id,m.side,m.text,m.score,m.created_at,m.debate_id,d.question
      FROM messages m JOIN debates d ON d.id=m.debate_id
      WHERE m.user_id=$1 ORDER BY m.score DESC,m.created_at DESC LIMIT 10`, [user.id]),
    pool.query(`SELECT COUNT(*)::int+1 AS rank FROM users WHERE rating>$1`, [user.rating])
  ]);

  res.json({ user, stats: statsR.rows[0], top_messages: msgsR.rows, rank: rankR.rows[0].rank });
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

// ─────────────────────────────────────────────────────────
// Error handler
// ─────────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error("🔴", err.message);
  res.status(500).json({ error: "Internal server error" });
});


// Profile update
app.patch("/api/profile", wrap(async(req,res)=>{
  const me = await getMe(req); if(!me) return res.status(401).json({error:"Login first"});
  const display_name = (req.body?.display_name||"").trim().slice(0,40)||null;
  const bio = (req.body?.bio||"").trim().slice(0,200)||null;
  const AVATARS=["⚔️","🔥","🧠","🎯","👑","🌍","⚡","🦁","🐺","🦊","🤖","💎","🥊","🎭","🌊","🦋"];
  const avatar = AVATARS.includes(req.body?.avatar) ? req.body.avatar : null;
  await pool.query(
    "UPDATE users SET display_name=COALESCE($1,display_name), bio=COALESCE($2,bio), avatar=COALESCE($3,avatar) WHERE id=$4",
    [display_name, bio, avatar, me.id]
  );
  res.json({success:true});
}));

app.get("/api/search", wrap(async(req,res)=>{
  const q=(req.query.q||"").trim(); if(!q||q.length<2) return res.json([]);
  const r=await pool.query(
    `SELECT d.id,d.question,d.category,d.type,COUNT(m.id)::int AS arg_count,
     COUNT(CASE WHEN m.side='YES' THEN 1 END)::int AS yes_count,
     COUNT(CASE WHEN m.side='NO' THEN 1 END)::int AS no_count
     FROM debates d LEFT JOIN messages m ON m.debate_id=d.id
     WHERE d.active=TRUE AND d.question ILIKE $1
     GROUP BY d.id ORDER BY arg_count DESC LIMIT 20`,
    ["%"+q+"%"]
  );
  res.json(r.rows);
}));

app.get("/messages/:id/replies", wrap(async(req,res)=>{
  const mid=parseInt(req.params.id,10); if(!Number.isFinite(mid)) return res.status(400).json({error:"Bad id"});
  const r=await pool.query(
    `SELECT m.id,m.side,m.text,m.score,m.created_at,m.parent_id,u.username,
     COALESCE(SUM(CASE WHEN rx.emoji='fire' THEN 1 END),0)::int AS fire_count,
     COALESCE(SUM(CASE WHEN rx.emoji='think' THEN 1 END),0)::int AS think_count,
     COALESCE(SUM(CASE WHEN rx.emoji='idea' THEN 1 END),0)::int AS idea_count
     FROM messages m JOIN users u ON u.id=m.user_id LEFT JOIN reactions rx ON rx.message_id=m.id
     WHERE m.parent_id=$1 GROUP BY m.id,u.username ORDER BY m.created_at ASC LIMIT 50`,
    [mid]
  );
  res.json(r.rows);
}));

app.post("/messages/:id/reply", wrap(async(req,res)=>{
  const me=await getMe(req); if(!me) return res.status(401).json({error:"Login first"});
  const pid=parseInt(req.params.id,10); if(!Number.isFinite(pid)) return res.status(400).json({error:"Bad id"});
  const parent=await pool.query("SELECT debate_id,side FROM messages WHERE id=$1",[pid]);
  if(!parent.rows[0]) return res.status(404).json({error:"Not found"});
  const text=String(req.body?.text||"").trim();
  if(!text) return res.status(400).json({error:"Text required"}); if(text.length>300) return res.status(400).json({error:"Max 300"});
  const did=parent.rows[0].debate_id, side=parent.rows[0].side;
  const r=await pool.query("INSERT INTO messages(debate_id,user_id,side,text,parent_id)VALUES($1,$2,$3,$4,$5)RETURNING id,created_at",[did,me.id,side,text,pid]);
  broadcastDebate(did,"new_reply",{id:r.rows[0].id,debate_id:did,parent_id:pid,username:me.username,side,text,score:0,created_at:r.rows[0].created_at});
  res.status(201).json({success:true,id:r.rows[0].id});
}));

// These are handled in migrate.js, but also guard here at startup:
// display_name, bio, avatar columns

// ─────────────────────────────────────────
// SHARED CSS + JS HELPERS
// ─────────────────────────────────────────
const BASE_CSS = `
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Unbounded:wght@400;600;700;800;900&family=Manrope:wght@400;500;600;700&display=swap" rel="stylesheet"/>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>⚔️</text></svg>"/>
<script>
  // Apply saved theme instantly (no flash)
  if(localStorage.getItem('argu-theme')==='light')document.documentElement.setAttribute('data-theme','light');
</script>
<style>
:root{
  --bg:#09090d;--bg2:#111116;--bg3:#17171d;--bg4:#1e1e26;
  --text:#eaedf3;--text2:#a8b0c4;--muted:#4a5068;--muted2:#6e7a94;
  --border:rgba(255,255,255,.065);--border2:rgba(255,255,255,.13);--border3:rgba(255,255,255,.22);
  --yes:#3b82f6;--yes-dim:rgba(59,130,246,.11);--yes-glow:rgba(59,130,246,.28);
  --no:#ef4444;--no-dim:rgba(239,68,68,.11);--no-glow:rgba(239,68,68,.28);
  --accent:#3b82f6;--gold:#f59e0b;--green:#22c55e;
  --card:var(--bg2);--r:14px;--r2:20px;
  --sh:0 4px 24px rgba(0,0,0,.4);--sh2:0 8px 48px rgba(0,0,0,.6);
}
[data-theme="light"]{
  --bg:#f0f2f8;--bg2:#ffffff;--bg3:#e8eaf2;--bg4:#dde0ec;
  --text:#0d0e14;--text2:#3a3f52;--muted:#9098b0;--muted2:#60677e;
  --border:rgba(0,0,0,.08);--border2:rgba(0,0,0,.14);--border3:rgba(0,0,0,.22);
  --card:#ffffff;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
html{scroll-behavior:smooth;}
body{font-family:'Manrope',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden;-webkit-font-smoothing:antialiased;transition:background .2s,color .2s;}
a{color:inherit;text-decoration:none;}
nav{position:sticky;top:0;z-index:100;border-bottom:1px solid var(--border);background:rgba(9,9,13,.88);backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px);}
[data-theme="light"] nav{background:rgba(240,242,248,.9);}
.nav-inner{max-width:1200px;margin:0 auto;padding:0 22px;height:56px;display:flex;align-items:center;justify-content:space-between;}
.logo{font-family:'Unbounded',sans-serif;font-size:15px;font-weight:900;letter-spacing:-.02em;}
.logo span{color:var(--accent);}
.nav-right{display:flex;align-items:center;gap:12px;}
.nav-link{font-size:13px;color:var(--muted2);font-weight:600;padding:5px 9px;border-radius:8px;transition:all .14s;}
.nav-link:hover,.nav-link.on{color:var(--text);background:var(--bg3);}
.theme-btn{width:32px;height:32px;border-radius:8px;border:1px solid var(--border2);background:var(--bg3);cursor:pointer;font-size:14px;display:flex;align-items:center;justify-content:center;transition:all .16s;}
.theme-btn:hover{border-color:var(--border3);}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;padding:10px 20px;border-radius:11px;border:none;font-family:'Unbounded',sans-serif;font-size:11px;font-weight:700;letter-spacing:.04em;cursor:pointer;transition:all .16s;text-decoration:none;}
.btn-blue{background:var(--accent);color:#fff;} .btn-blue:hover{background:#2563eb;transform:translateY(-1px);}
.btn-out{background:transparent;border:1px solid var(--border2);color:var(--text);} .btn-out:hover{background:var(--bg3);}
.btn-big{padding:14px 28px;border-radius:13px;font-size:12px;}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:20px 22px;}
.pill{display:inline-flex;padding:2px 8px;border-radius:999px;font-size:10px;font-weight:700;letter-spacing:.05em;}
.pill.yes{background:var(--yes-dim);color:var(--yes);border:1px solid rgba(59,130,246,.22);}
.pill.no{background:var(--no-dim);color:var(--no);border:1px solid rgba(239,68,68,.22);}
.skel{background:linear-gradient(90deg,var(--bg3) 25%,var(--bg4) 50%,var(--bg3) 75%);background-size:200% 100%;animation:sk 1.3s ease infinite;border-radius:8px;}
@keyframes sk{0%{background-position:200% 0}100%{background-position:-200% 0}}
#toast-wrap{position:fixed;bottom:64px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:7px;pointer-events:none;}
.toast{padding:12px 16px;border-radius:11px;font-size:13px;font-weight:600;border:1px solid;pointer-events:auto;max-width:300px;animation:tIn .22s ease;box-shadow:var(--sh);}
@keyframes tIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.toast.ok{background:#0d2218;color:var(--green);border-color:rgba(34,197,94,.3);}
.toast.err{background:#200e0e;color:var(--no);border-color:rgba(239,68,68,.3);}
.toast.inf{background:var(--bg2);color:var(--text2);border-color:var(--border2);}
::-webkit-scrollbar{width:5px;} ::-webkit-scrollbar-track{background:transparent;} ::-webkit-scrollbar-thumb{background:var(--bg4);border-radius:999px;}
</style>`;

const SHARED_JS = `
<div id="toast-wrap"></div>
<div id="warmup-banner" style="display:none;position:fixed;top:56px;left:0;right:0;z-index:200;background:#1a1a2e;border-bottom:1px solid rgba(59,130,246,.3);padding:11px 22px;align-items:center;justify-content:center;gap:11px;font-size:13px;color:var(--text2)">
  <svg width="16" height="16" viewBox="0 0 16 16"><circle cx="8" cy="8" r="6" fill="none" stroke="#3b82f6" stroke-width="2" stroke-dasharray="20" stroke-linecap="round"><animateTransform attributeName="transform" type="rotate" from="0 8 8" to="360 8 8" dur="0.9s" repeatCount="indefinite"/></circle></svg>
  <span>Server warming up (free tier cold start ~20s) — retrying automatically…</span>
</div>
<script>
function toast(msg,type){
  var w=document.getElementById('toast-wrap');
  var t=document.createElement('div');
  t.className='toast '+(type==='success'?'ok':type==='error'?'err':'inf');
  t.textContent=msg; w.appendChild(t);
  setTimeout(function(){t.style.opacity='0';t.style.transition='opacity .25s';setTimeout(function(){t.remove();},260);},3000);
}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function ago(ts){var s=Math.floor((Date.now()-new Date(ts))/1000);if(s<60)return s+'s ago';if(s<3600)return Math.floor(s/60)+'m ago';if(s<86400)return Math.floor(s/3600)+'h ago';return Math.floor(s/86400)+'d ago';}
function badge(r){if(r>=500)return'💎';if(r>=200)return'🥇';if(r>=100)return'🥈';if(r>=25)return'🥉';return'';}
async function api(url,opts){
  // Try up to 3 times with increasing timeouts for cold starts
  var delays=[10000,25000,45000];
  for(var attempt=0;attempt<delays.length;attempt++){
    var ctrl=new AbortController();
    var tid=setTimeout(function(){ctrl.abort();},delays[attempt]);
    try{
      var r=await fetch(url,Object.assign({credentials:'same-origin',headers:{'content-type':'application/json'},signal:ctrl.signal},opts||{}));
      clearTimeout(tid);
      // Hide warmup banner on success
      var wb=document.getElementById('warmup-banner');
      if(wb) wb.style.display='none';
      var t=await r.text();
      try{return JSON.parse(t);}catch(e){return{error:'Parse error'};}
    }catch(e){
      clearTimeout(tid);
      if(e.name!=='AbortError') return null;
      if(attempt<delays.length-1){
        // Show warmup banner during retry
        var wb2=document.getElementById('warmup-banner');
        if(wb2) wb2.style.display='flex';
        await new Promise(function(res){setTimeout(res,500);});
      }
    }
  }
  return null;
}
function toggleTheme(){
  var isL=document.documentElement.getAttribute('data-theme')==='light';
  document.documentElement.setAttribute('data-theme',isL?'dark':'light');
  localStorage.setItem('argu-theme',isL?'dark':'light');
  var btn=document.getElementById('themeBtn');
  if(btn)btn.textContent=isL?'☀️':'🌙';
}
window.addEventListener('DOMContentLoaded',function(){
  var isL=document.documentElement.getAttribute('data-theme')==='light';
  var btn=document.getElementById('themeBtn');
  if(btn)btn.textContent=isL?'🌙':'☀️';
});
<\/script>`;

// ─────────────────────────────────────────
// LANDING PAGE
// ─────────────────────────────────────────
function landingPage(){
return `<!doctype html><html lang="en">
<head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ARGU — Pick a side. Win the argument.</title>
<meta name="description" content="Real debates. Real stakes. The crowd decides who wins."/>
${BASE_CSS}
<style>
body{padding-bottom:46px;}
.page{max-width:1100px;margin:0 auto;padding:0 22px;position:relative;z-index:1;}
.glow{position:fixed;top:-10%;left:50%;transform:translateX(-50%);width:900px;height:600px;background:radial-gradient(ellipse,rgba(59,130,246,.055) 0%,transparent 68%);pointer-events:none;z-index:0;}
/* Hero */
.hero{min-height:88vh;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:60px 0 32px;}
.hero-badge{display:inline-flex;align-items:center;gap:6px;font-size:10px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--accent);border:1px solid rgba(59,130,246,.28);background:rgba(59,130,246,.07);padding:6px 14px;border-radius:999px;margin-bottom:28px;}
.ldot{width:7px;height:7px;border-radius:50%;background:var(--accent);animation:ld 1.3s infinite;display:inline-block;}
@keyframes ld{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.3;transform:scale(.7)}}
h1.hero-title{font-family:'Unbounded',sans-serif;font-size:clamp(42px,8vw,96px);font-weight:900;letter-spacing:-.04em;line-height:.95;margin-bottom:26px;}
h1.hero-title .y{color:var(--yes);} h1.hero-title .n{color:var(--no);}
.hero-sub{font-size:clamp(15px,2vw,19px);color:var(--text2);max-width:440px;line-height:1.65;margin-bottom:0;font-weight:500;}
/* Quick widget */
.widget-wrap{width:100%;max-width:500px;margin:28px 0;}
.widget{background:var(--card);border:1px solid var(--border2);border-radius:22px;padding:26px 24px;box-shadow:var(--sh);}
.widget-q{font-family:'Unbounded',sans-serif;font-size:16px;font-weight:700;line-height:1.32;margin-bottom:20px;}
.wbtns{display:flex;gap:9px;margin-bottom:11px;}
.wbtn{flex:1;padding:14px;border-radius:13px;border:2px solid;font-family:'Unbounded',sans-serif;font-size:12px;font-weight:700;cursor:pointer;transition:all .16s;}
.wbtn-y{border-color:rgba(59,130,246,.32);background:var(--yes-dim);color:var(--yes);}
.wbtn-y:hover,.wbtn-y.on{border-color:var(--yes);background:var(--yes);color:#fff;box-shadow:0 0 22px var(--yes-glow);}
.wbtn-n{border-color:rgba(239,68,68,.32);background:var(--no-dim);color:var(--no);}
.wbtn-n:hover,.wbtn-n.on{border-color:var(--no);background:var(--no);color:#fff;box-shadow:0 0 22px var(--no-glow);}
.widget-hint{font-size:11px;color:var(--muted);text-align:center;}
/* Ticker */
.ticker{position:fixed;bottom:0;left:0;right:0;z-index:99;background:var(--bg2);border-top:1px solid var(--border);padding:9px 0;overflow:hidden;}
.ticker-track{display:flex;gap:52px;animation:scroll 35s linear infinite;white-space:nowrap;width:max-content;}
.ticker-track:hover{animation-play-state:paused;}
@keyframes scroll{from{transform:translateX(0)}to{transform:translateX(-50%)}}
.ticker-item{display:inline-flex;align-items:center;gap:7px;font-size:12px;color:var(--text2);}
.tdot{width:4px;height:4px;border-radius:50%;background:var(--accent);flex-shrink:0;}
/* Stats */
.stats-band{border-top:1px solid var(--border);border-bottom:1px solid var(--border);padding:48px 0;background:linear-gradient(135deg,rgba(59,130,246,.04),rgba(99,102,241,.04));}
.stats-inner{max-width:640px;margin:0 auto;display:flex;justify-content:center;gap:56px;flex-wrap:wrap;padding:0 22px;}
.stat-n{font-family:'Unbounded',sans-serif;font-size:48px;font-weight:900;line-height:1;background:linear-gradient(135deg,var(--text),var(--text2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
.stat-l{font-size:10px;color:var(--muted);margin-top:6px;letter-spacing:.12em;text-transform:uppercase;font-weight:700;text-align:center;}
/* Hot takes */
.hot-section{padding:80px 0 0;}
.section-tag{font-size:10px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:var(--accent);margin-bottom:12px;text-align:center;}
.section-h{font-family:'Unbounded',sans-serif;font-size:clamp(22px,4vw,40px);font-weight:800;letter-spacing:-.025em;text-align:center;margin-bottom:48px;line-height:1.12;}
.debates-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(272px,1fr));gap:11px;}
.dcard{background:var(--card);border:1px solid var(--border);border-radius:18px;padding:18px 20px;transition:all .18s;display:block;color:inherit;}
.dcard:hover{border-color:var(--border2);transform:translateY(-3px);box-shadow:var(--sh);}
.dcard-type{font-size:9px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;margin-bottom:8px;}
.dcard-type.ev{color:var(--gold);} .dcard-type.qu{color:var(--accent);}
.dcard-q{font-family:'Unbounded',sans-serif;font-size:12px;font-weight:700;line-height:1.35;margin-bottom:12px;}
.dcard-bar{height:3px;background:var(--bg4);border-radius:999px;overflow:hidden;}
.dcard-yes{height:100%;background:linear-gradient(90deg,var(--yes),#6366f1);border-radius:999px;}
.dcard-nums{display:flex;justify-content:space-between;font-size:10px;font-weight:700;margin-top:6px;}
/* CTA */
.cta-block{text-align:center;padding:80px 0 90px;}
.cta-block h2{font-family:'Unbounded',sans-serif;font-size:clamp(24px,4vw,48px);font-weight:900;letter-spacing:-.03em;margin-bottom:14px;line-height:1.06;}
.cta-block p{font-size:16px;color:var(--text2);margin-bottom:32px;}
/* How it works */
.how-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:12px;}
.how-card{background:var(--card);border:1px solid var(--border);border-radius:18px;padding:24px 22px;transition:all .18s;}
.how-card:hover{border-color:var(--border2);transform:translateY(-2px);}
.how-icon{font-size:28px;margin-bottom:12px;}
.how-title{font-family:'Unbounded',sans-serif;font-size:12px;font-weight:700;margin-bottom:8px;}
.how-desc{font-size:13px;color:var(--text2);line-height:1.62;}
footer{border-top:1px solid var(--border);padding:22px;text-align:center;font-size:12px;color:var(--muted);}
.hero-ctas{display:flex;align-items:center;gap:10px;flex-wrap:wrap;justify-content:center;margin-top:28px;}
</style>
</head>
<body>
${SHARED_JS}
<div class="glow"></div>
<nav><div class="nav-inner">
  <a class="logo" href="/">ARGU<span>.</span></a>
  <div class="nav-right">
    <a class="nav-link" href="/explore">Debates</a>
    <a class="nav-link" href="/live">⚡ Live</a>
    <button class="theme-btn" id="themeBtn" onclick="toggleTheme()">☀️</button>
    <div id="navAuth"></div>
  </div>
</div></nav>
<div class="page">
  <div class="hero">
    <div class="hero-badge"><span class="ldot"></span>Live debates happening now</div>
    <h1 class="hero-title">The world<br>says <span class="y">YES</span><br>or <span class="n">NO</span></h1>
    <p class="hero-sub">Pick a side. Make your case in one sharp argument. Let the crowd vote on who wins.</p>
    <div class="widget-wrap">
      <div class="widget" id="widget">
        <div style="display:flex;flex-direction:column;gap:10px">
          <div class="skel" style="height:20px;width:85%"></div>
          <div class="skel" style="height:20px;width:60%"></div>
          <div style="display:flex;gap:9px;margin-top:8px">
            <div class="skel" style="height:50px;flex:1;border-radius:13px"></div>
            <div class="skel" style="height:50px;flex:1;border-radius:13px"></div>
          </div>
        </div>
      </div>
    </div>
    <div class="hero-ctas">
      <a href="/explore" class="btn btn-blue btn-big">Browse all debates →</a>
      <a href="/live" class="btn btn-out btn-big">⚡ Live now</a>
    </div>
  </div>
</div>

<div class="ticker" id="tickerWrap">
  <div class="ticker-track" id="tickerTrack">
    ${["Is college a scam?","Should billionaires exist?","Will AI replace programmers?","Is democracy failing?","Is hustle culture toxic?","Should AI have legal rights?","Is capitalism broken?","Is remote work better?","Should social media be banned for kids?","Is freedom of speech absolute?","Is happiness more important than success?","Are smartphones destroying attention spans?"].flatMap(q=>[q,q]).map(q=>`<span class="ticker-item"><span class="tdot"></span>${esc(q)}</span>`).join("")}
  </div>
</div>

<div class="stats-band">
  <div class="stats-inner">
    <div><div class="stat-n" id="sD">—</div><div class="stat-l">Debates</div></div>
    <div><div class="stat-n" id="sA">—</div><div class="stat-l">Arguments</div></div>
    <div><div class="stat-n" id="sU">—</div><div class="stat-l">Debaters</div></div>
  </div>
</div>

<div class="page">
  <div class="hot-section">
    <div class="section-tag">🔥 Trending</div>
    <h2 class="section-h">Jump into a debate</h2>
    <div class="debates-grid" id="preGrid">
      ${Array(6).fill(0).map(()=>`<div style="background:var(--card);border:1px solid var(--border);border-radius:18px;padding:18px 20px"><div class="skel" style="height:11px;width:35%;margin-bottom:9px"></div><div class="skel" style="height:15px;width:92%;margin-bottom:5px"></div><div class="skel" style="height:15px;width:72%;margin-bottom:12px"></div><div class="skel" style="height:3px;border-radius:999px"></div></div>`).join("")}
    </div>
    <div style="text-align:center;margin-top:28px">
      <a href="/explore" class="btn btn-out btn-big">See all debates →</a>
    </div>
  </div>

  <div style="padding:80px 0 0">
    <div class="section-tag">How it works</div>
    <h2 class="section-h">Debate like it matters.</h2>
    <div class="how-grid">
      <div class="how-card"><div class="how-icon">🌍</div><div class="how-title">Real events & questions</div><div class="how-desc">Breaking world events and the biggest questions humanity keeps arguing about.</div></div>
      <div class="how-card"><div class="how-icon">⚔️</div><div class="how-title">Pick your side</div><div class="how-desc">Every debate is binary — YES or NO. No fence-sitting. Choose and defend it.</div></div>
      <div class="how-card"><div class="how-icon">🗳️</div><div class="how-title">The crowd votes</div><div class="how-desc">Others vote your argument up or down. The best arguments rise to the top.</div></div>
      <div class="how-card"><div class="how-icon">👑</div><div class="how-title">Build your reputation</div><div class="how-desc">Earn rating from upvotes. Your vote weight grows — become a top voice.</div></div>
    </div>
  </div>

  <div class="cta-block">
    <h2>The world is arguing.<br>Where do you stand?</h2>
    <p>Real questions. Unfiltered arguments. The crowd decides.</p>
    <div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap">
      <a href="/explore" class="btn btn-blue btn-big">Start debating →</a>
      <a href="/live" class="btn btn-out btn-big">⚡ Watch live</a>
    </div>
  </div>
</div>

<footer>ARGU. — Where the world debates &nbsp;·&nbsp; <a href="/explore" style="color:var(--text2)">Debates</a> &nbsp;·&nbsp; <a href="/live" style="color:var(--text2)">Live</a></footer>

<script>
var qDebate=null, qSide=null;

async function loadNav(){
  var d=await api('/me'); var me=d&&d.user;
  var el=document.getElementById('navAuth');
  if(!me){el.innerHTML='<a href="/explore" class="btn btn-blue" style="padding:8px 16px;font-size:10px">Join</a>';}
  else{var b=badge(me.rating);el.innerHTML='<a href="/u/'+esc(me.username)+'" class="nav-link" style="display:flex;align-items:center;gap:5px"><strong>'+esc(me.username)+'</strong>'+(b?'<span>'+b+'</span>':'')+'<span style="color:var(--gold);font-size:11px">★'+me.rating+'</span></a>';}
}

async function loadStats(){
  var debates=null;
  for(var i=0;i<3;i++){
    debates=await api('/api/debates?sort=hot');
    if(debates&&debates.length) break;
    if(i<2) await new Promise(function(r){setTimeout(r,3000);});
  }
  var wb=document.getElementById('warmup-banner');if(wb)wb.style.display='none';
  if(!debates||!debates.length){
    document.getElementById('widget').innerHTML='<div style="text-align:center;padding:20px;color:var(--muted);font-size:13px">Could not load — <button onclick="loadStats()" style="color:var(--accent);border:none;background:none;cursor:pointer;font-size:13px">retry</button></div>';
    document.getElementById('preGrid').innerHTML='<div style="color:var(--muted);font-size:13px;text-align:center;padding:24px;grid-column:1/-1">Could not load debates — <button onclick="loadStats()" style="color:var(--accent);border:none;background:none;cursor:pointer;font-size:13px">retry</button></div>';
    return;
  }
  var totalArgs=debates.reduce(function(s,d){return s+(d.arg_count||0);},0);
  document.getElementById('sD').textContent=debates.length;
  document.getElementById('sA').textContent=totalArgs>=1000?(Math.round(totalArgs/100)/10)+'k':totalArgs;
  var lb=await api('/leaderboard/users?limit=1000');
  if(lb) document.getElementById('sU').textContent=lb.length;

  // Update ticker with real debates
  var names=debates.map(function(d){return d.question;}).slice(0,12);
  var doubled=names.concat(names);
  document.getElementById('tickerTrack').innerHTML=doubled.map(function(q){return '<span class="ticker-item"><span class="tdot"></span>'+esc(q)+'</span>';}).join('');

  var top=debates.slice(0,6);
  document.getElementById('preGrid').innerHTML=top.map(function(d){
    var total=d.yes_count+d.no_count, yp=total>0?Math.round(d.yes_count/total*100):50;
    var tl=d.type==='event'?'🌍 Event':'💭 Question';
    return '<a class="dcard" href="/debate/'+d.id+'"><div class="dcard-type '+(d.type==='event'?'ev':'qu')+'">'+tl+'</div><div class="dcard-q">'+esc(d.question)+'</div><div class="dcard-nums"><span style="color:var(--yes)">YES '+yp+'%</span><span style="color:var(--muted)">'+d.arg_count+' args</span><span style="color:var(--no)">'+(100-yp)+'% NO</span></div><div class="dcard-bar"><div class="dcard-yes" style="width:'+yp+'%"></div></div></a>';
  }).join('');

  // Pick random debate for widget
  qDebate=debates[Math.floor(Math.random()*Math.min(debates.length,10))];
  renderWidget('pick');
}

function renderWidget(step){
  var w=document.getElementById('widget'); if(!w||!qDebate) return;
  var d=qDebate, total=d.yes_count+d.no_count;
  if(step==='pick'){
    w.innerHTML='<div class="widget-q">'+esc(d.question)+'</div>'
      +'<div class="wbtns"><button class="wbtn wbtn-y" onclick="pickSide(\'YES\')">✓ YES</button><button class="wbtn wbtn-n" onclick="pickSide(\'NO\')">✗ NO</button></div>'
      +'<div class="widget-hint">'+total.toLocaleString()+' people have weighed in · <a href="/debate/'+d.id+'" style="color:var(--accent)">See all →</a></div>';
  }else if(step==='write'){
    var sc=qSide==='YES'?'var(--yes)':'var(--no)', bg=qSide==='YES'?'var(--yes-dim)':'var(--no-dim)';
    w.innerHTML='<div style="display:flex;align-items:center;gap:8px;margin-bottom:14px"><span style="font-size:10px;font-weight:700;padding:3px 10px;border-radius:999px;background:'+bg+';color:'+sc+';border:1px solid '+sc+'">'+qSide+'</span><span class="widget-q" style="margin:0;font-size:13px">'+esc(d.question)+'</span></div>'
      +'<textarea id="wTa" placeholder="Your argument… (max 300)" maxlength="300" style="width:100%;min-height:78px;padding:11px 13px;border-radius:11px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-family:\'Manrope\',sans-serif;font-size:13px;resize:none;outline:none;transition:border-color .16s" onfocus="this.style.borderColor=\'rgba(59,130,246,.5)\'" onblur="this.style.borderColor=\'var(--border)\'"></textarea>'
      +'<div style="display:flex;justify-content:space-between;align-items:center;margin-top:9px"><span id="wHint" style="font-size:11px;color:var(--muted)">0/300</span><div style="display:flex;gap:7px"><button onclick="renderWidget(\'pick\')" style="padding:8px 14px;border-radius:9px;border:1px solid var(--border);background:transparent;color:var(--muted2);font-size:12px;cursor:pointer">← Back</button><button onclick="submitWidget()" style="padding:8px 20px;border-radius:9px;border:none;background:var(--accent);color:#fff;font-family:\'Unbounded\',sans-serif;font-size:10px;font-weight:700;cursor:pointer">Post →</button></div></div>';
    setTimeout(function(){var t=document.getElementById('wTa');if(t){t.focus();t.addEventListener('input',function(){var h=document.getElementById('wHint');if(h)h.textContent=t.value.length+'/300';});}},50);
  }else if(step==='login'){
    var sc2=qSide==='YES'?'var(--yes)':'var(--no)';
    w.innerHTML='<div style="margin-bottom:14px"><div style="font-family:\'Unbounded\',sans-serif;font-size:13px;font-weight:700;margin-bottom:5px">You picked <span style="color:'+sc2+'">'+qSide+'</span></div><div style="font-size:12px;color:var(--muted2)">Create a free account to post</div></div>'
      +'<a href="/auth/google" style="display:flex;align-items:center;justify-content:center;gap:7px;padding:11px;border-radius:11px;border:1px solid var(--border2);background:var(--bg3);color:var(--text);font-size:13px;font-weight:600;text-decoration:none;margin-bottom:10px">'+gIcon()+'Continue with Google</a>'
      +'<div style="display:flex;align-items:center;gap:7px;margin-bottom:9px"><div style="flex:1;height:1px;background:var(--border)"></div><span style="font-size:11px;color:var(--muted)">or</span><div style="flex:1;height:1px;background:var(--border)"></div></div>'
      +'<div style="display:flex;gap:7px"><input id="wUser" placeholder="choose a username…" maxlength="20" style="flex:1;padding:10px 12px;border-radius:9px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-size:13px;outline:none"/><button onclick="widgetLogin()" style="padding:10px 18px;border-radius:9px;border:none;background:var(--accent);color:#fff;font-family:\'Unbounded\',sans-serif;font-size:10px;font-weight:700;cursor:pointer">Join →</button></div>';
  }else if(step==='done'){
    w.innerHTML='<div style="text-align:center;padding:14px 0"><div style="font-size:34px;margin-bottom:12px">🔥</div><div style="font-family:\'Unbounded\',sans-serif;font-size:15px;font-weight:700;margin-bottom:7px">Argument posted!</div><div style="font-size:13px;color:var(--text2);margin-bottom:20px">Others are already reading it.</div><a href="/debate/'+d.id+'" class="btn btn-blue">See the debate →</a></div>';
  }
}

function gIcon(){return '<svg width="15" height="15" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.31-8.16 2.31-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>';}

function pickSide(s){qSide=s;api('/me').then(function(d){if(d&&d.user)renderWidget('write');else renderWidget('login');});}
async function widgetLogin(){var u=(document.getElementById('wUser')||{}).value||'';if(!u.trim())return;var r=await api('/auth/login',{method:'POST',body:JSON.stringify({username:u.trim()})});if(r&&r.error){toast(r.error,'error');return;}renderWidget('write');loadNav();}
async function submitWidget(){var t=(document.getElementById('wTa')||{}).value||'';if(!t.trim())return;var r=await api('/debate/'+qDebate.id+'/messages',{method:'POST',body:JSON.stringify({text:t.trim(),side:qSide})});if(r&&r.error){toast(r.error,'error');return;}renderWidget('done');toast('Argument posted! 🔥','success');}

loadNav(); loadStats();
</script></body></html>`;
}

// ─────────────────────────────────────────
// EXPLORE PAGE
// ─────────────────────────────────────────
function explorePage(){
return `<!doctype html><html lang="en">
<head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Explore — ARGU</title>
${BASE_CSS}
<style>
body{padding-bottom:46px;}
.page{max-width:1200px;margin:0 auto;padding:30px 22px 60px;position:relative;z-index:1;}
.top-bar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:22px;}
.search-wrap{flex:1;min-width:180px;max-width:340px;position:relative;}
.si{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--muted);pointer-events:none;}
.search-in{width:100%;padding:10px 13px 10px 36px;border-radius:11px;border:1px solid var(--border);background:var(--bg2);color:var(--text);font-family:'Manrope',sans-serif;font-size:13px;outline:none;transition:border-color .16s;}
.search-in:focus{border-color:rgba(59,130,246,.45);}
.search-in::placeholder{color:var(--muted);}
.sort-tabs{display:flex;gap:3px;background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:3px;}
.stab{padding:7px 13px;border-radius:8px;font-size:11px;font-weight:700;cursor:pointer;color:var(--muted2);border:none;background:transparent;transition:all .13s;white-space:nowrap;}
.stab.on{background:var(--bg3);color:var(--text);border:1px solid var(--border2);}
.filter-row{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:20px;}
.fbtn{padding:5px 13px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid var(--border);background:transparent;color:var(--muted2);cursor:pointer;transition:all .13s;}
.fbtn.on{background:var(--bg3);border-color:var(--border2);color:var(--text);}
.fbtn:hover{border-color:var(--border2);color:var(--text);}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:20px;align-items:start;}
@media(max-width:680px){.cols{grid-template-columns:1fr;}}
.col-hdr{display:flex;align-items:center;gap:9px;margin-bottom:16px;padding-bottom:13px;border-bottom:1px solid var(--border);}
.col-icon{font-size:18px;}
.col-title{font-family:'Unbounded',sans-serif;font-size:12px;font-weight:800;}
.col-title.ev{color:var(--gold);} .col-title.qu{color:var(--accent);}
.col-sub{font-size:10px;color:var(--muted);margin-top:1px;}
.dcard{background:var(--card);border:1px solid var(--border);border-radius:15px;padding:16px 18px;margin-bottom:9px;transition:all .16s;display:block;color:inherit;}
.dcard:hover{border-color:var(--border2);transform:translateY(-2px);box-shadow:var(--sh);}
.dcard-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:9px;}
.ctag{font-size:9px;font-weight:700;letter-spacing:.09em;text-transform:uppercase;padding:3px 8px;border-radius:999px;}
.ctag.ev{color:var(--gold);background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.22);}
.ctag.qu{color:var(--accent);background:var(--yes-dim);border:1px solid rgba(59,130,246,.18);}
.arg-ct{font-size:11px;color:var(--muted);}
.dcard-q{font-family:'Unbounded',sans-serif;font-size:12px;font-weight:700;line-height:1.32;margin-bottom:11px;}
.dcard-bar{height:3px;background:var(--bg4);border-radius:999px;overflow:hidden;}
.dcard-yes{height:100%;background:linear-gradient(90deg,var(--yes),#6366f1);border-radius:999px;}
.dcard-nums{display:flex;justify-content:space-between;font-size:9px;font-weight:700;margin-top:5px;}
.dcard-cta{margin-top:10px;padding:8px;border-radius:8px;text-align:center;background:var(--bg3);font-size:11px;font-weight:600;color:var(--muted2);transition:all .16s;border:1px solid transparent;}
.dcard:hover .dcard-cta{background:var(--accent);color:#fff;border-color:var(--accent);}
.empty-col{text-align:center;padding:40px 20px;color:var(--muted);font-size:13px;background:var(--bg2);border:1px dashed var(--border2);border-radius:15px;}
.empty-col a{color:var(--accent);}
.auth-strip{background:var(--card);border:1px solid var(--border);border-radius:13px;padding:13px 16px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:24px;}
.auth-in{padding:9px 12px;border-radius:9px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-family:'Manrope',sans-serif;font-size:13px;outline:none;width:160px;transition:border-color .16s;}
.auth-in:focus{border-color:rgba(59,130,246,.45);}
.auth-in::placeholder{color:var(--muted);}
#srBox{margin-bottom:18px;display:none;}
.sr-label{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:11px;}
.highlight{background:rgba(59,130,246,.18);color:var(--yes);border-radius:3px;padding:0 2px;}
.ticker{position:fixed;bottom:0;left:0;right:0;z-index:99;background:var(--bg2);border-top:1px solid var(--border);padding:9px 0;overflow:hidden;}
.ticker-track{display:flex;gap:52px;animation:scroll 35s linear infinite;white-space:nowrap;width:max-content;}
@keyframes scroll{from{transform:translateX(0)}to{transform:translateX(-50%)}}
.ticker-item{display:inline-flex;align-items:center;gap:7px;font-size:12px;color:var(--text2);}
.tdot{width:4px;height:4px;border-radius:50%;background:var(--accent);flex-shrink:0;}
.ticker-track:hover{animation-play-state:paused;}
/* Page title */
.arena-hdr{margin-bottom:22px;}
.arena-title{font-family:'Unbounded',sans-serif;font-size:28px;font-weight:900;letter-spacing:-.02em;margin-bottom:5px;}
.arena-sub{font-size:13px;color:var(--text2);}
</style>
</head>
<body>
${SHARED_JS}
<nav><div class="nav-inner">
  <a class="logo" href="/">ARGU<span>.</span></a>
  <div class="nav-right" id="navRight">
    <button class="theme-btn" id="themeBtn" onclick="toggleTheme()">☀️</button>
  </div>
</div></nav>
<div class="page">
  <div class="auth-strip" id="authStrip"><span style="font-size:13px;color:var(--muted)">Loading…</span></div>
  <div class="arena-hdr">
    <div class="arena-title">The Arena</div>
    <div class="arena-sub">World events on the left. Timeless questions on the right. Pick a debate and make your case.</div>
  </div>
  <div class="top-bar">
    <div class="search-wrap">
      <span class="si">🔍</span>
      <input class="search-in" id="srIn" placeholder="Search debates…" maxlength="80" autocomplete="off"/>
    </div>
    <div class="sort-tabs">
      <button class="stab on" data-s="hot">🔥 Hot</button>
      <button class="stab" data-s="new">✨ New</button>
      <button class="stab" data-s="top">📈 Top</button>
    </div>
  </div>
  <div class="filter-row" id="filterRow"></div>
  <div id="srBox"><div class="sr-label" id="srLabel"></div><div id="srGrid"></div></div>
  <div id="mainCols">
    <div class="cols">
      <div>
        <div class="col-hdr"><span class="col-icon">🌍</span><div><div class="col-title ev">World Events</div><div class="col-sub">Breaking topics · current affairs</div></div></div>
        <div id="evCol">${Array(2).fill(0).map(()=>`<div style="background:var(--card);border:1px solid var(--border);border-radius:15px;padding:16px 18px;margin-bottom:9px"><div class="skel" style="height:11px;width:30%;margin-bottom:10px"></div><div class="skel" style="height:14px;width:90%;margin-bottom:5px"></div><div class="skel" style="height:14px;width:65%;margin-bottom:12px"></div><div class="skel" style="height:3px;border-radius:999px"></div></div>`).join('')}</div>
      </div>
      <div>
        <div class="col-hdr"><span class="col-icon">💭</span><div><div class="col-title qu">Questions</div><div class="col-sub">Society · life · the future</div></div></div>
        <div id="quCol">${Array(3).fill(0).map(()=>`<div style="background:var(--card);border:1px solid var(--border);border-radius:15px;padding:16px 18px;margin-bottom:9px"><div class="skel" style="height:11px;width:30%;margin-bottom:10px"></div><div class="skel" style="height:14px;width:90%;margin-bottom:5px"></div><div class="skel" style="height:14px;width:65%;margin-bottom:12px"></div><div class="skel" style="height:3px;border-radius:999px"></div></div>`).join('')}</div>
      </div>
    </div>
  </div>
</div>

<div class="ticker">
  <div class="ticker-track" id="tickerT">
    ${["Is college a scam?","Should billionaires exist?","Will AI replace programmers?","Is democracy failing?","Is hustle culture toxic?","Should AI have legal rights?","Is capitalism broken?","Is remote work better?","Should social media be banned for kids?","Is freedom of speech absolute?"].flatMap(q=>[q,q]).map(q=>`<span class="ticker-item"><span class="tdot"></span>${esc(q)}</span>`).join('')}
  </div>
</div>

<script>
var allDebates=[], curCat='All', curSort='hot', srTimer=null;

function dCard(d, sq){
  var total=d.yes_count+d.no_count, yp=total>0?Math.round(d.yes_count/total*100):50;
  var t=d.type||'question', cls=t==='event'?'ev':'qu';
  var q=esc(d.question);
  if(sq){var esc2=sq.replace(/[-[\]{}()*+?.,\\^$|#]/g,'\\$&');var re=new RegExp('('+esc2+')','gi');q=q.replace(re,'<mark class="highlight">$1</mark>');}
  return '<a class="dcard" href="/debate/'+d.id+'">'
    +'<div class="dcard-top"><span class="ctag '+cls+'">'+esc(d.category)+'</span><span class="arg-ct">'+d.arg_count+' args</span></div>'
    +'<div class="dcard-q">'+q+'</div>'
    +'<div class="dcard-bar"><div class="dcard-yes" style="width:'+yp+'%"></div></div>'
    +'<div class="dcard-nums"><span style="color:var(--yes)">YES '+yp+'%</span><span style="color:var(--no)">'+(100-yp)+'% NO</span></div>'
    +'<div class="dcard-cta">Debate this →</div></a>';
}

function renderCols(){
  var ca=curCat==='All';
  var evs=allDebates.filter(function(d){return (d.type||'question')==='event'&&(ca||d.category===curCat);});
  var qus=allDebates.filter(function(d){return (d.type||'question')==='question'&&(ca||d.category===curCat);});
  document.getElementById('evCol').innerHTML=evs.length
    ?evs.map(function(d){return dCard(d);}).join('')
    :'<div class="empty-col">No world events yet.<br><br>Add some in the <a href="/admin">admin panel</a> with type "Event".</div>';
  document.getElementById('quCol').innerHTML=qus.length
    ?qus.map(function(d){return dCard(d);}).join('')
    :'<div class="empty-col">No questions found for this filter.</div>';
}

function buildFilters(){
  var cats=['All'].concat([...new Set(allDebates.map(function(d){return d.category;}))]);
  document.getElementById('filterRow').innerHTML=cats.map(function(c){
    return '<button class="fbtn '+(c===curCat?'on':'')+'" data-cat="'+esc(c)+'">'+esc(c)+'</button>';
  }).join('');
  document.getElementById('filterRow').querySelectorAll('.fbtn').forEach(function(b){
    b.addEventListener('click',function(){
      curCat=b.getAttribute('data-cat');
      document.querySelectorAll('.fbtn').forEach(function(x){x.classList.toggle('on',x.getAttribute('data-cat')===curCat);});
      renderCols();
    });
  });
}

async function loadDebates(){
  var data=await api('/api/debates?sort='+curSort);
  var wb=document.getElementById('warmup-banner');if(wb)wb.style.display='none';
  if(!data){
    document.getElementById('evCol').innerHTML='<div class="empty-col">Could not connect — <a href="#" onclick="loadDebates();return false;" style="color:var(--accent)">retry</a></div>';
    document.getElementById('quCol').innerHTML='<div class="empty-col">Could not connect — <a href="#" onclick="loadDebates();return false;" style="color:var(--accent)">retry</a></div>';
    return;
  }
  allDebates=data; buildFilters(); renderCols();
}

document.querySelectorAll('.stab').forEach(function(btn){
  btn.addEventListener('click',function(){
    curSort=btn.getAttribute('data-s');
    document.querySelectorAll('.stab').forEach(function(b){b.classList.toggle('on',b===btn);});
    loadDebates();
  });
});

var srIn=document.getElementById('srIn');
srIn.addEventListener('input',function(){
  clearTimeout(srTimer); var q=srIn.value.trim();
  if(!q){document.getElementById('srBox').style.display='none';document.getElementById('mainCols').style.display='block';return;}
  srTimer=setTimeout(async function(){
    if(q.length<2) return;
    var results=await api('/api/search?q='+encodeURIComponent(q))||[];
    document.getElementById('mainCols').style.display='none';
    var sb=document.getElementById('srBox'); sb.style.display='block';
    document.getElementById('srLabel').textContent=results.length+' result'+(results.length!==1?'s':'')+' for "'+q+'"';
    document.getElementById('srGrid').innerHTML=results.length
      ?'<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:11px">'+results.map(function(d){return dCard(d,q);}).join('')+'</div>'
      :'<div class="empty-col">No results for "'+esc(q)+'"</div>';
  },280);
});
srIn.addEventListener('keydown',function(e){if(e.key==='Escape'){srIn.value='';srIn.dispatchEvent(new Event('input'));}});

async function loadNav(){
  var d=await api('/me'); var me=d&&d.user;
  var nr=document.getElementById('navRight'), strip=document.getElementById('authStrip');
  if(!me){
    nr.innerHTML='<button class="theme-btn" id="themeBtn" onclick="toggleTheme()">☀️</button>';
    window.addEventListener('DOMContentLoaded',function(){var b=document.getElementById('themeBtn');if(b)b.textContent=document.documentElement.getAttribute('data-theme')==='light'?'🌙':'☀️';});
    strip.innerHTML='<a href="/auth/google" style="display:inline-flex;align-items:center;gap:7px;padding:9px 15px;border-radius:10px;border:1px solid var(--border2);background:var(--bg3);color:var(--text);font-size:13px;font-weight:600;text-decoration:none">'+gIcon()+'Continue with Google</a><span style="font-size:12px;color:var(--muted)">or:</span><input class="auth-in" id="usIn" placeholder="username…" maxlength="20"/><button class="btn btn-blue" id="joinBtn" style="padding:9px 16px;font-size:10px">Join</button><span style="font-size:11px;color:var(--muted);margin-left:auto">Sign in to post & vote</span>';
    document.getElementById('joinBtn').addEventListener('click',async function(){
      var u=document.getElementById('usIn').value.trim(); if(!u) return;
      var r=await api('/auth/login',{method:'POST',body:JSON.stringify({username:u})});
      if(r&&r.error){toast(r.error,'error');return;}
      toast('Welcome, '+r.user.username+'! 👋','success'); await loadNav();
    });
  }else{
    var b=badge(me.rating);
    nr.innerHTML='<a href="/u/'+esc(me.username)+'" class="nav-link" style="display:flex;align-items:center;gap:5px"><strong>'+esc(me.username)+'</strong>'+(b?'<span>'+b+'</span>':'')+'</a><span style="color:var(--gold);font-size:12px">★'+me.rating+'</span><button class="theme-btn" id="themeBtn" onclick="toggleTheme()">☀️</button>';
    window.addEventListener('DOMContentLoaded',function(){var btn=document.getElementById('themeBtn');if(btn)btn.textContent=document.documentElement.getAttribute('data-theme')==='light'?'🌙':'☀️';});
    strip.innerHTML='<span style="font-size:13px">👋 <strong>'+esc(me.username)+'</strong> <span style="color:var(--gold)">'+b+' ★ '+me.rating+' pts</span></span><a href="/u/'+esc(me.username)+'" class="btn btn-out" style="margin-left:auto;padding:7px 14px;font-size:11px">Profile</a><button class="btn btn-out" id="logoutBtn" style="padding:7px 14px;font-size:11px">Sign out</button>';
    document.getElementById('logoutBtn').addEventListener('click',async function(){await api('/auth/logout',{method:'POST'});toast('Signed out','info');await loadNav();});
  }
}

function gIcon(){return '<svg width="14" height="14" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.31-8.16 2.31-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>';}

loadNav(); loadDebates();
</script></body></html>`;
}

// ─────────────────────────────────────────
// DEBATE PAGE
// ─────────────────────────────────────────
function debatePage(debateId, question, category, type){
  var EQ=esc(question), EC=esc(category), ET=esc(type||'question');
  return `<!doctype html><html lang="en">
<head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${EQ} — ARGU</title>
<meta property="og:title" content="${EQ}"/>
<meta property="og:description" content="Join the debate on ARGU."/>
${BASE_CSS}
<style>
body{padding-bottom:10px;}
.page{max-width:1100px;margin:0 auto;padding:0 22px 80px;position:relative;z-index:1;}
.back{font-size:13px;color:var(--muted2);display:inline-flex;align-items:center;gap:5px;margin:28px 0 18px;transition:color .14s;padding:5px 0;}
.back:hover{color:var(--text);}
.eyebrow{display:inline-flex;align-items:center;gap:5px;font-size:9px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;padding:4px 12px;border-radius:999px;margin-bottom:13px;}
.eyebrow.event{color:var(--gold);background:rgba(245,158,11,.09);border:1px solid rgba(245,158,11,.2);}
.eyebrow.question{color:var(--accent);background:var(--yes-dim);border:1px solid rgba(59,130,246,.2);}
.hero-q{font-family:'Unbounded',sans-serif;font-size:clamp(18px,3vw,36px);font-weight:700;line-height:1.1;letter-spacing:-.02em;max-width:740px;margin-bottom:20px;}
.scoreboard{display:flex;gap:9px;margin-bottom:7px;}
.sb-side{flex:1;padding:14px 18px;border-radius:15px;border:1px solid;display:flex;align-items:center;justify-content:space-between;transition:all .3s;}
.sb-side.yes{background:var(--yes-dim);border-color:rgba(59,130,246,.2);}
.sb-side.no{background:var(--no-dim);border-color:rgba(239,68,68,.2);}
.sb-lbl{font-family:'Unbounded',sans-serif;font-size:11px;font-weight:700;}
.sb-lbl.yes{color:var(--yes);} .sb-lbl.no{color:var(--no);}
.sb-big{font-family:'Unbounded',sans-serif;font-size:28px;font-weight:900;line-height:1;}
.sb-big.yes{color:var(--yes);} .sb-big.no{color:var(--no);}
.sb-pct{font-size:10px;color:var(--muted2);margin-top:2px;}
.prog-bar{height:4px;background:var(--bg4);border-radius:999px;overflow:hidden;margin-bottom:26px;}
.prog-yes{height:100%;background:linear-gradient(90deg,var(--yes),#6366f1);border-radius:999px;transition:width .6s cubic-bezier(.34,1,.64,1);}
.layout{display:grid;grid-template-columns:1fr 260px;gap:18px;align-items:start;}
@media(max-width:800px){.layout{grid-template-columns:1fr;}}
.composer{background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:18px;margin-bottom:18px;transition:border-color .2s;}
.composer:focus-within{border-color:rgba(59,130,246,.28);}
.clabel{font-size:9px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-bottom:12px;}
.side-row{display:flex;gap:7px;margin-bottom:12px;}
.side-btn{flex:1;padding:9px;border-radius:9px;border:1px solid var(--border);background:var(--bg3);color:var(--muted2);font-family:'Unbounded',sans-serif;font-size:10px;font-weight:700;cursor:pointer;transition:all .16s;}
.side-btn:hover{color:var(--text);border-color:var(--border2);}
.side-btn.y-on{background:var(--yes-dim);border-color:var(--yes);color:var(--yes);box-shadow:0 0 14px var(--yes-glow);}
.side-btn.n-on{background:var(--no-dim);border-color:var(--no);color:var(--no);box-shadow:0 0 14px var(--no-glow);}
.comp-ta{width:100%;min-height:84px;resize:vertical;padding:12px 13px;border-radius:9px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-family:'Manrope',sans-serif;font-size:13px;line-height:1.56;outline:none;transition:border-color .16s;}
.comp-ta:focus{border-color:rgba(59,130,246,.38);}
.comp-ta::placeholder{color:var(--muted);}
.post-btn{padding:10px 20px;border-radius:9px;border:none;background:var(--accent);color:#fff;font-family:'Unbounded',sans-serif;font-weight:700;font-size:10px;letter-spacing:.04em;cursor:pointer;transition:all .16s;}
.post-btn:hover{opacity:.87;transform:translateY(-1px);}
.sec-hdr{font-family:'Unbounded',sans-serif;font-size:11px;font-weight:700;letter-spacing:.04em;margin-bottom:13px;display:flex;align-items:center;gap:9px;}
.live-ind{display:flex;align-items:center;gap:4px;font-size:9px;font-weight:600;color:var(--green);background:rgba(34,197,94,.09);border:1px solid rgba(34,197,94,.2);padding:3px 9px;border-radius:999px;}
.rdot{width:5px;height:5px;border-radius:50%;background:var(--green);animation:rd 1.3s infinite;display:inline-block;}
@keyframes rd{0%,100%{opacity:1}50%{opacity:.3}}
.sort-bar{display:flex;align-items:center;gap:5px;}
.sort-btn{padding:5px 11px;border-radius:7px;border:1px solid var(--border);background:transparent;color:var(--muted);font-size:11px;font-weight:600;cursor:pointer;transition:all .13s;}
.sort-btn.on{background:var(--bg3);color:var(--text);border-color:var(--border2);}
.msg{display:grid;grid-template-columns:40px 1fr;gap:11px;background:var(--card);border:1px solid var(--border);border-radius:13px;padding:13px;margin-bottom:7px;animation:mIn .22s ease both;transition:border-color .16s;}
.msg:hover{border-color:var(--border2);}
.msg.nm{border-color:rgba(59,130,246,.28);box-shadow:0 0 14px rgba(59,130,246,.09);}
@keyframes mIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.vcol{display:flex;flex-direction:column;align-items:center;gap:4px;}
.vscore{font-family:'Unbounded',sans-serif;font-weight:800;font-size:14px;line-height:1;transition:color .2s,transform .2s;}
.vscore.pos{color:var(--yes);} .vscore.neg{color:var(--no);} .vscore.zero{color:var(--muted);}
.vscore.bump{transform:scale(1.3);}
.vbtn{width:28px;height:24px;border-radius:6px;border:1px solid var(--border);background:var(--bg3);color:var(--muted);font-size:10px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .13s;}
.vbtn.up:hover,.vbtn.up.active{background:var(--yes-dim);border-color:var(--yes);color:var(--yes);}
.vbtn.down:hover,.vbtn.down.active{background:var(--no-dim);border-color:var(--no);color:var(--no);}
.msg-head{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:6px;}
.msg-author{font-size:12px;font-weight:700;transition:color .13s;}
.msg-author:hover{color:var(--accent);}
.msg-time{margin-left:auto;font-size:10px;color:var(--muted);}
.msg-body{font-size:13px;color:rgba(234,237,243,.82);line-height:1.6;margin-bottom:9px;}
[data-theme="light"] .msg-body{color:var(--text2);}
.msg-acts{display:flex;gap:4px;flex-wrap:wrap;align-items:center;}
.react-btn{display:inline-flex;align-items:center;gap:3px;padding:4px 8px;border-radius:7px;border:1px solid var(--border);background:var(--bg3);color:var(--muted2);font-size:11px;cursor:pointer;transition:all .13s;}
.react-btn:hover{border-color:var(--border2);color:var(--text);}
.react-btn.active{background:rgba(245,158,11,.09);border-color:rgba(245,158,11,.3);color:var(--gold);}
.reply-btn,.share-btn{display:inline-flex;align-items:center;gap:3px;padding:4px 8px;border-radius:7px;border:1px solid transparent;background:transparent;color:var(--muted);font-size:10px;cursor:pointer;transition:all .13s;}
.reply-btn:hover,.share-btn:hover{color:var(--text);border-color:var(--border);}
.share-btn{margin-left:auto;}
.replies-box{margin-top:9px;padding-top:9px;border-top:1px solid var(--border);}
.reply-item{display:flex;gap:9px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.035);}
.reply-item:last-child{border-bottom:none;}
[data-theme="light"] .reply-item{border-bottom-color:rgba(0,0,0,.055);}
.reply-comp{margin-top:9px;display:flex;gap:7px;}
.reply-in{flex:1;padding:8px 11px;border-radius:8px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-family:'Manrope',sans-serif;font-size:12px;outline:none;transition:border-color .16s;}
.reply-in:focus{border-color:rgba(59,130,246,.38);}
.me-card{background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:16px;margin-bottom:13px;}
.lb-item{display:flex;align-items:center;gap:9px;padding:7px 0;border-bottom:1px solid var(--border);font-size:12px;}
.lb-item:last-child{border-bottom:none;}
.lb-num{font-family:'Unbounded',sans-serif;font-size:9px;font-weight:700;color:var(--muted);width:18px;text-align:center;flex-shrink:0;}
.lb-num.t1{color:var(--gold);}
.lb-name{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.lb-pts{font-size:10px;color:var(--muted2);}
.auth-sm{width:100%;padding:9px 11px;border-radius:9px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-family:'Manrope',sans-serif;font-size:12px;outline:none;margin-bottom:7px;transition:border-color .16s;}
.auth-sm:focus{border-color:rgba(59,130,246,.38);}
.empty-list{text-align:center;padding:44px 20px;color:var(--muted);font-size:13px;}
.join-btn{width:100%;margin-top:9px;padding:10px;border-radius:9px;border:1px solid rgba(59,130,246,.35);background:var(--yes-dim);color:var(--accent);font-size:12px;font-weight:600;cursor:pointer;transition:background .16s;}
.join-btn:hover{background:rgba(59,130,246,.2);}
.leave-btn{width:100%;margin-top:9px;padding:9px;border-radius:9px;border:1px solid var(--border);background:var(--bg3);color:var(--muted2);font-size:12px;cursor:pointer;transition:all .13s;}
.leave-btn:hover{border-color:var(--border2);color:var(--text);}
</style>
</head>
<body>
${SHARED_JS}
<nav><div class="nav-inner">
  <a class="logo" href="/">ARGU<span>.</span></a>
  <div class="nav-right" id="navRight">
    <button class="theme-btn" id="themeBtn" onclick="toggleTheme()">☀️</button>
  </div>
</div></nav>
<div class="page">
  <a class="back" href="/explore">← All debates</a>
  <div class="eyebrow ${ET}">${ET==='event'?'🌍 Event':'💭 Question'} · ${EC}</div>
  <h1 class="hero-q">${EQ}</h1>
  <div class="scoreboard">
    <div class="sb-side yes"><span class="sb-lbl yes">YES</span><div style="text-align:right"><div class="sb-big yes" id="yesC">0</div><div class="sb-pct" id="yesPct">—</div></div></div>
    <div class="sb-side no"><div><div class="sb-big no" id="noC">0</div><div class="sb-pct" id="noPct">—</div></div><span class="sb-lbl no">NO</span></div>
  </div>
  <div class="prog-bar"><div class="prog-yes" id="progY" style="width:50%"></div></div>
  <div class="layout">
    <div>
      <div class="composer">
        <div class="clabel">Your argument</div>
        <div class="side-row">
          <button class="side-btn y-on" id="btnY">✓ YES</button>
          <button class="side-btn" id="btnN">✗ NO</button>
        </div>
        <textarea class="comp-ta" id="ta" placeholder="Make your case… (max 300 chars)" maxlength="300"></textarea>
        <div style="display:flex;align-items:center;justify-content:space-between;margin-top:9px;gap:9px">
          <svg width="26" height="26" viewBox="0 0 26 26" id="cRing">
            <circle cx="13" cy="13" r="10" fill="none" stroke="var(--border)" stroke-width="2.5"/>
            <circle cx="13" cy="13" r="10" fill="none" stroke="var(--accent)" stroke-width="2.5" stroke-dasharray="62.83" stroke-dashoffset="62.83" stroke-linecap="round" transform="rotate(-90 13 13)" id="cArc" style="transition:stroke-dashoffset .2s,stroke .2s"/>
          </svg>
          <span style="font-size:10px;color:var(--muted);flex:1" id="cCount">0 / 300</span>
          <button class="post-btn" id="sendBtn">Post argument →</button>
        </div>
      </div>
      <div class="sec-hdr">
        <span id="argCnt">Arguments</span>
        <span class="live-ind" id="sseStatus"><span class="rdot"></span>Live</span>
        <div class="sort-bar" style="margin-left:auto">
          <button class="sort-btn on" id="sortN">New</button>
          <button class="sort-btn" id="sortT">Top</button>
        </div>
      </div>
      <div id="list">
        ${Array(3).fill(0).map(()=>`<div style="background:var(--card);border:1px solid var(--border);border-radius:13px;padding:13px;margin-bottom:7px;display:grid;grid-template-columns:40px 1fr;gap:11px"><div style="display:flex;flex-direction:column;align-items:center;gap:4px"><div class="skel" style="width:26px;height:16px;border-radius:4px;margin-bottom:4px"></div><div class="skel" style="width:28px;height:22px;border-radius:6px"></div><div class="skel" style="width:28px;height:22px;border-radius:6px"></div></div><div><div style="display:flex;gap:6px;margin-bottom:9px"><div class="skel" style="width:28px;height:16px;border-radius:999px"></div><div class="skel" style="width:72px;height:13px;border-radius:4px"></div></div><div class="skel" style="height:13px;width:100%;margin-bottom:5px"></div><div class="skel" style="height:13px;width:72%"></div></div></div>`).join('')}
      </div>
    </div>
    <div>
      <div class="me-card">
        <div class="clabel">Account</div>
        <div id="meBox"><div class="skel" style="height:13px;width:55%;margin-bottom:7px"></div><div class="skel" style="height:11px;width:38%"></div></div>
        <div id="loginBox" style="display:none">
          <a href="/auth/google" style="display:flex;align-items:center;justify-content:center;gap:7px;padding:9px;border-radius:9px;border:1px solid var(--border2);background:var(--bg3);color:var(--text);font-size:12px;font-weight:600;text-decoration:none;margin-bottom:9px">${`<svg width="14" height="14" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.31-8.16 2.31-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>`}Google</a>
          <div style="font-size:11px;color:var(--muted);text-align:center;margin-bottom:7px">or choose a username</div>
          <input class="auth-sm" id="usIn" placeholder="username…" maxlength="20"/>
          <button class="join-btn" id="loginBtn">Join debate →</button>
        </div>
        <div id="logoutBox" style="display:none"><button class="leave-btn" id="logoutBtn">Sign out</button></div>
      </div>
      <div class="card">
        <div class="clabel">Top Debaters</div>
        <div id="lb">${Array(5).fill(0).map(()=>`<div style="display:flex;align-items:center;gap:9px;padding:7px 0;border-bottom:1px solid var(--border)"><div class="skel" style="width:16px;height:11px;border-radius:3px"></div><div class="skel" style="flex:1;height:12px;border-radius:4px"></div><div class="skel" style="width:32px;height:10px;border-radius:3px"></div></div>`).join('')}</div>
      </div>
    </div>
  </div>
</div>
<script>
var DID=${debateId};
var EMOJI={fire:'🔥',think:'🤔',idea:'💡'};
var side='YES', sort='new', me=null, messages=[], sseConn=null;

document.getElementById('ta').addEventListener('input',function(){
  var n=this.value.length, pct=n/300, c=62.83, off=c*(1-pct);
  var arc=document.getElementById('cArc');
  arc.setAttribute('stroke-dashoffset',off);
  arc.setAttribute('stroke',pct>.9?'var(--no)':pct>.7?'var(--gold)':'var(--accent)');
  document.getElementById('cCount').textContent=n+' / 300';
  document.getElementById('cCount').style.color=pct>.9?'var(--no)':'var(--muted)';
});

function setSide(s){
  side=s;
  document.getElementById('btnY').className='side-btn'+(s==='YES'?' y-on':'');
  document.getElementById('btnN').className='side-btn'+(s==='NO'?' n-on':'');
}
document.getElementById('btnY').addEventListener('click',function(){setSide('YES');});
document.getElementById('btnN').addEventListener('click',function(){setSide('NO');});
document.getElementById('sortN').addEventListener('click',function(){sort='new';document.getElementById('sortN').classList.add('on');document.getElementById('sortT').classList.remove('on');loadMsgs();});
document.getElementById('sortT').addEventListener('click',function(){sort='top';document.getElementById('sortT').classList.add('on');document.getElementById('sortN').classList.remove('on');loadMsgs();});

function connectSSE(){
  if(sseConn)sseConn.close();
  sseConn=new EventSource('/api/events/debate/'+DID);
  sseConn.addEventListener('new_message',function(e){
    var msg=JSON.parse(e.data);
    if(sort==='new'){messages.unshift(msg);prependMsg(msg,true);}
    updateScores();
  });
  sseConn.addEventListener('vote_update',function(e){
    var d=JSON.parse(e.data);
    messages=messages.map(function(m){return m.id===d.messageId?Object.assign({},m,{score:d.newScore}):m;});
    var sc=document.getElementById('score-'+d.messageId);
    if(sc){sc.textContent=d.newScore;sc.className='vscore'+(d.newScore>0?' pos':d.newScore<0?' neg':' zero');sc.classList.add('bump');setTimeout(function(){sc.classList.remove('bump');},300);}
  });
  sseConn.addEventListener('new_reply',function(e){
    var r=JSON.parse(e.data);
    var rc=document.getElementById('rc-'+r.parent_id);
    if(rc){var cur=parseInt(rc.textContent)||0;rc.textContent=(cur+1)+' replies';}
  });
  sseConn.onerror=function(){
    var s=document.getElementById('sseStatus');
    s.style.color='var(--no)';s.innerHTML='⚠ Reconnecting…';
    setTimeout(connectSSE,5000);
  };
}

function updateScores(){
  var yes=messages.filter(function(m){return m.side==='YES';}).length;
  var no=messages.filter(function(m){return m.side==='NO';}).length;
  var total=yes+no, yp=total>0?Math.round(yes/total*100):50;
  document.getElementById('yesC').textContent=yes;
  document.getElementById('noC').textContent=no;
  document.getElementById('yesPct').textContent=total>0?yp+'% of args':'—';
  document.getElementById('noPct').textContent=total>0?(100-yp)+'% of args':'—';
  document.getElementById('progY').style.width=yp+'%';
  document.getElementById('argCnt').textContent=messages.length+' Argument'+(messages.length!==1?'s':'');
}

function buildMsg(m,delay){
  var sc=m.score>0?'pos':m.score<0?'neg':'zero', pc=m.side==='YES'?'yes':'no';
  return '<div class="msg" id="msg-'+m.id+'" style="animation-delay:'+(delay||0)+'s">'
    +'<div class="vcol"><div class="vscore '+sc+'" id="score-'+m.id+'">'+m.score+'</div><button class="vbtn up" data-id="'+m.id+'" data-v="1">▲</button><button class="vbtn down" data-id="'+m.id+'" data-v="-1">▼</button></div>'
    +'<div><div class="msg-head"><span class="pill '+pc+'">'+m.side+'</span><a class="msg-author" href="/u/'+esc(m.username)+'">'+esc(m.username)+'</a><span class="msg-time">'+ago(m.created_at)+'</span></div>'
    +'<div class="msg-body">'+esc(m.text)+'</div>'
    +'<div class="msg-acts">'
    +['fire','think','idea'].map(function(e){return '<button class="react-btn" data-id="'+m.id+'" data-emoji="'+e+'">'+EMOJI[e]+' <span id="rc-'+e+'-'+m.id+'">'+(m[e+'_count']||0)+'</span></button>';}).join('')
    +'<button class="reply-btn" data-id="'+m.id+'">💬 <span id="rc-'+m.id+'">'+(m.reply_count>0?m.reply_count+' replies':'Reply')+'</span></button>'
    +'<button class="share-btn" data-url="'+location.origin+'/debate/'+DID+'#msg-'+m.id+'">🔗</button>'
    +'</div><div class="replies-box" id="repl-'+m.id+'" style="display:none"></div></div></div>';
}

function attachListeners(el){
  if(!el)return;
  el.querySelectorAll('.vbtn').forEach(function(btn){
    btn.addEventListener('click',async function(){
      if(!me){toast('Login to vote','error');return;}
      var id=btn.getAttribute('data-id'),v=parseInt(btn.getAttribute('data-v'),10);
      btn.disabled=true;
      var r=await api('/messages/'+id+'/vote',{method:'POST',body:JSON.stringify({value:v})});
      btn.disabled=false;
      if(!r||r.error){toast((r&&r.error)||'Error','error');return;}
      if(r.newScore!=null){
        var sc=document.getElementById('score-'+id);
        if(sc){sc.textContent=r.newScore;sc.className='vscore'+(r.newScore>0?' pos':r.newScore<0?' neg':' zero');sc.classList.add('bump');setTimeout(function(){sc.classList.remove('bump');},300);}
        messages=messages.map(function(m){return m.id==id?Object.assign({},m,{score:r.newScore}):m;});
      }
    });
  });
  el.querySelectorAll('.react-btn').forEach(function(btn){
    btn.addEventListener('click',async function(){
      if(!me){toast('Login to react','error');return;}
      var id=btn.getAttribute('data-id'),emoji=btn.getAttribute('data-emoji');
      var r=await api('/messages/'+id+'/react',{method:'POST',body:JSON.stringify({emoji:emoji})});
      if(!r||r.error){toast((r&&r.error)||'Error','error');return;}
      var cEl=document.getElementById('rc-'+emoji+'-'+id);
      if(cEl){var cur=parseInt(cEl.textContent)||0;cEl.textContent=r.action==='added'?cur+1:Math.max(0,cur-1);btn.classList.toggle('active',r.action==='added');}
    });
  });
  el.querySelectorAll('.reply-btn').forEach(function(btn){
    btn.addEventListener('click',function(){toggleReplies(btn.getAttribute('data-id'));});
  });
  el.querySelectorAll('.share-btn').forEach(function(btn){
    btn.addEventListener('click',function(){
      navigator.clipboard.writeText(btn.getAttribute('data-url')).then(function(){toast('Link copied!','success');}).catch(function(){toast('Copy: '+btn.getAttribute('data-url'),'info');});
    });
  });
}

async function toggleReplies(msgId){
  var box=document.getElementById('repl-'+msgId); if(!box) return;
  if(box.style.display==='block'){box.style.display='none';return;}
  box.style.display='block';
  box.innerHTML='<div class="skel" style="height:38px;border-radius:8px;margin-bottom:7px"></div>';
  var replies=await api('/messages/'+msgId+'/replies')||[];
  box.innerHTML='';
  replies.forEach(function(r){
    var d=document.createElement('div'); d.className='reply-item';
    d.innerHTML='<div style="flex-shrink:0;width:22px;text-align:center;font-size:10px;font-weight:700;color:var(--muted);padding-top:2px">↳</div><div style="flex:1"><div style="display:flex;align-items:center;gap:5px;margin-bottom:4px"><span class="pill '+(r.side==='YES'?'yes':'no')+'">'+r.side+'</span><a href="/u/'+esc(r.username)+'" style="font-size:11px;font-weight:700">'+esc(r.username)+'</a><span style="font-size:9px;color:var(--muted);margin-left:auto">'+ago(r.created_at)+'</span></div><div style="font-size:12px;color:var(--text2);line-height:1.5">'+esc(r.text)+'</div></div>';
    box.appendChild(d);
  });
  var rc=document.createElement('div'); rc.className='reply-comp';
  rc.innerHTML='<input class="reply-in" id="ri-'+msgId+'" placeholder="Reply…" maxlength="300"/><button onclick="postReply('+msgId+')" style="padding:8px 14px;border-radius:8px;border:none;background:var(--accent);color:#fff;font-size:10px;font-weight:700;cursor:pointer;font-family:\'Unbounded\',sans-serif">Reply</button>';
  box.appendChild(rc);
}

async function postReply(pid){
  if(!me){toast('Login to reply','error');return;}
  var input=document.getElementById('ri-'+pid);
  var text=(input&&input.value||'').trim(); if(!text) return;
  var r=await api('/messages/'+pid+'/reply',{method:'POST',body:JSON.stringify({text:text})});
  if(!r||r.error){toast((r&&r.error)||'Error','error');return;}
  if(input)input.value='';
  toast('Reply posted!','success');
  var box=document.getElementById('repl-'+pid);
  if(box){box.style.display='none';setTimeout(function(){toggleReplies(pid);},80);}
}

function prependMsg(m,isNew){
  var list=document.getElementById('list');
  var em=list.querySelector('.empty-list');if(em)em.remove();
  var wrap=document.createElement('div');wrap.innerHTML=buildMsg(m,0);
  var el=wrap.firstChild;
  if(isNew){el.classList.add('nm');setTimeout(function(){el.classList.remove('nm');},2200);}
  list.insertBefore(el,list.firstChild);attachListeners(el);
}

function renderMsgs(rows){
  messages=rows; updateScores();
  var list=document.getElementById('list');
  if(!rows.length){list.innerHTML='<div class="empty-list">No arguments yet — be the first!</div>';return;}
  list.innerHTML=rows.map(function(m,i){return buildMsg(m,Math.min(i,6)*.04);}).join('');
  list.querySelectorAll('.msg').forEach(function(el){attachListeners(el);});
}

async function loadMsgs(){
  var rows=await api('/debate/'+DID+'/messages?sort='+sort)||[];
  renderMsgs(Array.isArray(rows)?rows:[]);
}

function updateMe(u){
  me=u; var b=badge(u.rating);
  document.getElementById('meBox').innerHTML='<a href="/u/'+esc(u.username)+'" style="font-weight:700;font-size:13px;display:flex;align-items:center;gap:5px">'+esc(u.username)+(b?'<span>'+b+'</span>':'')+'</a><div style="color:var(--gold);font-size:11px;margin-top:2px">★ '+u.rating+' pts</div>';
  document.getElementById('loginBox').style.display='none';
  document.getElementById('logoutBox').style.display='block';
  var nr=document.getElementById('navRight');
  if(nr)nr.innerHTML='<a href="/u/'+esc(u.username)+'" class="nav-link" style="font-weight:600">'+esc(u.username)+(b?'<span style="margin-left:4px">'+b+'</span>':'')+'</a><span style="color:var(--gold);font-size:11px">★'+u.rating+'</span><button class="theme-btn" id="themeBtn" onclick="toggleTheme()">☀️</button>';
}

async function loadMe(){
  var d=await api('/me');
  if(d&&d.user){updateMe(d.user);}
  else{
    me=null;
    document.getElementById('meBox').innerHTML='<div style="font-size:12px;color:var(--muted2)">Not signed in</div><div style="font-size:10px;color:var(--muted);margin-top:3px">Join to post & vote</div>';
    document.getElementById('loginBox').style.display='block';
    document.getElementById('logoutBox').style.display='none';
  }
}

async function loadLB(){
  var rows=await api('/leaderboard/users?limit=7')||[];
  document.getElementById('lb').innerHTML=rows.length
    ?rows.map(function(u,i){var b=badge(u.rating);return '<div class="lb-item"><span class="lb-num '+(i===0?'t1':'')+'">&#35;'+(i+1)+'</span><a class="lb-name" href="/u/'+esc(u.username)+'">'+esc(u.username)+(b?'<span style="margin-left:3px">'+b+'</span>':'')+'</a><span class="lb-pts">'+u.rating+'</span></div>';}).join('')
    :'<div style="color:var(--muted);font-size:12px">No users yet</div>';
}

document.getElementById('loginBtn').addEventListener('click',async function(){
  var u=(document.getElementById('usIn')||{}).value||''; if(!u.trim()) return;
  var r=await api('/auth/login',{method:'POST',body:JSON.stringify({username:u.trim()})});
  if(!r||r.error){toast((r&&r.error)||'Error','error');return;}
  toast('Welcome, '+r.user.username+'! 👋','success');
  await Promise.all([loadMe(),loadLB()]);
});
document.getElementById('logoutBtn').addEventListener('click',async function(){
  await api('/auth/logout',{method:'POST'}); toast('Signed out','info'); me=null;
  await Promise.all([loadMe(),loadLB()]);
});
document.getElementById('sendBtn').addEventListener('click',async function(){
  if(!me){toast('Login to post an argument','error');return;}
  var text=document.getElementById('ta').value.trim();
  if(!text){toast('Write your argument first','error');return;}
  document.getElementById('sendBtn').disabled=true;document.getElementById('sendBtn').textContent='Posting…';
  var r=await api('/debate/'+DID+'/messages',{method:'POST',body:JSON.stringify({text:text,side:side})});
  document.getElementById('sendBtn').disabled=false;document.getElementById('sendBtn').textContent='Post argument →';
  if(!r||r.error){toast((r&&r.error)||'Error','error');return;}
  document.getElementById('ta').value='';document.getElementById('ta').dispatchEvent(new Event('input'));
  toast('Argument posted! 🔥','success');
  if(sort==='new')await loadMsgs();
});

connectSSE();
Promise.all([loadMe(),loadLB(),loadMsgs()]);
</script></body></html>`;
}

// ─────────────────────────────────────────
// PROFILE PAGE (with edit)
// ─────────────────────────────────────────
function profilePage(username){
  var EU=esc(username);
  return `<!doctype html><html lang="en">
<head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${EU} — ARGU</title>
${BASE_CSS}
<style>
body{padding-bottom:10px;}
.page{max-width:740px;margin:0 auto;padding:36px 22px 80px;position:relative;z-index:1;}
.back{font-size:13px;color:var(--muted2);display:inline-flex;align-items:center;gap:5px;margin-bottom:26px;transition:color .14s;}
.back:hover{color:var(--text);}
.prof-top{display:flex;align-items:center;gap:20px;margin-bottom:28px;padding:22px;background:var(--card);border:1px solid var(--border);border-radius:20px;}
.avatar{width:64px;height:64px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:26px;flex-shrink:0;border:2px solid var(--border2);}
.prof-name{font-family:'Unbounded',sans-serif;font-size:20px;font-weight:900;display:flex;align-items:center;gap:9px;margin-bottom:4px;}
.bio-text{font-size:13px;color:var(--text2);line-height:1.55;margin-top:4px;}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:9px;margin-bottom:26px;}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:13px;padding:14px;text-align:center;transition:border-color .16s;}
.stat-card:hover{border-color:var(--border2);}
.stat-n{font-family:'Unbounded',sans-serif;font-size:24px;font-weight:900;}
.stat-l{font-size:9px;color:var(--muted);margin-top:4px;letter-spacing:.08em;text-transform:uppercase;font-weight:700;}
.arg-card{background:var(--card);border:1px solid var(--border);border-radius:13px;padding:14px 16px;margin-bottom:9px;transition:all .16s;}
.arg-card:hover{border-color:var(--border2);transform:translateY(-1px);}
.arg-head{display:flex;align-items:center;gap:7px;margin-bottom:8px;flex-wrap:wrap;}
.arg-body{font-size:13px;color:var(--text2);line-height:1.58;}
.score-tag{font-family:'Unbounded',sans-serif;font-size:11px;font-weight:800;padding:3px 9px;border-radius:7px;margin-left:auto;}
.score-tag.pos{color:var(--yes);background:var(--yes-dim);} .score-tag.neg{color:var(--no);background:var(--no-dim);} .score-tag.zero{color:var(--muted);background:var(--bg3);}
.sec-title{font-family:'Unbounded',sans-serif;font-size:12px;font-weight:700;margin-bottom:14px;}
.edit-btn{padding:7px 14px;border-radius:9px;border:1px solid var(--border2);background:transparent;color:var(--muted2);font-size:11px;cursor:pointer;transition:all .14s;margin-left:auto;}
.edit-btn:hover{border-color:var(--border3);color:var(--text);}
/* Edit modal */
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:200;display:flex;align-items:center;justify-content:center;padding:18px;}
.modal-bg.hidden{display:none;}
.modal{background:var(--bg2);border:1px solid var(--border2);border-radius:20px;padding:26px;width:100%;max-width:460px;box-shadow:var(--sh2);}
.modal h3{font-family:'Unbounded',sans-serif;font-size:14px;font-weight:700;margin-bottom:18px;}
.mfield{margin-bottom:11px;}
.mfield label{display:block;font-size:10px;color:var(--muted);margin-bottom:5px;text-transform:uppercase;letter-spacing:.06em;}
.mfield input,.mfield textarea{width:100%;padding:10px 12px;border-radius:9px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-family:'Manrope',sans-serif;font-size:13px;outline:none;transition:border-color .16s;}
.mfield input:focus,.mfield textarea:focus{border-color:rgba(59,130,246,.45);}
.mfield textarea{resize:vertical;min-height:70px;}
.avatar-grid{display:flex;flex-wrap:wrap;gap:7px;}
.avatar-opt{width:36px;height:36px;border-radius:9px;border:2px solid var(--border);background:var(--bg3);font-size:18px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .13s;}
.avatar-opt:hover{border-color:var(--border2);}
.avatar-opt.sel{border-color:var(--accent);background:var(--yes-dim);}
</style>
</head>
<body>
${SHARED_JS}
<nav><div class="nav-inner">
  <a class="logo" href="/">ARGU<span>.</span></a>
  <div class="nav-right" id="navRight">
    <button class="theme-btn" id="themeBtn" onclick="toggleTheme()">☀️</button>
  </div>
</div></nav>
<div class="page">
  <a class="back" href="/">← Back</a>
  <div id="content">
    <div class="prof-top">
      <div class="skel avatar" style="background:var(--bg3)"></div>
      <div style="flex:1">
        <div class="skel" style="height:20px;width:50%;margin-bottom:9px;border-radius:6px"></div>
        <div class="skel" style="height:13px;width:32%;margin-bottom:5px;border-radius:4px"></div>
        <div class="skel" style="height:13px;width:24%;border-radius:4px"></div>
      </div>
    </div>
    <div class="stats-grid">${Array(5).fill(0).map(()=>`<div class="stat-card"><div class="skel" style="height:24px;width:54%;margin:0 auto 7px;border-radius:6px"></div><div class="skel" style="height:9px;width:64%;margin:0 auto;border-radius:3px"></div></div>`).join('')}</div>
  </div>
</div>

<!-- Edit Modal -->
<div class="modal-bg hidden" id="editMod">
  <div class="modal">
    <h3>✏️ Edit Profile</h3>
    <div class="mfield"><label>Display Name (optional)</label><input id="eDN" placeholder="Your display name…" maxlength="40"/></div>
    <div class="mfield"><label>Bio (optional)</label><textarea id="eBio" placeholder="A short bio about you…" maxlength="200"></textarea></div>
    <div class="mfield">
      <label>Avatar</label>
      <div class="avatar-grid" id="avGrid"></div>
    </div>
    <div style="display:flex;gap:8px;margin-top:16px;justify-content:flex-end">
      <button class="edit-btn" id="editCancel">Cancel</button>
      <button class="btn btn-blue" id="editSave" style="padding:9px 20px;font-size:11px">Save</button>
    </div>
  </div>
</div>

<script>
var TARGET='${EU}';
var AVATARS=['⚔️','🔥','🧠','🎯','👑','🌍','⚡','🦁','🐺','🦊','🤖','💎','🥊','🎭','🌊','🦋'];
var selAvatar=null;
var editMod=document.getElementById('editMod');

document.getElementById('editCancel').addEventListener('click',function(){editMod.classList.add('hidden');});
editMod.addEventListener('click',function(e){if(e.target===editMod)editMod.classList.add('hidden');});

document.getElementById('editSave').addEventListener('click',async function(){
  var dn=document.getElementById('eDN').value.trim();
  var bio=document.getElementById('eBio').value.trim();
  var r=await api('/api/profile',{method:'PATCH',body:JSON.stringify({display_name:dn,bio:bio,avatar:selAvatar})});
  if(!r||r.error){toast((r&&r.error)||'Error','error');return;}
  toast('Profile updated!','success');
  editMod.classList.add('hidden');
  load();
});

function openEdit(user){
  document.getElementById('eDN').value=user.display_name||'';
  document.getElementById('eBio').value=user.bio||'';
  selAvatar=user.avatar||'⚔️';
  var grid=document.getElementById('avGrid');
  grid.innerHTML=AVATARS.map(function(a){return '<button class="avatar-opt'+(a===selAvatar?' sel':'')+'" data-av="'+a+'">'+a+'</button>';}).join('');
  grid.querySelectorAll('.avatar-opt').forEach(function(btn){
    btn.addEventListener('click',function(){
      selAvatar=btn.getAttribute('data-av');
      grid.querySelectorAll('.avatar-opt').forEach(function(b){b.classList.toggle('sel',b.getAttribute('data-av')===selAvatar);});
    });
  });
  editMod.classList.remove('hidden');
}

async function load(){
  var pd=await api('/api/user/'+TARGET);
  var md=await api('/me'); var me=md&&md.user;
  var isOwn=me&&me.username===TARGET;
  var nr=document.getElementById('navRight');
  if(me){var b=badge(me.rating);nr.innerHTML='<a href="/u/'+esc(me.username)+'" class="nav-link" style="font-weight:600">'+esc(me.username)+(b?'<span style="margin-left:3px">'+b+'</span>':'')+'</a><span style="color:var(--gold);font-size:11px">★'+me.rating+'</span><button class="theme-btn" id="themeBtn" onclick="toggleTheme()">☀️</button>';}
  if(!pd||pd.error){document.getElementById('content').innerHTML='<div style="text-align:center;padding:56px;color:var(--muted)">User not found</div>';return;}
  var u=pd.user, st=pd.stats, msgs=pd.top_messages, rank=pd.rank;
  var initial=u.username[0].toUpperCase();
  var hue=(u.username.split('').reduce(function(a,c){return a+c.charCodeAt(0);},0)*47)%360;
  var av=u.avatar||'⚔️';
  var dn=u.display_name||u.username;
  var b=badge(u.rating);
  var joined=new Date(u.created_at).toLocaleDateString('en-US',{month:'long',year:'numeric'});
  document.getElementById('content').innerHTML=
    '<div class="prof-top">'
      +'<div class="avatar" style="background:linear-gradient(135deg,hsl('+hue+',48%,18%),hsl('+hue+',38%,26%));border-color:hsl('+hue+',44%,32%)">'+av+'</div>'
      +'<div style="flex:1;min-width:0">'
        +'<div class="prof-name">'+esc(dn)+(b?'<span>'+b+'</span>':'')
          +(isOwn?'<button class="edit-btn" onclick="openEdit('+JSON.stringify({display_name:u.display_name||'',bio:u.bio||'',avatar:av}).replace(/</g,'\\u003c')+')">✏️ Edit</button>':'')+'</div>'
        +(u.display_name&&u.display_name!==u.username?'<div style="font-size:11px;color:var(--muted2);margin-bottom:3px">@'+esc(u.username)+'</div>':'')
        +'<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">'
          +'<div style="font-family:\'Unbounded\',sans-serif;font-size:14px;font-weight:700;color:var(--gold);background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.2);padding:4px 12px;border-radius:8px">★ '+u.rating+' pts</div>'
          +'<div style="font-size:11px;color:var(--muted2)">Rank #'+rank+'</div>'
          +'<div style="font-size:11px;color:var(--muted)">Joined '+joined+'</div>'
        +'</div>'
        +(u.bio?'<div class="bio-text">'+esc(u.bio)+'</div>':'')
      +'</div></div>'
    +'<div class="stats-grid">'
      +'<div class="stat-card"><div class="stat-n">'+st.total_args+'</div><div class="stat-l">Arguments</div></div>'
      +'<div class="stat-card"><div class="stat-n" style="color:var(--yes)">'+st.yes_args+'</div><div class="stat-l">YES side</div></div>'
      +'<div class="stat-card"><div class="stat-n" style="color:var(--no)">'+st.no_args+'</div><div class="stat-l">NO side</div></div>'
      +'<div class="stat-card"><div class="stat-n" style="color:var(--gold)">'+st.total_upvotes+'</div><div class="stat-l">Upvotes</div></div>'
      +'<div class="stat-card"><div class="stat-n">'+st.best_score+'</div><div class="stat-l">Best score</div></div>'
    +'</div>'
    +'<div class="sec-title">Top Arguments</div>'
    +(msgs.length?msgs.map(function(m){
      var pc=m.side==='YES'?'yes':'no', sc=m.score>0?'pos':m.score<0?'neg':'zero';
      return '<div class="arg-card"><div class="arg-head"><span class="pill '+pc+'">'+m.side+'</span>'
        +'<a href="/debate/'+(m.debate_id||'')+'" style="font-size:11px;color:var(--muted2);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(m.question||'')+'</a>'
        +'<span class="score-tag '+sc+'">'+(m.score>0?'+':'')+m.score+'</span></div>'
        +'<div class="arg-body">'+esc(m.text)+'</div></div>';
    }).join(''):'<div style="color:var(--muted);font-size:13px;text-align:center;padding:36px">No arguments yet</div>');
}
load();
</script></body></html>`;
}

// ─────────────────────────────────────────
// LIVE PAGE
// ─────────────────────────────────────────
function livePage(){
return `<!doctype html><html lang="en">
<head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>⚡ Live — ARGU</title>
${BASE_CSS}
<style>
html,body{overflow:hidden;height:100%;margin:0;}
body{display:flex;flex-direction:column;}
nav{flex-shrink:0;}
.wrap{flex:1;display:grid;grid-template-columns:1fr 300px;overflow:hidden;}
@media(max-width:720px){.wrap{grid-template-columns:1fr;}.right-panel{display:none;}}
/* Left */
.left{display:flex;flex-direction:column;height:100%;overflow:hidden;padding:20px 24px 16px;}
.phase-bar{display:flex;gap:3px;background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:4px;margin-bottom:18px;flex-shrink:0;}
.phase-item{flex:1;padding:9px 4px;border-radius:8px;display:flex;align-items:center;justify-content:center;gap:6px;font-family:'Unbounded',sans-serif;font-size:9px;font-weight:700;color:var(--muted);border:1px solid transparent;transition:all .3s;}
.phase-item.on{background:var(--bg3);border-color:var(--border2);color:var(--text);}
.phase-item.done{color:var(--green);}
/* Center */
.q-area{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:0 12px;overflow:hidden;}
.live-cat{font-size:9px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--accent);background:var(--yes-dim);border:1px solid rgba(59,130,246,.18);padding:5px 14px;border-radius:999px;margin-bottom:14px;}
.live-q{font-family:'Unbounded',sans-serif;font-size:clamp(18px,3vw,34px);font-weight:900;line-height:1.08;letter-spacing:-.02em;max-width:600px;margin-bottom:22px;}
/* Timer ring */
.timer-wrap{position:relative;width:88px;height:88px;margin-bottom:18px;flex-shrink:0;}
.timer-svg{transform:rotate(-90deg);}
.timer-bg{fill:none;stroke:var(--bg3);stroke-width:5;}
.timer-arc{fill:none;stroke:var(--accent);stroke-width:5;stroke-linecap:round;transition:stroke-dashoffset .9s linear,stroke .4s;}
.timer-num{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-family:'Unbounded',sans-serif;font-size:22px;font-weight:900;}
.timer-phase{font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;margin-top:4px;color:var(--muted2);}
/* Phase content */
.read-content{font-size:15px;color:var(--muted2);line-height:1.7;}
.argue-content,.vote-content{width:100%;max-width:500px;}
.side-btns{display:flex;gap:10px;margin-bottom:13px;width:100%;}
.live-side{flex:1;padding:14px;border-radius:13px;border:2px solid;font-family:'Unbounded',sans-serif;font-size:12px;font-weight:700;cursor:pointer;transition:all .18s;}
.live-side.y{border-color:rgba(59,130,246,.3);background:var(--yes-dim);color:var(--yes);}
.live-side.y.on,.live-side.y:hover{border-color:var(--yes);background:var(--yes);color:#fff;box-shadow:0 0 22px var(--yes-glow);}
.live-side.n{border-color:rgba(239,68,68,.3);background:var(--no-dim);color:var(--no);}
.live-side.n.on,.live-side.n:hover{border-color:var(--no);background:var(--no);color:#fff;box-shadow:0 0 22px var(--no-glow);}
.live-ta{width:100%;min-height:72px;padding:12px;border-radius:11px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-family:'Manrope',sans-serif;font-size:13px;resize:none;outline:none;margin-bottom:10px;transition:border-color .2s;}
.live-ta:focus{border-color:rgba(59,130,246,.4);}
.live-post{width:100%;padding:12px;border-radius:11px;border:none;background:var(--accent);color:#fff;font-family:'Unbounded',sans-serif;font-size:11px;font-weight:700;cursor:pointer;transition:all .16s;}
.live-post:hover{opacity:.87;}
.live-post:disabled{opacity:.5;cursor:not-allowed;}
.vote-list{width:100%;max-width:560px;max-height:220px;overflow-y:auto;display:flex;flex-direction:column;gap:7px;}
.vote-card{background:var(--bg2);border:1px solid var(--border);border-radius:11px;padding:11px 13px;display:flex;align-items:flex-start;gap:11px;transition:all .16s;}
.vote-card:hover{border-color:var(--border2);}
.vcol{display:flex;flex-direction:column;align-items:center;gap:3px;}
.vscore{font-family:'Unbounded',sans-serif;font-size:13px;font-weight:800;line-height:1;}
.vscore.pos{color:var(--yes);} .vscore.neg{color:var(--no);} .vscore.zero{color:var(--muted);}
.vbtn{width:26px;height:22px;border-radius:5px;border:1px solid var(--border);background:var(--bg3);color:var(--muted);font-size:10px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .13s;}
.vbtn.up:hover{background:var(--yes-dim);border-color:var(--yes);color:var(--yes);}
.vbtn.down:hover{background:var(--no-dim);border-color:var(--no);color:var(--no);}
.vote-body{font-size:12px;color:var(--text2);line-height:1.55;}
.login-ov{position:fixed;inset:0;background:rgba(9,9,13,.92);z-index:50;display:flex;align-items:center;justify-content:center;padding:22px;backdrop-filter:blur(8px);}
.login-ov.hidden{display:none;}
.login-box{background:var(--bg2);border:1px solid var(--border2);border-radius:22px;padding:30px;width:100%;max-width:380px;text-align:center;box-shadow:var(--sh2);}
.login-box h2{font-family:'Unbounded',sans-serif;font-size:16px;font-weight:800;margin-bottom:8px;}
.login-box p{font-size:13px;color:var(--text2);margin-bottom:22px;}
/* Right panel */
.right-panel{border-left:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden;background:var(--bg2);}
.rp-hdr{padding:14px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-shrink:0;}
.rp-title{font-family:'Unbounded',sans-serif;font-size:10px;font-weight:700;display:flex;align-items:center;gap:5px;}
.rdot{width:5px;height:5px;border-radius:50%;background:var(--no);animation:rd 1s infinite;display:inline-block;}
@keyframes rd{0%,100%{opacity:1}50%{opacity:.2}}
.rp-feed{flex:1;overflow-y:auto;padding:10px;}
.feed-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:10px 11px;margin-bottom:7px;animation:fIn .22s ease;}
@keyframes fIn{from{opacity:0;transform:translateX(8px)}to{opacity:1;transform:none}}
.feed-top{display:flex;align-items:center;gap:5px;margin-bottom:5px;}
.feed-body{font-size:11px;color:var(--text2);line-height:1.5;}
.rp-next{padding:12px 16px;border-top:1px solid var(--border);flex-shrink:0;}
.next-lbl{font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:5px;}
.next-q{font-family:'Unbounded',sans-serif;font-size:11px;font-weight:700;line-height:1.3;}
.score-bar{display:flex;gap:7px;font-size:10px;font-weight:700;margin-bottom:10px;}
</style>
</head>
<body>
${SHARED_JS}
<nav><div class="nav-inner">
  <a href="/" class="nav-link" style="font-size:13px">← Back</a>
  <a class="logo" href="/">ARGU<span>.</span></a>
  <div class="nav-right">
    <span style="display:inline-flex;align-items:center;gap:5px;font-size:10px;font-weight:700;color:var(--no);background:rgba(239,68,68,.09);border:1px solid rgba(239,68,68,.22);padding:4px 11px;border-radius:999px"><span class="rdot"></span>LIVE</span>
    <button class="theme-btn" id="themeBtn" onclick="toggleTheme()">☀️</button>
  </div>
</div></nav>

<div class="wrap">
  <div class="left">
    <div class="phase-bar">
      <div class="phase-item on" id="ph-read">📖 Read</div>
      <div class="phase-item" id="ph-argue">⚔️ Argue</div>
      <div class="phase-item" id="ph-vote">🗳️ Vote</div>
    </div>
    <div class="q-area" id="qArea">
      <div class="live-cat skel" style="width:90px;height:22px;border-radius:999px"></div>
      <div class="skel" style="height:32px;width:80%;max-width:480px;margin:16px 0 6px;border-radius:8px"></div>
      <div class="skel" style="height:32px;width:60%;max-width:360px;border-radius:8px;margin-bottom:22px"></div>
      <div class="timer-wrap">
        <svg class="timer-svg" width="88" height="88" viewBox="0 0 88 88">
          <circle class="timer-bg" cx="44" cy="44" r="38"/>
          <circle class="timer-arc" cx="44" cy="44" r="38" id="timerArc" stroke-dasharray="238.76" stroke-dashoffset="0"/>
        </svg>
        <div class="timer-num" id="timerNum">—</div>
      </div>
      <div class="timer-phase" id="phaseLabel">Connecting…</div>
    </div>
  </div>
  <div class="right-panel">
    <div class="rp-hdr">
      <div class="rp-title"><span class="rdot"></span>Live feed</div>
      <span id="argCtR" style="font-size:11px;color:var(--muted)">0 args</span>
    </div>
    <div class="rp-feed" id="rpFeed"><div style="padding:24px;text-align:center;font-size:12px;color:var(--muted)">Waiting…</div></div>
    <div class="rp-next">
      <div class="next-lbl">NEXT:</div>
      <div class="next-q" id="nextQ">—</div>
    </div>
  </div>
</div>

<!-- Login overlay -->
<div class="login-ov hidden" id="loginOv">
  <div class="login-box">
    <h2>⚡ Join the debate</h2>
    <p>Sign in to post arguments and vote live</p>
    <a href="/auth/google" style="display:flex;align-items:center;justify-content:center;gap:8px;padding:12px;border-radius:11px;border:1px solid var(--border2);background:var(--bg3);color:var(--text);font-size:13px;font-weight:600;text-decoration:none;margin-bottom:11px"><svg width="15" height="15" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.31-8.16 2.31-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>Continue with Google</a>
    <div style="text-align:center;font-size:11px;color:var(--muted);margin-bottom:9px">or pick a username</div>
    <div style="display:flex;gap:7px">
      <input id="lovUser" placeholder="username…" maxlength="20" style="flex:1;padding:10px 12px;border-radius:9px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-size:13px;outline:none;"/>
      <button onclick="lovLogin()" style="padding:10px 16px;border-radius:9px;border:none;background:var(--accent);color:#fff;font-family:'Unbounded',sans-serif;font-size:10px;font-weight:700;cursor:pointer">Join</button>
    </div>
    <button onclick="document.getElementById('loginOv').classList.add('hidden')" style="width:100%;margin-top:11px;padding:9px;border-radius:9px;border:1px solid var(--border);background:transparent;color:var(--muted);font-size:12px;cursor:pointer">Browse only</button>
  </div>
</div>

<script>
var me=null, curSide='YES', liveState=null, countdownInt=null, curRemaining=0, feedMsgs=[], debateId=null, posted=false;
var CIRC=238.76;

async function lovLogin(){
  var u=(document.getElementById('lovUser')||{}).value||''; if(!u.trim()) return;
  var r=await api('/auth/login',{method:'POST',body:JSON.stringify({username:u.trim()})});
  if(!r||r.error){toast((r&&r.error)||'Error','error');return;}
  me=r.user; document.getElementById('loginOv').classList.add('hidden');
  toast('Welcome, '+me.username+' 👋','success');
}

function setPhase(ph){
  ['read','argue','vote'].forEach(function(p){
    var el=document.getElementById('ph-'+p);
    if(!el) return;
    el.className='phase-item'+(p===ph?' on':'');
  });
}

function updateTimer(remaining, duration){
  var pct=duration>0?remaining/duration:0;
  var offset=CIRC*(1-pct);
  var arc=document.getElementById('timerArc');
  if(arc){arc.setAttribute('stroke-dashoffset',offset);arc.setAttribute('stroke',remaining<=10?'var(--no)':remaining<=20?'var(--gold)':'var(--accent)');}
  var tn=document.getElementById('timerNum');
  if(tn)tn.textContent=remaining;
}

function renderPhaseContent(state){
  if(!state||!state.debate) return;
  var d=state.debate, ph=state.phase;
  var qa=document.getElementById('qArea');
  setPhase(ph);
  document.getElementById('phaseLabel').textContent=ph.toUpperCase();
  var timerWrap='<div class="timer-wrap"><svg class="timer-svg" width="88" height="88" viewBox="0 0 88 88"><circle class="timer-bg" cx="44" cy="44" r="38"/><circle class="timer-arc" cx="44" cy="44" r="38" id="timerArc" stroke-dasharray="238.76" stroke-dashoffset="0"/></svg><div class="timer-num" id="timerNum">'+state.remaining+'</div></div><div class="timer-phase" id="phaseLabel">'+ph.toUpperCase()+'</div>';
  var header='<div class="live-cat">'+esc(d.category)+' · '+(d.type==='event'?'🌍 Event':'💭 Question')+'</div><h2 class="live-q">'+esc(d.question)+'</h2>';
  if(ph==='read'){
    qa.innerHTML=header+timerWrap+'<p class="read-content">Take a moment to form your opinion. Arguing starts soon.</p>';
  }else if(ph==='argue'){
    qa.innerHTML=header+timerWrap
      +'<div class="argue-content">'
      +'<div class="score-bar"><span style="color:var(--yes)">YES '+(feedMsgs.filter(function(m){return m.side==="YES";}).length)+'</span><span style="flex:1;text-align:center;color:var(--muted)">·</span><span style="color:var(--no)">'+(feedMsgs.filter(function(m){return m.side==="NO";}).length)+' NO</span></div>'
      +(posted?'<div style="text-align:center;padding:14px;background:var(--bg3);border-radius:11px;font-size:13px;color:var(--text2)">✓ Argument posted! Watch the votes roll in.</div>'
      :'<div class="side-btns"><button class="live-side y on" id="liveBtnY" onclick="setLS(\'YES\')">✓ YES</button><button class="live-side n" id="liveBtnN" onclick="setLS(\'NO\')">✗ NO</button></div>'
      +'<textarea class="live-ta" id="liveTa" placeholder="One sharp argument… (max 300 chars)" maxlength="300"></textarea>'
      +'<button class="live-post" id="livePost" onclick="postLive()">Post argument →</button>')
      +'</div>';
  }else if(ph==='vote'){
    var cards=feedMsgs.slice(0,12).map(function(m){
      var sc=m.score>0?'pos':m.score<0?'neg':'zero', pc=m.side==='YES'?'yes':'no';
      return '<div class="vote-card"><div class="vcol"><div class="vscore '+sc+'" id="lsc-'+m.id+'">'+m.score+'</div><button class="vbtn up" onclick="liveVote('+m.id+',1)">▲</button><button class="vbtn down" onclick="liveVote('+m.id+',-1)">▼</button></div><div><div style="display:flex;align-items:center;gap:5px;margin-bottom:4px"><span class="pill '+pc+'">'+m.side+'</span><a href="/u/'+esc(m.username)+'" style="font-size:10px;font-weight:700">'+esc(m.username)+'</a></div><div class="vote-body">'+esc(m.text)+'</div></div></div>';
    }).join('');
    qa.innerHTML=header+'<p style="font-size:12px;color:var(--muted2);margin-bottom:11px">Vote for the best arguments</p><div class="vote-list">'+cards+'</div>';
  }
  updateTimer(state.remaining, state.duration);
}

function setLS(s){
  curSide=s;
  var by=document.getElementById('liveBtnY'), bn=document.getElementById('liveBtnN');
  if(by)by.className='live-side y'+(s==='YES'?' on':'');
  if(bn)bn.className='live-side n'+(s==='NO'?' on':'');
}

async function liveVote(msgId, val){
  if(!me){document.getElementById('loginOv').classList.remove('hidden');return;}
  var r=await api('/messages/'+msgId+'/vote',{method:'POST',body:JSON.stringify({value:val})});
  if(!r||r.error){toast((r&&r.error)||'Error','error');return;}
  if(r.newScore!=null){var sc=document.getElementById('lsc-'+msgId);if(sc){sc.textContent=r.newScore;sc.className='vscore'+(r.newScore>0?' pos':r.newScore<0?' neg':' zero');}}
}

async function postLive(){
  if(!me){document.getElementById('loginOv').classList.remove('hidden');return;}
  var ta=document.getElementById('liveTa'); var text=ta?ta.value.trim():'';
  if(!text){toast('Write something first','error');return;}
  var pb=document.getElementById('livePost'); if(pb){pb.disabled=true;pb.textContent='Posting…';}
  var r=await api('/debate/'+debateId+'/messages',{method:'POST',body:JSON.stringify({text:text,side:curSide})});
  if(!r||r.error){toast((r&&r.error)||'Error','error');if(pb){pb.disabled=false;pb.textContent='Post argument →';}return;}
  posted=true; toast('Posted! 🔥','success');
  if(liveState)renderPhaseContent(liveState);
}

function addFeedMsg(m){
  var feed=document.getElementById('rpFeed');
  var empty=feed.querySelector('div[style*="24px"]'); if(empty)empty.remove();
  var pc=m.side==='YES'?'yes':'no';
  var card=document.createElement('div'); card.className='feed-card';
  card.innerHTML='<div class="feed-top"><span class="pill '+pc+'" style="font-size:9px">'+m.side+'</span><a href="/u/'+esc(m.username)+'" style="font-size:10px;font-weight:700">'+esc(m.username)+'</a><span style="font-size:9px;color:var(--muted);margin-left:auto">now</span></div><div class="feed-body">'+esc(m.text)+'</div>';
  feed.insertBefore(card, feed.firstChild);
  var ct=document.getElementById('argCtR'); if(ct){var n=parseInt(ct.textContent)||0;ct.textContent=(n+1)+' args';}
}

var pollInt=null;
async function pollLive(){
  var state=await api('/api/live-state');
  var wb=document.getElementById('warmup-banner');
  if(!state||state.error){
    if(wb)wb.style.display='flex';
    document.getElementById('phaseLabel').textContent='Warming up…';
    return;
  }
  if(wb)wb.style.display='none';
  liveState=state;
  if(state.debate){
    if(debateId!==state.debate.id){
      debateId=state.debate.id; feedMsgs=[];
      posted=false;
      // load existing args
      var msgs=await api('/debate/'+state.debate.id+'/messages?sort=top&limit=20')||[];
      feedMsgs=msgs;
      document.getElementById('rpFeed').innerHTML='';
      msgs.slice(0,8).forEach(function(m){addFeedMsg(m);});
    }
    renderPhaseContent(state);
    if(state.next&&state.next.question) document.getElementById('nextQ').textContent=state.next.question;
  }
  curRemaining=state.remaining||0;
  clearInterval(countdownInt);
  countdownInt=setInterval(function(){
    curRemaining=Math.max(0,curRemaining-1);
    updateTimer(curRemaining, state.duration||60);
    if(curRemaining<=0){clearInterval(countdownInt);}
  },1000);
}

// SSE for live feed
function connectLiveSSE(){
  var sse=new EventSource('/api/events/global');
  sse.addEventListener('activity',function(e){
    try{var d=JSON.parse(e.data); if(d&&d.username&&d.text){feedMsgs.unshift(d);if(feedMsgs.length>20)feedMsgs.pop();addFeedMsg(d);}}catch(x){}
  });
}

async function init(){
  var d=await api('/me'); me=d&&d.user;
  if(!me) setTimeout(function(){document.getElementById('loginOv').classList.remove('hidden');},2000);
  await pollLive();
  pollInt=setInterval(pollLive, 5000);
  connectLiveSSE();
}
init();
</script></body></html>`;
}

// ─────────────────────────────────────────
// ADMIN PAGE
// ─────────────────────────────────────────
function adminPage(){
  const CATS = ["Technology","Economy","Society","Politics","Education","Life","Work","General"];
  const catOpts = CATS.map(c=>`<option value="${c}">${c}</option>`).join('');
  return `<!doctype html><html lang="en">
<head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Admin — ARGU</title>
${BASE_CSS}
<style>
body{padding-bottom:10px;}
.page{max-width:1100px;margin:0 auto;padding:30px 22px 80px;}
.tabs{display:flex;gap:4px;background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:4px;margin-bottom:26px;flex-wrap:wrap;}
.tab{padding:9px 18px;border-radius:8px;font-family:'Unbounded',sans-serif;font-size:10px;font-weight:700;cursor:pointer;color:var(--muted);border:1px solid transparent;transition:all .14s;background:transparent;}
.tab.on{background:var(--bg3);color:var(--text);border-color:var(--border2);}
.pnl{display:none;} .pnl.on{display:block;}
.kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:9px;margin-bottom:22px;}
.kpi{background:var(--card);border:1px solid var(--border);border-radius:13px;padding:14px;text-align:center;}
.kpi-n{font-family:'Unbounded',sans-serif;font-size:26px;font-weight:900;}
.kpi-l{font-size:9px;color:var(--muted);margin-top:5px;letter-spacing:.1em;text-transform:uppercase;}
.chart-wrap{background:var(--card);border:1px solid var(--border);border-radius:13px;padding:18px;margin-bottom:22px;}
.bar-chart{display:flex;align-items:flex-end;gap:5px;height:88px;margin-top:11px;}
.bar{background:var(--accent);border-radius:4px 4px 0 0;flex:1;min-width:6px;transition:height .3s;}
.bar:hover{opacity:.75;}
.chart-lbl{font-size:9px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);}
.add-form{background:var(--card);border:1px solid var(--border);border-radius:13px;padding:18px;margin-bottom:20px;display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end;}
.add-form input,.add-form select{padding:9px 12px;border-radius:9px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-family:'Manrope',sans-serif;font-size:13px;outline:none;transition:border-color .16s;}
.add-form input:focus,.add-form select:focus{border-color:rgba(59,130,246,.4);}
.add-form input[name=q]{flex:1;min-width:200px;}
table{width:100%;border-collapse:collapse;font-size:12px;}
th{text-align:left;padding:9px 11px;border-bottom:1px solid var(--border);font-size:9px;font-weight:700;letter-spacing:.09em;text-transform:uppercase;color:var(--muted);}
td{padding:9px 11px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:middle;}
[data-theme="light"] td{border-bottom-color:rgba(0,0,0,.05);}
tr:hover td{background:var(--bg3);}
.act-btn{padding:5px 11px;border-radius:7px;border:1px solid var(--border);background:transparent;font-size:11px;cursor:pointer;transition:all .13s;}
.act-btn:hover{border-color:var(--border2);color:var(--text);}
.act-btn.del{color:var(--no);border-color:rgba(239,68,68,.2);} .act-btn.del:hover{background:rgba(239,68,68,.09);}
.act-btn.pri{color:var(--yes);border-color:rgba(59,130,246,.2);} .act-btn.pri:hover{background:var(--yes-dim);}
.pill.ev{background:rgba(245,158,11,.1);color:var(--gold);border:1px solid rgba(245,158,11,.22);}
.pill.qu{background:var(--yes-dim);color:var(--accent);border:1px solid rgba(59,130,246,.2);}
.inline-edit{padding:6px 9px;border-radius:7px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-family:'Manrope',sans-serif;font-size:12px;outline:none;width:100%;}
.cat-item{background:var(--card);border:1px solid var(--border);border-radius:11px;padding:13px 16px;margin-bottom:9px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
.user-item{background:var(--card);border:1px solid var(--border);border-radius:11px;padding:13px 16px;margin-bottom:7px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
.err-box{background:#1a0606;border:1px solid rgba(239,68,68,.3);border-radius:11px;padding:14px 16px;color:var(--no);font-size:13px;margin-bottom:18px;display:none;}
.login-wrap{max-width:360px;margin:80px auto;text-align:center;}
.login-wrap h2{font-family:'Unbounded',sans-serif;font-size:18px;margin-bottom:22px;}
</style>
</head>
<body>
${SHARED_JS}
<nav><div class="nav-inner">
  <a class="logo" href="/">ARGU<span>.</span></a>
  <div class="nav-right" id="navRight">
    <button class="theme-btn" id="themeBtn" onclick="toggleTheme()">☀️</button>
  </div>
</div></nav>

<!-- Login form -->
<div class="page" id="loginView">
  <div class="login-wrap">
    <h2>🛡️ Admin</h2>
    <input id="pwIn" type="password" placeholder="Admin password" style="width:100%;padding:11px 13px;border-radius:11px;border:1px solid var(--border);background:var(--bg2);color:var(--text);font-size:14px;outline:none;margin-bottom:11px;" onkeydown="if(event.key==='Enter')doLogin()"/>
    <button onclick="doLogin()" class="btn btn-blue" style="width:100%;padding:12px;font-size:11px">Sign in →</button>
    <div id="loginErr" style="margin-top:10px;font-size:12px;color:var(--no)"></div>
  </div>
</div>

<!-- Dashboard -->
<div class="page" id="dashView" style="display:none">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;flex-wrap:wrap;gap:9px">
    <h1 style="font-family:'Unbounded',sans-serif;font-size:18px;font-weight:800">🛡️ Admin Dashboard</h1>
    <div style="display:flex;align-items:center;gap:9px">
      <span style="font-size:12px;color:var(--muted2)">Admin</span>
      <button onclick="doLogout()" class="btn btn-out" style="padding:8px 15px;font-size:10px">Sign out</button>
    </div>
  </div>
  <div id="errBox" class="err-box"></div>
  <div class="tabs">
    <button class="tab on" data-pnl="overview">📊 Overview</button>
    <button class="tab" data-pnl="debates">💬 Debates</button>
    <button class="tab" data-pnl="categories">🏷️ Categories</button>
    <button class="tab" data-pnl="users">👥 Users</button>
  </div>

  <!-- Overview -->
  <div class="pnl on" id="pnl-overview">
    <div class="kpis" id="kpis">
      ${Array(4).fill(0).map(()=>`<div class="kpi"><div class="skel" style="height:26px;width:52%;margin:0 auto 7px;border-radius:6px"></div><div class="skel" style="height:9px;width:68%;margin:0 auto;border-radius:3px"></div></div>`).join('')}
    </div>
    <div class="chart-wrap">
      <div class="chart-lbl">📈 Daily Visitors (14 days)</div>
      <div class="bar-chart" id="chart"></div>
    </div>
    <div style="font-family:'Unbounded',sans-serif;font-size:11px;font-weight:700;margin-bottom:13px">Recent Users</div>
    <div id="recentUsers"></div>
  </div>

  <!-- Debates -->
  <div class="pnl" id="pnl-debates">
    <div class="add-form">
      <input name="q" id="newQ" placeholder="Debate question…" maxlength="300"/>
      <select id="newCat">${catOpts}</select>
      <select id="newType"><option value="question">💭 Question</option><option value="event">🌍 Event</option></select>
      <button class="btn btn-blue" onclick="addDebate()" style="padding:9px 18px;font-size:10px">+ Add</button>
    </div>
    <div id="debateErr" style="font-size:12px;color:var(--no);margin-bottom:11px"></div>
    <div id="debatesTable"></div>
  </div>

  <!-- Categories -->
  <div class="pnl" id="pnl-categories">
    <div id="catsView"></div>
  </div>

  <!-- Users -->
  <div class="pnl" id="pnl-users">
    <div id="usersView"></div>
  </div>
</div>

<script>
var allDebates=[], allUsers=[];

// Tabs
document.querySelectorAll('.tab').forEach(function(btn){
  btn.addEventListener('click',function(){
    var pnl=btn.getAttribute('data-pnl');
    document.querySelectorAll('.tab').forEach(function(b){b.classList.toggle('on',b===btn);});
    document.querySelectorAll('.pnl').forEach(function(p){p.classList.toggle('on',p.id==='pnl-'+pnl);});
  });
});

function showErr(msg){
  var eb=document.getElementById('errBox');
  if(!eb) return;
  eb.textContent=msg; eb.style.display='block';
  eb.innerHTML=msg+'<button onclick="retryLoad()" style="margin-left:12px;padding:5px 12px;border-radius:7px;border:1px solid var(--no);background:transparent;color:var(--no);font-size:11px;cursor:pointer">Retry</button>';
}
function hideErr(){var eb=document.getElementById('errBox');if(eb)eb.style.display='none';}

async function doLogin(){
  var pw=(document.getElementById('pwIn')||{}).value||'';
  if(!pw){document.getElementById('loginErr').textContent='Enter password';return;}
  var btn=document.querySelector('#loginView button');
  var errEl=document.getElementById('loginErr');
  var secs=0,ti=null;
  function setBtn(txt){if(btn)btn.textContent=txt;}
  if(btn){btn.disabled=true;}
  errEl.textContent='';
  // Show live countdown so user knows it's working (Render cold start can be 50s)
  setBtn('Connecting… 0s');
  ti=setInterval(function(){secs++;setBtn('Connecting… '+secs+'s');},1000);
  try{
    var resp=await fetch('/admin/login',{
      method:'POST',
      credentials:'same-origin',
      headers:{'content-type':'application/json'},
      body:JSON.stringify({password:pw})
    });
    clearInterval(ti);
    if(btn){btn.disabled=false;}
    var data=await resp.json();
    if(data.error){setBtn('Sign in →');errEl.textContent=data.error;return;}
    setBtn('Sign in →');
    document.getElementById('loginView').style.display='none';
    document.getElementById('dashView').style.display='block';
    document.getElementById('navRight').innerHTML='<span style="font-size:12px;color:var(--muted2)">Admin</span><button class="theme-btn" id="themeBtn" onclick="toggleTheme()">☀️</button>';
    loadAll();
  }catch(e){
    clearInterval(ti);
    if(btn){btn.disabled=false;}
    setBtn('Sign in →');
    errEl.textContent='Connection error: '+e.message+'. Try again.';
  }
}

async function doLogout(){
  await api('/admin/logout',{method:'POST'});
  document.getElementById('dashView').style.display='none';
  document.getElementById('loginView').style.display='block';
  document.getElementById('pwIn').value='';
}

async function checkSession(){
  // Quick 4s check - if already logged in, show dashboard
  // Otherwise just show login form (no blocking)
  var ctrl=new AbortController();
  var tid=setTimeout(function(){ctrl.abort();},4000);
  try{
    var r=await fetch('/admin/api/stats',{credentials:'same-origin',headers:{'content-type':'application/json'},signal:ctrl.signal});
    clearTimeout(tid);
    if(!r.ok) return; // not logged in
    var data=await r.json();
    if(data&&!data.error){
      document.getElementById('loginView').style.display='none';
      document.getElementById('dashView').style.display='block';
      document.getElementById('navRight').innerHTML='<span style="font-size:12px;color:var(--muted2)">Admin</span><button class="theme-btn" id="themeBtn" onclick="toggleTheme()">☀️</button>';
      renderStats(data);
      loadDebatesPanel();
      loadUsersPanel();
    }
  }catch(e){clearTimeout(tid);}
}

async function loadAll(){
  hideErr();
  try{
    var r=await fetch('/admin/api/stats',{credentials:'same-origin',headers:{'content-type':'application/json'}});
    if(!r.ok){showErr('Error '+r.status+' — try refreshing');return;}
    var data=await r.json();
    if(data.error){showErr('Error: '+data.error);return;}
    renderStats(data);
  }catch(e){showErr('Network error: '+e.message);return;}
  loadDebatesPanel();
  loadUsersPanel();
}

function retryLoad(){hideErr();loadAll();}

function renderStats(d){
  var kpis=[{n:d.debates,l:'Debates'},{n:d.args,l:'Arguments'},{n:d.users,l:'Users'},{n:d.visitors_today,l:'Today visitors'}];
  document.getElementById('kpis').innerHTML=kpis.map(function(k){return '<div class="kpi"><div class="kpi-n">'+k.n+'</div><div class="kpi-l">'+k.l+'</div></div>';}).join('');
  var chart=d.daily_visitors||[], maxV=Math.max(...chart.map(function(x){return x.count;}),1);
  document.getElementById('chart').innerHTML=chart.map(function(x){
    var h=Math.max(6,Math.round(x.count/maxV*88));
    return '<div class="bar" style="height:'+h+'px" title="'+x.date+': '+x.count+' visitors"></div>';
  }).join('');
  if(d.recent_users&&d.recent_users.length){
    document.getElementById('recentUsers').innerHTML='<table><thead><tr><th>Username</th><th>Joined</th><th>Rating</th><th>Args</th></tr></thead><tbody>'+d.recent_users.map(function(u){return '<tr><td><a href="/u/'+esc(u.username)+'" target="_blank" style="font-weight:600">'+esc(u.username)+'</a></td><td style="color:var(--muted2)">'+new Date(u.created_at).toLocaleDateString()+'</td><td>★ '+u.rating+'</td><td>'+u.arg_count+'</td></tr>';}).join('')+'</tbody></table>';
  }
}

async function loadDebatesPanel(){
  try{
    var r=await fetch('/admin/api/stats',{credentials:'same-origin',headers:{'content-type':'application/json'}});
    var data=await r.json();
    if(!data||data.error) return;
    allDebates=data.debates_list||[];
    renderDebatesTable();
  }catch(e){}
}

function renderDebatesTable(){
  var t='<table><thead><tr><th>#</th><th>Question</th><th>Cat</th><th>Type</th><th>Args</th><th>Active</th><th>Actions</th></tr></thead><tbody>';
  allDebates.forEach(function(d){
    t+='<tr>'
      +'<td style="color:var(--muted);font-size:10px">'+d.id+'</td>'
      +'<td style="max-width:280px"><div style="font-weight:600;font-size:12px;line-height:1.3">'+esc(d.question)+'</div></td>'
      +'<td><input class="inline-edit" style="width:110px" value="'+esc(d.category)+'" onchange="updateDebate('+d.id+',\'category\',this.value)"/></td>'
      +'<td><select class="inline-edit" style="width:92px" onchange="updateDebate('+d.id+',\'type\',this.value)">'
        +'<option value="question"'+(d.type==='question'?' selected':'')+'>💭 Q</option>'
        +'<option value="event"'+(d.type==='event'?' selected':'')+'>🌍 Ev</option>'
      +'</select></td>'
      +'<td style="font-weight:600">'+d.arg_count+'</td>'
      +'<td style="color:'+(d.active?'var(--green)':'var(--no)')+'">'+((d.active)?'✓':'✗')+'</td>'
      +'<td style="display:flex;gap:4px;flex-wrap:wrap">'
        +'<button class="act-btn pri" onclick="toggleDebate('+d.id+')">'+((d.active)?'Hide':'Show')+'</button>'
        +'<button class="act-btn del" onclick="delDebate('+d.id+')">Del</button>'
      +'</td>'
    +'</tr>';
  });
  t+='</tbody></table>';
  document.getElementById('debatesTable').innerHTML=t;
}

async function addDebate(){
  var q=(document.getElementById('newQ')||{}).value||''; q=q.trim();
  var cat=(document.getElementById('newCat')||{}).value||'General';
  var type=(document.getElementById('newType')||{}).value||'question';
  if(!q){document.getElementById('debateErr').textContent='Enter a question';return;}
  var r=await api('/admin/debates',{method:'POST',body:JSON.stringify({question:q,category:cat,type:type})});
  if(!r||r.error){document.getElementById('debateErr').textContent=(r&&r.error)||'Error';return;}
  document.getElementById('debateErr').textContent='';
  document.getElementById('newQ').value='';
  toast('Debate added!','success');
  await loadDebatesPanel();
}

async function updateDebate(id, field, val){
  var payload={};
  // fetch existing to preserve other fields
  var d=allDebates.find(function(x){return x.id===id;});
  if(d) payload={question:d.question,category:d.category,type:d.type};
  payload[field]=val;
  var r=await api('/admin/debates/'+id,{method:'PATCH',body:JSON.stringify(payload)});
  if(!r||r.error){toast((r&&r.error)||'Error','error');return;}
  toast('Updated!','success');
  if(d) d[field]=val;
}

async function toggleDebate(id){
  var r=await api('/admin/debates/'+id+'/toggle',{method:'POST'});
  if(!r||r.error){toast((r&&r.error)||'Error','error');return;}
  await loadDebatesPanel();
}

async function delDebate(id){
  if(!confirm('Delete debate #'+id+' and all its messages?')) return;
  var r=await api('/admin/debates/'+id,{method:'DELETE'});
  if(!r||r.error){toast((r&&r.error)||'Error','error');return;}
  toast('Deleted','success'); await loadDebatesPanel();
}

async function loadUsersPanel(){
  try{
    var r=await fetch('/admin/api/stats',{credentials:'same-origin',headers:{'content-type':'application/json'}});
    var data=await r.json();
    if(!data||data.error) return;
    allUsers=data.all_users||[];
    renderCatsPanel(data.categories||[]);
    renderUsersTable();
}

function renderCatsPanel(cats){
  if(!cats.length){document.getElementById('catsView').innerHTML='<div style="color:var(--muted);font-size:13px">No categories found</div>';return;}
  document.getElementById('catsView').innerHTML=cats.map(function(c){
    return '<div class="cat-item"><strong style="flex:1">'+esc(c.category)+'</strong><span style="font-size:12px;color:var(--muted2)">'+c.count+' debates</span>'
      +'<button class="act-btn del" onclick="deleteCategory(\''+esc(c.category)+'\')">Delete cat</button></div>';
  }).join('');
}

async function deleteCategory(name){
  var action=prompt('Delete "'+name+'" category. Type "delete" to remove all, or a category name to move debates to it:');
  if(!action) return;
  var r;
  if(action==='delete'){r=await api('/admin/category/'+encodeURIComponent(name),{method:'DELETE',body:JSON.stringify({action:'delete'})});}
  else{r=await api('/admin/category/'+encodeURIComponent(name),{method:'DELETE',body:JSON.stringify({action:'move',target:action})});}
  if(!r||r.error){toast((r&&r.error)||'Error','error');return;}
  toast('Done','success'); await loadUsersPanel();
}

function renderUsersTable(){
  document.getElementById('usersView').innerHTML='<table><thead><tr><th>Username</th><th>Rating</th><th>Args</th><th>Joined</th><th>Actions</th></tr></thead><tbody>'
    +allUsers.map(function(u){
      return '<tr>'
        +'<td><a href="/u/'+esc(u.username)+'" target="_blank" style="font-weight:700">'+esc(u.username)+'</a></td>'
        +'<td><input class="inline-edit" type="number" style="width:70px" value="'+u.rating+'" onchange="setRating(\''+esc(u.username)+'\',this.value)"/></td>'
        +'<td>'+u.arg_count+'</td>'
        +'<td style="color:var(--muted2)">'+new Date(u.created_at).toLocaleDateString()+'</td>'
        +'<td><button class="act-btn del" onclick="delUser(\''+esc(u.username)+'\')">Delete</button></td>'
      +'</tr>';
    }).join('')
    +'</tbody></table>';
}

async function setRating(username, rating){
  var r=await api('/admin/users/'+encodeURIComponent(username)+'/rating',{method:'PATCH',body:JSON.stringify({rating:parseInt(rating,10)||0})});
  if(!r||r.error){toast((r&&r.error)||'Error','error');return;}
  toast('Rating updated','success');
}

async function delUser(username){
  if(!confirm('Delete user "'+username+'" and all their data?')) return;
  var r=await api('/admin/users/'+encodeURIComponent(username),{method:'DELETE'});
  if(!r||r.error){toast((r&&r.error)||'Error','error');return;}
  toast('Deleted','success'); await loadUsersPanel();
}

checkSession();
</script></body></html>`;
}

// ─────────────────────────────────────────
// PAGE ROUTES
// ─────────────────────────────────────────
app.get("/", wrap(async(req,res)=>{
  trackView(req, res, '/');
  res.send(landingPage());
}));
app.get("/explore", wrap(async(req,res)=>{
  trackView(req, res, '/explore');
  res.send(explorePage());
}));
app.get("/live", wrap(async(req,res)=>{
  res.send(livePage());
}));
app.get("/debate", (req,res)=>res.redirect("/explore"));
app.get("/debate/:id", wrap(async(req,res)=>{
  const id=parseInt(req.params.id,10);
  if(!Number.isFinite(id)) return res.redirect("/explore");
  const r=await pool.query("SELECT id,question,category,type FROM debates WHERE id=$1 AND active=TRUE",[id]);
  if(!r.rows[0]) return res.redirect("/explore");
  trackView(req, res, '/debate/'+id);
  const d=r.rows[0];
  res.send(debatePage(d.id, d.question, d.category, d.type||'question'));
}));
app.get("/u/:username", wrap(async(req,res)=>{
  res.send(profilePage(req.params.username));
}));
app.get("/admin", (req,res)=>{
  res.send(adminPage());
});

// admin stats needs debates_list, categories, all_users
app.get("/admin/api/stats", requireAdmin, wrap(async(req,res)=>{
  const [kpi,chart,debates,recentUsers,allUsers,cats] = await Promise.all([
    pool.query(`SELECT
      (SELECT COUNT(*)::int FROM debates WHERE active=TRUE) AS debates,
      (SELECT COUNT(*)::int FROM messages) AS args,
      (SELECT COUNT(*)::int FROM users) AS users,
      (SELECT COUNT(DISTINCT visitor_id)::int FROM page_views WHERE created_at >= NOW()-INTERVAL '1 day') AS visitors_today`),
    pool.query(`SELECT to_char(d,'YYYY-MM-DD') AS date,COUNT(DISTINCT visitor_id)::int AS count FROM generate_series(NOW()-INTERVAL '13 days',NOW(),'1 day'::interval) AS d LEFT JOIN page_views pv ON to_char(pv.created_at,'YYYY-MM-DD')=to_char(d,'YYYY-MM-DD') GROUP BY d ORDER BY d`),
    pool.query(`SELECT d.id,d.question,d.category,d.type,d.active,COUNT(m.id)::int AS arg_count FROM debates d LEFT JOIN messages m ON m.debate_id=d.id GROUP BY d.id ORDER BY d.id DESC`),
    pool.query(`SELECT u.username,u.created_at,u.rating,COUNT(m.id)::int AS arg_count FROM users u LEFT JOIN messages m ON m.user_id=u.id GROUP BY u.id ORDER BY u.created_at DESC LIMIT 10`),
    pool.query(`SELECT u.username,u.created_at,u.rating,COUNT(m.id)::int AS arg_count FROM users u LEFT JOIN messages m ON m.user_id=u.id GROUP BY u.id ORDER BY u.rating DESC LIMIT 100`),
    pool.query(`SELECT category,COUNT(*)::int FROM debates WHERE active=TRUE GROUP BY category ORDER BY count DESC`)
  ]);
  const k=kpi.rows[0];
  res.json({
    debates:k.debates,args:k.args,users:k.users,visitors_today:k.visitors_today,
    daily_visitors:chart.rows,
    debates_list:debates.rows,
    recent_users:recentUsers.rows,
    all_users:allUsers.rows,
    categories:cats.rows
  });
}));

app.use((err,req,res,_next)=>{
  console.error(err);
  res.status(500).json({error:"Internal server error"});
});

const PORT = process.env.PORT || 3000;
app.listen(PORT,"0.0.0.0",()=>console.log("ARGU running on :"+PORT));