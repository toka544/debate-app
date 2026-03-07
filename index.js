require("dotenv").config();
const express      = require("express");
const cookieParser = require("cookie-parser");
const rateLimit    = require("express-rate-limit");
const crypto       = require("crypto");
const { Pool }     = require("pg");

const app = express();
app.set("trust proxy", 1);
app.use(express.json());
app.use(cookieParser());

if (!process.env.DATABASE_URL) { console.error("DATABASE_URL not set"); process.exit(1); }
const ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || "admin123").trim();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: (process.env.DATABASE_URL || "").includes("render.com") ? { rejectUnauthorized: false } : undefined,
  max: 20, idleTimeoutMillis: 30000, connectionTimeoutMillis: 5000,
});
pool.on("error", err => console.error("DB pool error:", err.message));

// SSE
const sseDebate = new Map();
const sseGlobal = new Set();
function sseAdd(map,key,res){if(!map.has(key))map.set(key,new Set());map.get(key).add(res);}
function sseRemove(map,key,res){map.get(key)?.delete(res);if(map.get(key)?.size===0)map.delete(key);}
function sseSend(res,event,data){try{res.write("event:"+event+"\ndata:"+JSON.stringify(data)+"\n\n");}catch{}}
function broadcastDebate(debateId,event,data){sseDebate.get(debateId)?.forEach(r=>sseSend(r,event,data));}
function broadcastGlobal(event,data){sseGlobal.forEach(r=>sseSend(r,event,data));}

const wrap = fn => (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next);
function esc(s){return String(s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");}
async function getMe(req){
  const u=req.cookies?.username; if(!u)return null;
  try{const r=await pool.query("SELECT id,username,rating FROM users WHERE username=$1",[u]);return r.rows[0]??null;}
  catch{return null;}
}
function getVisitorId(req,res){
  let vid=req.cookies?.visitor_id;
  if(!vid){vid=crypto.randomBytes(12).toString("hex");res.cookie("visitor_id",vid,{httpOnly:true,sameSite:"lax",maxAge:365*24*3600*1000});}
  return vid;
}
function trackView(req,res,path){pool.query("INSERT INTO page_views(path,visitor_id)VALUES($1,$2)",[path,getVisitorId(req,res)]).catch(()=>{});}
function requireAdmin(req,res,next){
  if((req.cookies?.admin_session||"").trim()===ADMIN_PASSWORD)return next();
  return res.status(401).type("html").send(adminLoginPage(""));
}

const loginLimiter    = rateLimit({windowMs:60000,max:20,standardHeaders:true,legacyHeaders:false,message:{error:"Too many attempts"}});
const messageLimiter  = rateLimit({windowMs:60000,max:10,standardHeaders:true,legacyHeaders:false,message:{error:"Max 10 posts/min"}});
const voteLimiter     = rateLimit({windowMs:60000,max:120,standardHeaders:true,legacyHeaders:false,message:{error:"Voting too fast"}});
const reactionLimiter = rateLimit({windowMs:60000,max:60,standardHeaders:true,legacyHeaders:false,message:{error:"Too many reactions"}});
const replyLimiter    = rateLimit({windowMs:60000,max:10,standardHeaders:true,legacyHeaders:false,message:{error:"Replying too fast"}});

app.get("/api/events/debate/:id",(req,res)=>{
  const id=parseInt(req.params.id,10); if(!Number.isFinite(id))return res.status(400).end();
  res.setHeader("Content-Type","text/event-stream");res.setHeader("Cache-Control","no-cache");
  res.setHeader("Connection","keep-alive");res.setHeader("X-Accel-Buffering","no");res.flushHeaders();
  sseSend(res,"connected",{id}); sseAdd(sseDebate,id,res);
  const hb=setInterval(()=>{try{res.write(":hb\n\n");}catch{}},25000);
  req.on("close",()=>{clearInterval(hb);sseRemove(sseDebate,id,res);});
});
app.get("/api/events/global",(req,res)=>{
  res.setHeader("Content-Type","text/event-stream");res.setHeader("Cache-Control","no-cache");
  res.setHeader("Connection","keep-alive");res.setHeader("X-Accel-Buffering","no");res.flushHeaders();
  sseSend(res,"connected",{}); sseGlobal.add(res);
  const hb=setInterval(()=>{try{res.write(":hb\n\n");}catch{}},25000);
  req.on("close",()=>{clearInterval(hb);sseGlobal.delete(res);});
});

app.post("/auth/login",loginLimiter,wrap(async(req,res)=>{
  const u=(req.body?.username||"").trim().replace(/\s+/g,"_");
  if(!u||u.length<3||u.length>20)return res.status(400).json({error:"Username must be 3-20 chars"});
  if(!/^[a-zA-Z0-9_]+$/.test(u))return res.status(400).json({error:"Only letters, numbers, _ allowed"});
  await pool.query("INSERT INTO users(username)VALUES($1)ON CONFLICT(username)DO NOTHING",[u]);
  res.cookie("username",u,{httpOnly:true,sameSite:"lax"});
  const r=await pool.query("SELECT id,username,rating FROM users WHERE username=$1",[u]);
  res.json({success:true,user:r.rows[0]});
}));
app.post("/auth/logout",(req,res)=>{res.clearCookie("username");res.json({success:true});});
app.get("/me",wrap(async(req,res)=>res.json({user:await getMe(req)})));

const GOOGLE_CLIENT_ID=process.env.GOOGLE_CLIENT_ID||"";
const GOOGLE_CLIENT_SECRET=process.env.GOOGLE_CLIENT_SECRET||"";
const GOOGLE_REDIRECT=process.env.GOOGLE_REDIRECT_URI||"https://debate-app-o3qw.onrender.com/auth/google/callback";

app.get("/auth/google",(req,res)=>{
  if(!GOOGLE_CLIENT_ID)return res.status(500).send("Google auth not configured");
  const p=new URLSearchParams({client_id:GOOGLE_CLIENT_ID,redirect_uri:GOOGLE_REDIRECT,response_type:"code",scope:"openid email profile",prompt:"select_account"});
  res.redirect("https://accounts.google.com/o/oauth2/v2/auth?"+p.toString());
});
app.get("/auth/google/callback",wrap(async(req,res)=>{
  const code=req.query.code; if(!code)return res.redirect("/?error=no_code");
  const tokenRes=await fetch("https://oauth2.googleapis.com/token",{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},body:new URLSearchParams({code,client_id:GOOGLE_CLIENT_ID,client_secret:GOOGLE_CLIENT_SECRET,redirect_uri:GOOGLE_REDIRECT,grant_type:"authorization_code"})});
  const tokens=await tokenRes.json(); if(!tokens.access_token)return res.redirect("/?error=token_failed");
  const info=await (await fetch("https://www.googleapis.com/oauth2/v2/userinfo",{headers:{Authorization:"Bearer "+tokens.access_token}})).json();
  if(!info.email)return res.redirect("/?error=no_email");
  const base=(info.name||info.email.split("@")[0]).replace(/[^a-zA-Z0-9_]/g,"_").replace(/_+/g,"_").slice(0,18)||"user";
  let fin=base;
  const ex=await pool.query("SELECT username FROM users WHERE username=$1",[fin]);
  if(ex.rows[0]){const s=info.id?info.id.slice(-4):Math.floor(Math.random()*9000+1000).toString();fin=(base.slice(0,14)+"_"+s).slice(0,20);}
  await pool.query("INSERT INTO users(username)VALUES($1)ON CONFLICT(username)DO NOTHING",[fin]);
  res.cookie("username",fin,{httpOnly:true,sameSite:"lax"}); res.redirect("/");
}));

app.get("/api/search",wrap(async(req,res)=>{
  const q=(req.query.q||"").trim(); if(!q||q.length<2)return res.json([]);
  const r=await pool.query(`SELECT d.id,d.question,d.category,d.type,COUNT(m.id)::int AS arg_count,COUNT(CASE WHEN m.side='YES' THEN 1 END)::int AS yes_count,COUNT(CASE WHEN m.side='NO' THEN 1 END)::int AS no_count FROM debates d LEFT JOIN messages m ON m.debate_id=d.id WHERE d.active=TRUE AND d.question ILIKE $1 GROUP BY d.id ORDER BY arg_count DESC LIMIT 20`,["%"+q+"%"]);
  res.json(r.rows);
}));

app.get("/api/debates",wrap(async(req,res)=>{
  const sort=req.query.sort||"new";
  let ob; if(sort==="hot")ob="(COUNT(m.id)/POWER(EXTRACT(EPOCH FROM(NOW()-d.created_at))/3600+2,1.3))DESC"; else if(sort==="top")ob="COUNT(m.id)DESC,d.id DESC"; else ob="d.id DESC";
  const r=await pool.query(`SELECT d.id,d.question,d.category,d.type,COUNT(m.id)::int AS arg_count,COUNT(CASE WHEN m.side='YES' THEN 1 END)::int AS yes_count,COUNT(CASE WHEN m.side='NO' THEN 1 END)::int AS no_count FROM debates d LEFT JOIN messages m ON m.debate_id=d.id WHERE d.active=TRUE GROUP BY d.id ORDER BY ${ob}`);
  res.json(r.rows);
}));

app.get("/leaderboard/users",wrap(async(req,res)=>{
  const lim=Math.min(parseInt(req.query.limit||"10",10),100);
  res.json((await pool.query("SELECT username,rating FROM users ORDER BY rating DESC,id ASC LIMIT $1",[lim])).rows);
}));

app.get("/debate/:id/messages",wrap(async(req,res)=>{
  const did=parseInt(req.params.id,10); if(!Number.isFinite(did))return res.status(400).json({error:"Bad id"});
  const sort=req.query.sort==="top"?"top":"new";
  const ob=sort==="top"?"m.score DESC,m.created_at DESC":"m.created_at DESC";
  const lim=Math.min(parseInt(req.query.limit||"50",10),200);
  const r=await pool.query(`SELECT m.id,m.side,m.text,m.score,m.created_at,m.parent_id,u.username,COALESCE(SUM(CASE WHEN r.emoji='fire' THEN 1 END),0)::int AS fire_count,COALESCE(SUM(CASE WHEN r.emoji='think' THEN 1 END),0)::int AS think_count,COALESCE(SUM(CASE WHEN r.emoji='idea' THEN 1 END),0)::int AS idea_count,(SELECT COUNT(*)::int FROM messages c WHERE c.parent_id=m.id)AS reply_count FROM messages m JOIN users u ON u.id=m.user_id LEFT JOIN reactions r ON r.message_id=m.id WHERE m.debate_id=$1 AND m.parent_id IS NULL GROUP BY m.id,u.username ORDER BY ${ob} LIMIT $2`,[did,lim]);
  res.json(r.rows);
}));

app.get("/messages/:id/replies",wrap(async(req,res)=>{
  const mid=parseInt(req.params.id,10); if(!Number.isFinite(mid))return res.status(400).json({error:"Bad id"});
  const r=await pool.query(`SELECT m.id,m.side,m.text,m.score,m.created_at,m.parent_id,u.username,COALESCE(SUM(CASE WHEN r.emoji='fire' THEN 1 END),0)::int AS fire_count,COALESCE(SUM(CASE WHEN r.emoji='think' THEN 1 END),0)::int AS think_count,COALESCE(SUM(CASE WHEN r.emoji='idea' THEN 1 END),0)::int AS idea_count FROM messages m JOIN users u ON u.id=m.user_id LEFT JOIN reactions r ON r.message_id=m.id WHERE m.parent_id=$1 GROUP BY m.id,u.username ORDER BY m.created_at ASC LIMIT 50`,[mid]);
  res.json(r.rows);
}));

app.post("/debate/:id/messages",messageLimiter,wrap(async(req,res)=>{
  const me=await getMe(req); if(!me)return res.status(401).json({error:"Login first"});
  const did=parseInt(req.params.id,10); if(!Number.isFinite(did))return res.status(400).json({error:"Bad id"});
  const ex=await pool.query("SELECT 1 FROM debates WHERE id=$1 AND active=TRUE",[did]); if(!ex.rows[0])return res.status(404).json({error:"Not found"});
  const text=String(req.body?.text||"").trim(), side=String(req.body?.side||"").toUpperCase();
  const parentId=req.body?.parent_id?parseInt(req.body.parent_id,10):null;
  if(!text)return res.status(400).json({error:"Text required"}); if(text.length>300)return res.status(400).json({error:"Max 300 chars"});
  if(side!=="YES"&&side!=="NO")return res.status(400).json({error:"Side YES or NO"});
  if(parentId){const pe=await pool.query("SELECT 1 FROM messages WHERE id=$1 AND debate_id=$2",[parentId,did]);if(!pe.rows[0])return res.status(404).json({error:"Parent not found"});}
  const r=await pool.query("INSERT INTO messages(debate_id,user_id,side,text,parent_id)VALUES($1,$2,$3,$4,$5)RETURNING id,created_at",[did,me.id,side,text,parentId||null]);
  const msg={id:r.rows[0].id,debate_id:did,user_id:me.id,username:me.username,side,text,score:0,created_at:r.rows[0].created_at,parent_id:parentId||null,fire_count:0,think_count:0,idea_count:0,reply_count:0};
  broadcastDebate(did,"new_message",msg); broadcastGlobal("activity",{type:"new_message",debateId:did,username:me.username});
  res.status(201).json({success:true,id:r.rows[0].id});
}));

app.post("/messages/:id/reply",replyLimiter,wrap(async(req,res)=>{
  const me=await getMe(req); if(!me)return res.status(401).json({error:"Login first"});
  const pid=parseInt(req.params.id,10); if(!Number.isFinite(pid))return res.status(400).json({error:"Bad id"});
  const parent=await pool.query("SELECT debate_id,side FROM messages WHERE id=$1",[pid]); if(!parent.rows[0])return res.status(404).json({error:"Not found"});
  const text=String(req.body?.text||"").trim(); if(!text)return res.status(400).json({error:"Text required"}); if(text.length>300)return res.status(400).json({error:"Max 300"});
  const did=parent.rows[0].debate_id, side=parent.rows[0].side;
  const r=await pool.query("INSERT INTO messages(debate_id,user_id,side,text,parent_id)VALUES($1,$2,$3,$4,$5)RETURNING id,created_at",[did,me.id,side,text,pid]);
  broadcastDebate(did,"new_reply",{id:r.rows[0].id,debate_id:did,parent_id:pid,username:me.username,side,text,score:0,created_at:r.rows[0].created_at});
  res.status(201).json({success:true,id:r.rows[0].id});
}));

app.post("/messages/:id/vote",voteLimiter,wrap(async(req,res)=>{
  const me=await getMe(req); if(!me)return res.status(401).json({error:"Login first"});
  const mid=parseInt(req.params.id,10); if(!Number.isFinite(mid))return res.status(400).json({error:"Bad id"});
  const value=parseInt(req.body?.value,10); if(value!==1&&value!==-1)return res.status(400).json({error:"Value 1 or -1"});
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    const vr=await client.query("SELECT rating FROM users WHERE id=$1",[me.id]);
    const weight=Math.min(5,1+Math.floor((vr.rows[0]?.rating??0)/50));
    const mr=await client.query("SELECT id,user_id,debate_id FROM messages WHERE id=$1 FOR UPDATE",[mid]);
    const msg=mr.rows[0]; if(!msg){await client.query("ROLLBACK");return res.status(404).json({error:"Not found"});}
    if(msg.user_id===me.id){await client.query("ROLLBACK");return res.status(400).json({error:"Can't vote own message"});}
    const er=await client.query("SELECT id,value,weight FROM votes WHERE message_id=$1 AND user_id=$2",[mid,me.id]);
    const existing=er.rows[0]; let dv=0;
    if(!existing){await client.query("INSERT INTO votes(message_id,user_id,value,weight)VALUES($1,$2,$3,$4)",[mid,me.id,value,weight]);dv=value*weight;}
    else if(existing.value===value){await client.query("DELETE FROM votes WHERE id=$1",[existing.id]);dv=-(existing.value*existing.weight);}
    else{await client.query("UPDATE votes SET value=$1,weight=$2 WHERE id=$3",[value,weight,existing.id]);dv=(value*weight)-(existing.value*existing.weight);}
    let ns=null;
    if(dv!==0){const sr=await client.query("UPDATE messages SET score=score+$1 WHERE id=$2 RETURNING score",[dv,mid]);ns=sr.rows[0]?.score;await client.query("UPDATE users SET rating=rating+$1 WHERE id=$2",[dv*3,msg.user_id]);}
    await client.query("COMMIT");
    if(ns!==null)broadcastDebate(msg.debate_id,"vote_update",{messageId:mid,newScore:ns});
    res.json({success:true,deltaVote:dv,weightUsed:weight,newScore:ns});
  }catch(e){await client.query("ROLLBACK").catch(()=>{});throw e;}finally{client.release();}
}));

app.post("/messages/:id/react",reactionLimiter,wrap(async(req,res)=>{
  const me=await getMe(req); if(!me)return res.status(401).json({error:"Login first"});
  const mid=parseInt(req.params.id,10); if(!Number.isFinite(mid))return res.status(400).json({error:"Bad id"});
  const emoji=req.body?.emoji; if(!["fire","think","idea"].includes(emoji))return res.status(400).json({error:"Invalid emoji"});
  const ex=await pool.query("SELECT id FROM reactions WHERE message_id=$1 AND user_id=$2 AND emoji=$3",[mid,me.id,emoji]);
  if(ex.rows[0]){await pool.query("DELETE FROM reactions WHERE id=$1",[ex.rows[0].id]);res.json({success:true,action:"removed"});}
  else{await pool.query("INSERT INTO reactions(message_id,user_id,emoji)VALUES($1,$2,$3)",[mid,me.id,emoji]);res.json({success:true,action:"added"});}
}));

app.get("/api/user/:username",wrap(async(req,res)=>{
  const ur=await pool.query("SELECT id,username,rating,created_at FROM users WHERE username=$1",[req.params.username]);
  if(!ur.rows[0])return res.status(404).json({error:"Not found"});
  const u=ur.rows[0];
  const st=await pool.query("SELECT COUNT(*)::int AS total_args,COUNT(CASE WHEN side='YES' THEN 1 END)::int AS yes_args,COUNT(CASE WHEN side='NO' THEN 1 END)::int AS no_args,COALESCE(SUM(CASE WHEN score>0 THEN score END),0)::int AS total_upvotes,COALESCE(MAX(score),0)::int AS best_score FROM messages WHERE user_id=$1 AND parent_id IS NULL",[u.id]);
  const ms=await pool.query("SELECT m.id,m.side,m.text,m.score,m.created_at,d.id AS debate_id,d.question FROM messages m JOIN debates d ON d.id=m.debate_id WHERE m.user_id=$1 AND m.parent_id IS NULL ORDER BY m.score DESC,m.created_at DESC LIMIT 10",[u.id]);
  const rk=await pool.query("SELECT COUNT(*)::int AS rank FROM users WHERE rating>$1",[u.rating]);
  res.json({user:u,stats:st.rows[0],top_messages:ms.rows,rank:(rk.rows[0]?.rank??0)+1});
}));
// Admin API
app.post("/admin/login",(req,res)=>{
  const pw=(req.body?.password||"").trim();
  if(pw!==ADMIN_PASSWORD)return res.status(401).json({error:"Wrong password"});
  res.cookie("admin_session",ADMIN_PASSWORD,{httpOnly:true,sameSite:"lax",maxAge:7*24*3600*1000});
  res.json({success:true});
});
app.post("/admin/logout",(req,res)=>{res.clearCookie("admin_session");res.redirect("/admin");});

app.post("/admin/debates",requireAdmin,wrap(async(req,res)=>{
  const q=(req.body?.question||"").trim(),cat=(req.body?.category||"General").trim(),typ=req.body?.type==="event"?"event":"question";
  if(!q)return res.status(400).json({error:"Question required"});
  const r=await pool.query("INSERT INTO debates(question,category,type)VALUES($1,$2,$3)RETURNING id,question,category,type,active",[q,cat,typ]);
  broadcastGlobal("new_debate",r.rows[0]); res.json({success:true});
}));
app.post("/admin/debates/:id/toggle",requireAdmin,wrap(async(req,res)=>{
  const id=parseInt(req.params.id,10); if(!Number.isFinite(id))return res.status(400).json({error:"Bad id"});
  await pool.query("UPDATE debates SET active=NOT active WHERE id=$1",[id]); res.json({success:true});
}));
app.delete("/admin/debates/:id",requireAdmin,wrap(async(req,res)=>{
  const id=parseInt(req.params.id,10); if(!Number.isFinite(id))return res.status(400).json({error:"Bad id"});
  await pool.query("DELETE FROM debates WHERE id=$1",[id]); res.json({success:true});
}));
app.patch("/admin/debates/:id",requireAdmin,wrap(async(req,res)=>{
  const id=parseInt(req.params.id,10), q=(req.body?.question||"").trim(), cat=(req.body?.category||"").trim(), typ=req.body?.type==="event"?"event":"question";
  if(!q||!cat)return res.status(400).json({error:"question and category required"});
  await pool.query("UPDATE debates SET question=$1,category=$2,type=$3 WHERE id=$4",[q,cat,typ,id]); res.json({success:true});
}));
app.delete("/admin/category/:name",requireAdmin,wrap(async(req,res)=>{
  const name=decodeURIComponent(req.params.name), action=req.body?.action||"move", target=(req.body?.target||"General").trim();
  if(action==="delete")await pool.query("DELETE FROM debates WHERE category=$1",[name]);
  else await pool.query("UPDATE debates SET category=$1 WHERE category=$2",[target,name]);
  res.json({success:true});
}));
app.delete("/admin/messages/:id",requireAdmin,wrap(async(req,res)=>{
  const id=parseInt(req.params.id,10); if(!Number.isFinite(id))return res.status(400).json({error:"Bad id"});
  await pool.query("DELETE FROM messages WHERE id=$1",[id]); res.json({success:true});
}));
app.delete("/admin/users/:username",requireAdmin,wrap(async(req,res)=>{
  const u=req.params.username;
  const ur=await pool.query("SELECT id FROM users WHERE username=$1",[u]); if(!ur.rows[0])return res.status(404).json({error:"Not found"});
  const uid=ur.rows[0].id;
  await pool.query("DELETE FROM votes WHERE user_id=$1",[uid]);
  await pool.query("DELETE FROM reactions WHERE user_id=$1",[uid]);
  await pool.query("DELETE FROM messages WHERE user_id=$1",[uid]);
  await pool.query("DELETE FROM users WHERE id=$1",[uid]);
  res.json({success:true});
}));
app.patch("/admin/users/:username/rating",requireAdmin,wrap(async(req,res)=>{
  const rating=parseInt(req.body?.rating??0,10); if(!Number.isFinite(rating))return res.status(400).json({error:"Bad rating"});
  await pool.query("UPDATE users SET rating=$1 WHERE username=$2",[rating,req.params.username]); res.json({success:true});
}));

app.get("/admin/api/stats",requireAdmin,wrap(async(req,res)=>{
  const safe=async(q,p=[])=>{try{return(await pool.query(q,p)).rows;}catch(e){console.error("stats err:",e.message);return[];}};
  const [dr,ur,mr,vr,day,top,recU]=await Promise.all([
    safe("SELECT COUNT(*)::int AS count FROM debates WHERE active=TRUE"),
    safe("SELECT COUNT(*)::int AS count FROM users"),
    safe("SELECT COUNT(*)::int AS count FROM messages"),
    safe("SELECT COUNT(*)::int AS total,COUNT(DISTINCT visitor_id)::int AS unique_visitors FROM page_views"),
    safe("SELECT DATE(created_at)AS day,COUNT(*)::int AS views,COUNT(DISTINCT visitor_id)::int AS uniq FROM page_views WHERE created_at>NOW()-INTERVAL '14 days' GROUP BY day ORDER BY day DESC"),
    safe("SELECT d.id,d.question,d.category,d.type,d.active,COUNT(m.id)::int AS arg_count,COALESCE((SELECT COUNT(*)::int FROM page_views WHERE path='/debate/'||d.id::text),0)AS views FROM debates d LEFT JOIN messages m ON m.debate_id=d.id GROUP BY d.id ORDER BY d.id ASC"),
    safe("SELECT username,rating,created_at,(SELECT COUNT(*)::int FROM messages WHERE user_id=users.id)AS arg_count FROM users ORDER BY created_at DESC LIMIT 20"),
  ]);
  res.json({debates:dr[0]?.count??0,users:ur[0]?.count??0,messages:mr[0]?.count??0,total_views:vr[0]?.total??0,unique_visitors:vr[0]?.unique_visitors??0,daily:day,top_debates:top,recent_users:recU});
}));

// Live debate state
const LIVE_PHASES=[{name:"read",duration:15},{name:"argue",duration:60},{name:"vote",duration:45}];
const ROUND_TOTAL=LIVE_PHASES.reduce((s,p)=>s+p.duration,0);
let liveDebateIds=[],liveRoundStart=Date.now();

async function refreshLiveDebates(){
  try{
    const r=await pool.query("SELECT id FROM debates WHERE active=TRUE ORDER BY id");
    const ids=r.rows.map(x=>x.id);
    for(let i=ids.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[ids[i],ids[j]]=[ids[j],ids[i]];}
    liveDebateIds=ids;
  }catch(e){console.error("live refresh:",e.message);}
}
refreshLiveDebates();

app.get("/api/live-state",wrap(async(req,res)=>{
  if(!liveDebateIds.length)await refreshLiveDebates();
  if(!liveDebateIds.length)return res.json({error:"no debates"});
  const elapsed=(Date.now()-liveRoundStart)/1000;
  const roundIndex=Math.floor(elapsed/ROUND_TOTAL);
  const withinRound=elapsed%ROUND_TOTAL;
  const debateIdx=roundIndex%liveDebateIds.length;
  const debateId=liveDebateIds[debateIdx];
  const nextId=liveDebateIds[(debateIdx+1)%liveDebateIds.length];
  let phaseIdx=0,phaseEl=withinRound;
  for(let i=0;i<LIVE_PHASES.length;i++){if(phaseEl<LIVE_PHASES[i].duration){phaseIdx=i;break;}phaseEl-=LIVE_PHASES[i].duration;if(i===LIVE_PHASES.length-1)phaseIdx=i;}
  const phase=LIVE_PHASES[phaseIdx];
  const remaining=Math.max(0,Math.ceil(phase.duration-phaseEl));
  const [cur,nxt]=await Promise.all([
    pool.query("SELECT d.id,d.question,d.category,COUNT(CASE WHEN m.side='YES' THEN 1 END)::int AS yes_count,COUNT(CASE WHEN m.side='NO' THEN 1 END)::int AS no_count FROM debates d LEFT JOIN messages m ON m.debate_id=d.id WHERE d.id=$1 GROUP BY d.id",[debateId]),
    pool.query("SELECT id,question FROM debates WHERE id=$1",[nextId]),
  ]);
  res.json({debate:cur.rows[0]||null,next:nxt.rows[0]||null,phase:phase.name,remaining,duration:phase.duration});
}));

// HTML routes
app.get("/",wrap(async(req,res)=>{trackView(req,res,"/");res.type("html").send(landingPage());}));
app.get("/explore",wrap(async(req,res)=>{trackView(req,res,"/explore");res.type("html").send(explorePage());}));
app.get("/live",(req,res)=>res.type("html").send(livePage()));
app.get("/debate",(req,res)=>res.redirect("/explore"));
app.get("/debate/:id",wrap(async(req,res)=>{
  const id=parseInt(req.params.id,10); if(!Number.isFinite(id))return res.status(400).type("text").send("Bad id");
  const r=await pool.query("SELECT id,question,category,type FROM debates WHERE id=$1 AND active=TRUE",[id]);
  if(!r.rows[0])return res.status(404).type("text").send("Not found");
  trackView(req,res,"/debate/"+id);
  res.type("html").send(debatePage(id,r.rows[0].question,r.rows[0].category,r.rows[0].type));
}));
app.get("/u/:username",wrap(async(req,res)=>{res.type("html").send(profilePage(req.params.username));}));
app.get("/admin",(req,res)=>{
  if((req.cookies?.admin_session||"").trim()!==ADMIN_PASSWORD)return res.type("html").send(adminLoginPage(""));
  res.type("html").send(adminPage());
});

app.use((err,req,res,_next)=>{
  console.error("ERR:",err.message);
  res.status(500).json({error:"Internal server error"});
});
// ── Shared CSS/JS ─────────────────────────────────────────
const BASE_CSS=`
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Unbounded:wght@400;600;700;900&family=Manrope:wght@300;400;500;600;700&display=swap" rel="stylesheet"/>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
:root{
  --bg:#08090d;--bg2:#0f1117;--bg3:#161820;--bg4:#1c1f28;
  --border:rgba(255,255,255,0.055);--border2:rgba(255,255,255,0.12);--border3:rgba(255,255,255,0.2);
  --yes:#3b82f6;--yes-dim:rgba(59,130,246,0.12);--yes-glow:rgba(59,130,246,0.25);
  --no:#ef4444;--no-dim:rgba(239,68,68,0.12);--no-glow:rgba(239,68,68,0.25);
  --accent:#3b82f6;--accent2:#6366f1;--gold:#f59e0b;--green:#22c55e;
  --text:#eaedf3;--text2:#a8afc0;--muted:#4a5060;--muted2:#7c8394;
  --r:14px;--r2:20px;--shadow:0 4px 24px rgba(0,0,0,0.4);--shadow2:0 8px 40px rgba(0,0,0,0.6);
}
html{scroll-behavior:smooth;}
body{font-family:'Manrope',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden;-webkit-font-smoothing:antialiased;}
body::before{content:'';position:fixed;top:-20%;left:50%;transform:translateX(-50%);width:1000px;height:700px;background:radial-gradient(ellipse,rgba(59,130,246,0.04)0%,transparent 65%);pointer-events:none;z-index:0;}
nav{position:sticky;top:0;z-index:100;border-bottom:1px solid var(--border);background:rgba(8,9,13,0.85);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);}
.nav-inner{max-width:1100px;margin:0 auto;display:flex;align-items:center;justify-content:space-between;padding:0 24px;height:56px;}
.logo{font-family:'Unbounded',sans-serif;font-weight:900;font-size:15px;letter-spacing:.06em;color:var(--text);text-decoration:none;display:flex;align-items:center;gap:2px;}
.logo span{color:var(--accent);}
.nav-right{display:flex;align-items:center;gap:10px;font-size:13px;color:var(--muted2);}
a{color:inherit;text-decoration:none;}
#toastContainer{position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:8px;pointer-events:none;}
.toast{padding:12px 18px;border-radius:12px;font-size:13px;font-weight:600;opacity:0;transform:translateY(8px) scale(0.96);transition:all .25s cubic-bezier(.34,1.56,.64,1);pointer-events:all;max-width:320px;box-shadow:var(--shadow2);border:1px solid var(--border2);}
.toast.show{opacity:1;transform:none;}
.toast-success{background:#0d2e1a;color:var(--green);border-color:rgba(34,197,94,.25);}
.toast-error{background:#2e0d0d;color:var(--no);border-color:rgba(239,68,68,.25);}
.toast-info{background:var(--bg3);color:var(--text2);border-color:var(--border2);}
.skel{background:linear-gradient(90deg,var(--bg3)25%,var(--bg4)50%,var(--bg3)75%);background-size:200% 100%;animation:shimmer 1.4s infinite;border-radius:8px;}
@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r);padding:20px;}
.card-label{font-size:10px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin-bottom:14px;}
.btn-primary{padding:11px 22px;border-radius:12px;border:none;background:var(--accent);color:#fff;font-family:'Unbounded',sans-serif;font-weight:700;font-size:11px;letter-spacing:.04em;cursor:pointer;transition:all .18s;}
.btn-primary:hover{opacity:.85;transform:translateY(-1px);}
.pill{display:inline-flex;padding:2px 9px;border-radius:999px;font-size:10px;font-weight:700;letter-spacing:.06em;}
.pill.yes{background:var(--yes-dim);color:var(--yes);border:1px solid rgba(59,130,246,.25);}
.pill.no{background:var(--no-dim);color:var(--no);border:1px solid rgba(239,68,68,.25);}
::-webkit-scrollbar{width:6px;}::-webkit-scrollbar-track{background:var(--bg);}
::-webkit-scrollbar-thumb{background:var(--bg4);border-radius:999px;}::-webkit-scrollbar-thumb:hover{background:var(--muted);}
</style>`;

const SHARED_JS=`
<div id="toastContainer"></div>
<script>
function showToast(msg,type){type=type||'info';const c=document.getElementById('toastContainer');const t=document.createElement('div');t.className='toast toast-'+type;t.textContent=msg;c.appendChild(t);requestAnimationFrame(()=>requestAnimationFrame(()=>t.classList.add('show')));setTimeout(()=>{t.classList.remove('show');setTimeout(()=>t.remove(),300);},3200);}
function getBadge(r){if(r>=500)return'💎';if(r>=200)return'🥇';if(r>=100)return'🥈';if(r>=25)return'🥉';return'';}
function esc(s){return String(s).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');}
function ago(ts){const s=Math.floor((Date.now()-new Date(ts))/1000);if(s<60)return s+'s ago';if(s<3600)return Math.floor(s/60)+'m ago';if(s<86400)return Math.floor(s/3600)+'h ago';return Math.floor(s/86400)+'d ago';}
async function api(url,opts){try{const r=await fetch(url,{headers:{'content-type':'application/json'},...(opts||{})});const d=await r.json();return d;}catch(e){return null;}}
<\/script>`;
// ── Landing page ──────────────────────────────────────────
function landingPage(){
return `<!doctype html><html lang="en">
<head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ARGU — Where the world debates</title>
<meta name="description" content="Pick a side. Make your case. Let the world decide."/>
<meta name="theme-color" content="#3b82f6"/>
${BASE_CSS}
<style>
.page{max-width:1100px;margin:0 auto;padding:0 24px;position:relative;z-index:1;}
.nav-link{font-size:13px;color:var(--muted2);padding:5px 10px;border-radius:8px;transition:all .15s;}
.nav-link:hover{color:var(--text);background:var(--bg3);}
.nav-btn{padding:8px 18px;border-radius:10px;background:var(--accent);color:#fff;font-family:'Unbounded',sans-serif;font-size:11px;font-weight:700;letter-spacing:.04em;border:none;cursor:pointer;text-decoration:none;transition:all .15s;}
.nav-btn:hover{opacity:.85;transform:translateY(-1px);}
.hero{min-height:90vh;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:60px 0 40px;}
.hero-eyebrow{display:inline-flex;align-items:center;gap:7px;font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--accent);border:1px solid rgba(59,130,246,.3);background:rgba(59,130,246,.07);padding:6px 16px;border-radius:999px;margin-bottom:32px;}
.live-dot{width:7px;height:7px;border-radius:50%;background:var(--accent);animation:blink 1.4s infinite;flex-shrink:0;}
@keyframes blink{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(59,130,246,.4)}50%{opacity:.3;box-shadow:0 0 0 4px rgba(59,130,246,0)}}
.hero h1{font-family:'Unbounded',sans-serif;font-size:clamp(40px,7vw,88px);font-weight:900;letter-spacing:-0.04em;line-height:.98;margin-bottom:28px;}
.hero h1 .yes{color:var(--yes);} .hero h1 .no{color:var(--no);}
.hero-sub{font-size:clamp(15px,2vw,18px);color:var(--muted2);max-width:480px;line-height:1.65;margin-bottom:40px;font-weight:500;}
.btn-big{padding:15px 32px;border-radius:14px;font-family:'Unbounded',sans-serif;font-size:12px;font-weight:700;letter-spacing:.04em;cursor:pointer;transition:all .2s;text-decoration:none;display:inline-block;}
.btn-big-primary{background:var(--accent);color:#fff;border:none;box-shadow:0 0 32px rgba(59,130,246,.35);}
.btn-big-primary:hover{opacity:.9;transform:translateY(-2px);box-shadow:0 0 48px rgba(59,130,246,.5);}
.btn-big-outline{background:transparent;color:var(--text);border:1px solid var(--border2);}
.btn-big-outline:hover{background:var(--bg2);border-color:var(--border3);}
.quick-widget{width:100%;max-width:520px;background:var(--bg2);border:1px solid var(--border2);border-radius:24px;padding:28px;box-shadow:var(--shadow);margin-bottom:36px;}
.quick-q{font-family:'Unbounded',sans-serif;font-size:17px;font-weight:700;line-height:1.3;margin-bottom:22px;letter-spacing:-0.01em;}
.quick-btns{display:flex;gap:10px;margin-bottom:14px;}
.quick-btn{flex:1;padding:15px;border-radius:14px;font-family:'Unbounded',sans-serif;font-size:13px;font-weight:700;cursor:pointer;transition:all .18s;border:2px solid;}
.quick-btn-yes{border-color:rgba(59,130,246,.3);background:var(--yes-dim);color:var(--yes);}
.quick-btn-yes:hover{border-color:var(--yes);background:var(--yes);color:#fff;box-shadow:0 0 20px var(--yes-glow);}
.quick-btn-no{border-color:rgba(239,68,68,.3);background:var(--no-dim);color:var(--no);}
.quick-btn-no:hover{border-color:var(--no);background:var(--no);color:#fff;box-shadow:0 0 20px var(--no-glow);}
.quick-hint{font-size:11px;color:var(--muted);text-align:center;}
.ticker{background:var(--bg2);border-top:1px solid var(--border);border-bottom:1px solid var(--border);padding:13px 0;overflow:hidden;margin:0 -24px;}
.ticker-track{display:flex;gap:56px;animation:scroll 35s linear infinite;white-space:nowrap;width:max-content;}
.ticker-track:hover{animation-play-state:paused;}
@keyframes scroll{from{transform:translateX(0)}to{transform:translateX(-50%)}}
.ticker-item{display:inline-flex;align-items:center;gap:8px;font-size:13px;color:var(--muted2);}
.ticker-dot{width:5px;height:5px;border-radius:50%;background:var(--accent);flex-shrink:0;}
.stats-band{background:linear-gradient(135deg,rgba(59,130,246,.06),rgba(99,102,241,.06));border-top:1px solid var(--border);border-bottom:1px solid var(--border);padding:52px 0;margin:0 -24px;}
.stats-inner{max-width:700px;margin:0 auto;display:flex;justify-content:center;gap:64px;flex-wrap:wrap;padding:0 24px;}
.stat-big{text-align:center;}
.stat-big-n{font-family:'Unbounded',sans-serif;font-size:52px;font-weight:900;line-height:1;background:linear-gradient(135deg,var(--text),var(--muted2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
.stat-big-l{font-size:11px;color:var(--muted);margin-top:7px;letter-spacing:.1em;text-transform:uppercase;font-weight:700;}
.section{padding:88px 0;}
.section-label{font-size:10px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:var(--accent);margin-bottom:14px;text-align:center;}
.section h2{font-family:'Unbounded',sans-serif;font-size:clamp(24px,4vw,42px);font-weight:800;letter-spacing:-0.025em;text-align:center;margin-bottom:52px;line-height:1.12;}
.how-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:14px;}
.how-card{background:var(--bg2);border:1px solid var(--border);border-radius:20px;padding:28px 24px;transition:border-color .2s,transform .2s;}
.how-card:hover{border-color:var(--border2);transform:translateY(-2px);}
.how-icon{font-size:30px;margin-bottom:14px;}
.how-title{font-family:'Unbounded',sans-serif;font-size:13px;font-weight:700;margin-bottom:9px;}
.how-desc{font-size:13px;color:var(--muted2);line-height:1.65;}
.preview-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;}
.preview-card{background:var(--bg2);border:1px solid var(--border);border-radius:18px;padding:20px;transition:all .2s;text-decoration:none;display:block;}
.preview-card:hover{border-color:var(--border2);transform:translateY(-3px);box-shadow:var(--shadow);}
.preview-q{font-family:'Unbounded',sans-serif;font-size:13px;font-weight:700;line-height:1.35;margin-bottom:14px;}
.preview-bar{height:3px;background:var(--bg4);border-radius:999px;overflow:hidden;}
.preview-yes{height:100%;background:linear-gradient(90deg,var(--yes),var(--accent2));border-radius:999px;}
.cta-bottom{text-align:center;padding:80px 0 100px;}
.cta-bottom h2{font-family:'Unbounded',sans-serif;font-size:clamp(26px,4.5vw,50px);font-weight:900;letter-spacing:-0.03em;margin-bottom:16px;line-height:1.08;}
.cta-bottom p{font-size:16px;color:var(--muted2);margin-bottom:36px;}
footer{border-top:1px solid var(--border);padding:28px 24px;text-align:center;font-size:12px;color:var(--muted);}
</style>
</head>
<body>
${SHARED_JS}
<nav>
  <div class="nav-inner">
    <a class="logo" href="/">ARGU<span>.</span></a>
    <div style="display:flex;align-items:center;gap:8px;">
      <a class="nav-link" href="/explore">Debates</a>
      <a class="nav-link" href="/live">⚡ Live</a>
      <div id="navAuth"></div>
    </div>
  </div>
</nav>
<div class="page">
  <div class="hero">
    <div class="hero-eyebrow"><span class="live-dot"></span>Live debates happening now</div>
    <h1>The world<br>says <span class="yes">YES</span><br>or <span class="no">NO</span></h1>
    <p class="hero-sub">Pick a side. Make your case in one argument. Let the world vote on who wins.</p>
    <div class="quick-widget" id="quickWidget">
      <div style="display:flex;flex-direction:column;gap:10px">
        <div class="skel" style="height:22px;width:85%"></div>
        <div class="skel" style="height:22px;width:60%"></div>
        <div style="display:flex;gap:10px;margin-top:8px">
          <div class="skel" style="height:52px;flex:1;border-radius:14px"></div>
          <div class="skel" style="height:52px;flex:1;border-radius:14px"></div>
        </div>
      </div>
    </div>
    <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;justify-content:center;">
      <a href="/explore" class="btn-big btn-big-primary">See all debates →</a>
      <a href="/live" class="btn-big btn-big-outline">⚡ Live now</a>
    </div>
  </div>
</div>
<div class="ticker">
  <div class="ticker-track">
    ${ ["Is college a scam?","Should billionaires exist?","Will AI replace programmers?","Is democracy failing?","Is hustle culture toxic?","Should AI have legal rights?","Is capitalism broken?","Is remote work better?","Should social media be banned for kids?","Is freedom of speech absolute?"].flatMap(q=>[q,q]).map(q=>`<span class="ticker-item"><span class="ticker-dot"></span>${esc(q)}</span>`).join("") }
  </div>
</div>
<div class="stats-band">
  <div class="stats-inner">
    <div class="stat-big"><div class="stat-big-n" id="sDebates">—</div><div class="stat-big-l">Debates</div></div>
    <div class="stat-big"><div class="stat-big-n" id="sArgs">—</div><div class="stat-big-l">Arguments</div></div>
    <div class="stat-big"><div class="stat-big-n" id="sUsers">—</div><div class="stat-big-l">Debaters</div></div>
  </div>
</div>
<div class="page">
  <div class="section">
    <div class="section-label">How it works</div>
    <h2>Debate like it matters.</h2>
    <div class="how-grid">
      <div class="how-card"><div class="how-icon">🌍</div><div class="how-title">Real events & questions</div><div class="how-desc">Breaking world events and the big philosophical questions humanity keeps arguing about.</div></div>
      <div class="how-card"><div class="how-icon">⚔️</div><div class="how-title">Pick your side</div><div class="how-desc">Every debate is binary — YES or NO. No fence-sitting. Choose and defend it with your sharpest argument.</div></div>
      <div class="how-card"><div class="how-icon">🗳️</div><div class="how-title">The crowd votes</div><div class="how-desc">Other debaters vote on your argument. Better arguments get higher scores and more influence.</div></div>
      <div class="how-card"><div class="how-icon">🏆</div><div class="how-title">Rise the leaderboard</div><div class="how-desc">Earn rating from upvotes. Your vote weight grows with your rating — become a top voice.</div></div>
    </div>
  </div>
  <div class="section" style="padding-top:0">
    <div class="section-label">Trending now</div>
    <h2>Jump into a debate</h2>
    <div class="preview-grid" id="previewGrid">
      ${ Array(6).fill(0).map(()=>`<div style="background:var(--bg2);border:1px solid var(--border);border-radius:18px;padding:20px;"><div class="skel" style="height:14px;width:40%;margin-bottom:10px"></div><div class="skel" style="height:18px;width:90%;margin-bottom:6px"></div><div class="skel" style="height:18px;width:70%;margin-bottom:14px"></div><div class="skel" style="height:3px;border-radius:999px"></div></div>`).join("") }
    </div>
    <div style="text-align:center;margin-top:32px"><a href="/explore" class="btn-big btn-big-outline">See all debates →</a></div>
  </div>
  <div class="cta-bottom">
    <h2>Join the debate.</h2>
    <p>Real questions. Real arguments. The crowd decides who wins.</p>
    <div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap">
      <a href="/explore" class="btn-big btn-big-primary">Browse all debates →</a>
      <a href="/live" class="btn-big btn-big-outline">⚡ Live now</a>
    </div>
  </div>
</div>
<footer>ARGU. — Where the world debates &nbsp;·&nbsp; <a href="/explore" style="color:var(--muted2)">Debates</a></footer>
<script>
let quickDebate=null,quickSide=null;
async function loadNav(){
  const d=await api("/me"); const me=d&&d.user;
  const el=document.getElementById("navAuth");
  if(!me){el.innerHTML='<a href="/explore" class="nav-btn">Join debate</a>';}
  else{const b=getBadge(me.rating);el.innerHTML='<a href="/u/'+esc(me.username)+'" style="font-size:13px;color:var(--muted2);display:flex;align-items:center;gap:6px;padding:4px 10px;border-radius:8px;transition:background .15s" onmouseover="this.style.background=\'var(--bg3)\'" onmouseout="this.style.background=\'\'"><strong style="color:var(--text)">'+esc(me.username)+'</strong>'+(b?'<span>'+b+'</span>':'')+'<span style="color:var(--gold);font-size:12px">★'+me.rating+'</span></a>';}
}
async function loadStats(){
  const [debates,lb]=await Promise.all([api("/api/debates?sort=hot"),api("/leaderboard/users?limit=1000")]);
  if(!debates||!debates.length)return;
  const totalArgs=debates.reduce((s,d)=>s+(d.arg_count||0),0);
  document.getElementById("sDebates").textContent=debates.length;
  document.getElementById("sArgs").textContent=totalArgs>=1000?Math.round(totalArgs/100)/10+"k":totalArgs;
  if(lb)document.getElementById("sUsers").textContent=lb.length;
  const top=debates.slice(0,6);
  document.getElementById("previewGrid").innerHTML=top.map(d=>{
    const total=d.yes_count+d.no_count, yp=total>0?Math.round(d.yes_count/total*100):50;
    const typeLabel=d.type==="event"?"🌍 Event":"💭 Question";
    return '<a class="preview-card" href="/debate/'+d.id+'"><div style="font-size:9px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;margin-bottom:9px;color:'+(d.type==="event"?"var(--gold)":"var(--accent)")+'">'+typeLabel+'</div><div class="preview-q">'+esc(d.question)+'</div><div style="display:flex;justify-content:space-between;font-size:11px;color:var(--muted);margin-bottom:8px"><span style="color:var(--yes);font-weight:700">YES '+yp+'%</span><span>'+d.arg_count+' args</span><span style="color:var(--no);font-weight:700">'+(100-yp)+'% NO</span></div><div class="preview-bar"><div class="preview-yes" style="width:'+yp+'%"></div></div></a>';
  }).join("");
  quickDebate=debates[Math.floor(Math.random()*Math.min(debates.length,8))];
  renderQuick("pick");
}
function renderQuick(step){
  const w=document.getElementById("quickWidget"); const d=quickDebate; if(!d){w.innerHTML='';return;}
  const total=d.yes_count+d.no_count;
  if(step==="pick"){
    w.innerHTML='<div class="quick-q">'+esc(d.question)+'</div><div class="quick-btns"><button class="quick-btn quick-btn-yes" onclick="pickSide(\'YES\')">✓ YES</button><button class="quick-btn quick-btn-no" onclick="pickSide(\'NO\')">✗ NO</button></div><div class="quick-hint">'+(total||0).toLocaleString()+' people have weighed in · <a href="/debate/'+d.id+'" style="color:var(--accent)">See all arguments →</a></div>';
  }else if(step==="write"){
    const sc=quickSide==="YES"?"var(--yes)":"var(--no)";const bg=quickSide==="YES"?"var(--yes-dim)":"var(--no-dim)";
    w.innerHTML='<div style="display:flex;align-items:center;gap:8px;margin-bottom:16px"><span style="font-size:10px;font-weight:700;letter-spacing:.1em;background:'+bg+';color:'+sc+';padding:4px 12px;border-radius:999px;border:1px solid '+sc+'">'+quickSide+'</span><span style="font-family:\'Unbounded\',sans-serif;font-size:13px;font-weight:700;line-height:1.3">'+esc(d.question)+'</span></div><textarea id="quickText" placeholder="Make your case in one strong argument…" maxlength="300" style="width:100%;min-height:80px;padding:13px;border-radius:12px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-family:\'Manrope\',sans-serif;font-size:14px;resize:none;outline:none;transition:border-color .18s;" onfocus="this.style.borderColor=\'rgba(59,130,246,.5)\'" onblur="this.style.borderColor=\'var(--border)\'" oninput="document.getElementById(\'qHint\').textContent=this.value.length+\' / 300\'"></textarea><div style="display:flex;justify-content:space-between;align-items:center;margin-top:10px"><span id="qHint" style="font-size:11px;color:var(--muted)">0 / 300</span><div style="display:flex;gap:8px"><button onclick="renderQuick(\'pick\')" style="padding:9px 16px;border-radius:10px;border:1px solid var(--border);background:transparent;color:var(--muted2);font-size:12px;cursor:pointer">← Back</button><button onclick="submitQuick()" style="padding:9px 22px;border-radius:10px;border:none;background:var(--accent);color:#fff;font-family:\'Unbounded\',sans-serif;font-size:11px;font-weight:700;cursor:pointer">Post →</button></div></div>';
    setTimeout(()=>document.getElementById("quickText")&&document.getElementById("quickText").focus(),50);
  }else if(step==="done"){
    w.innerHTML='<div style="text-align:center;padding:16px 0"><div style="font-size:36px;margin-bottom:14px">🔥</div><div style="font-family:\'Unbounded\',sans-serif;font-size:16px;font-weight:700;margin-bottom:8px">Argument posted!</div><div style="font-size:13px;color:var(--muted2);margin-bottom:22px">Others are already voting on it.</div><a href="/debate/'+d.id+'" style="display:inline-block;padding:12px 28px;border-radius:12px;background:var(--accent);color:#fff;font-family:\'Unbounded\',sans-serif;font-size:11px;font-weight:700">See the full debate →</a></div>';
  }else if(step==="login"){
    w.innerHTML='<div style="margin-bottom:16px"><div style="font-family:\'Unbounded\',sans-serif;font-size:13px;font-weight:700;margin-bottom:6px">You picked <span style="color:'+(quickSide==="YES"?"var(--yes)":"var(--no)")+'">'+quickSide+'</span></div><div style="font-size:12px;color:var(--muted2)">Create a free account to post your argument</div></div><a href="/auth/google" style="display:flex;align-items:center;justify-content:center;gap:8px;padding:12px;border-radius:12px;border:1px solid var(--border2);background:var(--bg3);color:var(--text);font-size:13px;font-weight:600;text-decoration:none;margin-bottom:12px;transition:background .15s" onmouseover="this.style.background=\'var(--bg4)\'" onmouseout="this.style.background=\'var(--bg3)\'"><svg width="16" height="16" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.31-8.16 2.31-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>Continue with Google</a><div style="display:flex;align-items:center;gap:8px;margin-bottom:10px"><div style="flex:1;height:1px;background:var(--border)"></div><span style="font-size:11px;color:var(--muted)">or</span><div style="flex:1;height:1px;background:var(--border)"></div></div><div style="display:flex;gap:8px"><input id="quickUser" placeholder="choose a username…" maxlength="20" style="flex:1;padding:11px 13px;border-radius:10px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-size:13px;outline:none;transition:border-color .18s" onfocus="this.style.borderColor=\'rgba(59,130,246,.5)\'" onblur="this.style.borderColor=\'var(--border)\'"/><button onclick="quickLogin()" style="padding:11px 20px;border-radius:10px;border:none;background:var(--accent);color:#fff;font-family:\'Unbounded\',sans-serif;font-size:11px;font-weight:700;cursor:pointer;white-space:nowrap">Join →</button></div>';
  }
}
function pickSide(s){quickSide=s;api("/me").then(d=>{if(d&&d.user)renderQuick("write");else renderQuick("login");});}
async function quickLogin(){const u=(document.getElementById("quickUser")||{}).value||"";if(!u.trim())return;const r=await api("/auth/login",{method:"POST",body:JSON.stringify({username:u.trim()})});if(r&&r.error){showToast(r.error,"error");return;}renderQuick("write");loadNav();}
async function submitQuick(){const t=(document.getElementById("quickText")||{}).value||"";if(!t.trim())return;const r=await api("/debate/"+quickDebate.id+"/messages",{method:"POST",body:JSON.stringify({text:t.trim(),side:quickSide})});if(r&&r.error){showToast(r.error,"error");return;}renderQuick("done");showToast("Argument posted! 🔥","success");}
loadNav();loadStats();
</script></body></html>`;
}
// ── Explore page ──────────────────────────────────────────
function explorePage(){
return `<!doctype html><html lang="en">
<head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Explore Debates — ARGU</title>
${BASE_CSS}
<style>
.page{max-width:1240px;margin:0 auto;padding:36px 24px 80px;position:relative;z-index:1;}
.top-bar{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:28px;}
.search-wrap{flex:1;min-width:200px;max-width:380px;position:relative;}
.search-icon{position:absolute;left:13px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:15px;pointer-events:none;}
.search-input{width:100%;padding:11px 14px 11px 38px;border-radius:12px;border:1px solid var(--border);background:var(--bg2);color:var(--text);font-family:'Manrope',sans-serif;font-size:13px;outline:none;transition:border-color .18s;}
.search-input:focus{border-color:rgba(59,130,246,.5);background:var(--bg3);}
.search-input::placeholder{color:var(--muted);}
.sort-tabs{display:flex;gap:4px;background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:3px;}
.sort-tab{padding:7px 14px;border-radius:8px;font-size:11px;font-weight:700;cursor:pointer;color:var(--muted2);border:none;background:transparent;transition:all .15s;letter-spacing:.03em;white-space:nowrap;}
.sort-tab.on{background:var(--bg3);color:var(--text);border:1px solid var(--border2);}
.filter-row{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:24px;}
.filter-btn{padding:6px 14px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid var(--border);background:transparent;color:var(--muted2);cursor:pointer;transition:all .15s;white-space:nowrap;}
.filter-btn.on{background:var(--bg3);border-color:var(--border2);color:var(--text);}
.filter-btn:hover{border-color:var(--border2);color:var(--text);}
.columns{display:grid;grid-template-columns:1fr 1fr;gap:20px;align-items:start;}
@media(max-width:700px){.columns{grid-template-columns:1fr;}}
.col-header{display:flex;align-items:center;gap:10px;margin-bottom:18px;padding-bottom:14px;border-bottom:1px solid var(--border);}
.col-icon{font-size:20px;}
.col-title{font-family:'Unbounded',sans-serif;font-size:13px;font-weight:800;}
.col-title.event{color:var(--gold);}.col-title.question{color:var(--accent);}
.col-sub{font-size:11px;color:var(--muted);margin-top:2px;}
.dcard{background:var(--bg2);border:1px solid var(--border);border-radius:16px;padding:18px;margin-bottom:10px;transition:all .18s;text-decoration:none;color:inherit;display:block;}
.dcard:hover{border-color:var(--border2);transform:translateY(-2px);box-shadow:var(--shadow);}
.dcard-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;}
.cat-tag{font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;padding:3px 9px;border-radius:999px;}
.cat-tag.event{color:var(--gold);background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.22);}
.cat-tag.question{color:var(--accent);background:var(--yes-dim);border:1px solid rgba(59,130,246,.18);}
.arg-ct{font-size:11px;color:var(--muted);}
.dcard-q{font-family:'Unbounded',sans-serif;font-size:13px;font-weight:700;line-height:1.3;margin-bottom:12px;}
.dcard-bar{height:3px;background:var(--bg4);border-radius:999px;overflow:hidden;}
.dcard-yes{height:100%;background:linear-gradient(90deg,var(--yes),var(--accent2));border-radius:999px;transition:width .5s;}
.dcard-nums{display:flex;justify-content:space-between;font-size:10px;font-weight:700;margin-top:7px;}
.dcard-open{padding:9px;border-radius:9px;text-align:center;background:var(--bg3);font-size:11px;font-weight:600;color:var(--muted2);transition:all .18s;margin-top:11px;border:1px solid transparent;}
.dcard:hover .dcard-open{background:var(--accent);color:#fff;border-color:var(--accent);}
.empty-col{text-align:center;padding:44px 20px;color:var(--muted);font-size:13px;background:var(--bg2);border:1px dashed var(--border);border-radius:16px;}
.auth-bar{background:var(--bg2);border:1px solid var(--border);border-radius:14px;padding:14px 18px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:28px;}
.auth-input{padding:10px 13px;border-radius:10px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-family:'Manrope',sans-serif;font-size:13px;outline:none;width:170px;transition:border-color .18s;}
.auth-input:focus{border-color:rgba(59,130,246,.5);}
.auth-input::placeholder{color:var(--muted);}
.btn-out{padding:9px 16px;border-radius:10px;border:1px solid var(--border);background:transparent;color:var(--muted2);font-size:13px;cursor:pointer;transition:all .15s;}
.btn-out:hover{border-color:var(--border2);color:var(--text);}
#searchResults{margin-bottom:20px;display:none;}
#searchResults .sr-label{font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:12px;}
.highlight{background:rgba(59,130,246,.2);color:var(--yes);border-radius:3px;padding:0 2px;}
</style>
</head>
<body>
${SHARED_JS}
<nav>
  <div class="nav-inner">
    <a class="logo" href="/">ARGU<span>.</span></a>
    <div class="nav-right" id="navRight"></div>
  </div>
</nav>
<div class="page">
  <div class="auth-bar" id="authBar"><span style="font-size:13px;color:var(--muted)">Loading…</span></div>
  <div class="top-bar">
    <div class="search-wrap">
      <span class="search-icon">🔍</span>
      <input class="search-input" id="searchInput" placeholder="Search debates…" maxlength="80" autocomplete="off"/>
    </div>
    <div class="sort-tabs">
      <button class="sort-tab on" data-sort="hot">🔥 Hot</button>
      <button class="sort-tab" data-sort="new">✨ New</button>
      <button class="sort-tab" data-sort="top">📈 Top</button>
    </div>
  </div>
  <div class="filter-row" id="filterRow"></div>
  <div id="searchResults"><div class="sr-label" id="srLabel"></div><div id="srGrid"></div></div>
  <div id="mainCols">
    <div class="columns">
      <div>
        <div class="col-header"><span class="col-icon">🌍</span><div><div class="col-title event">World Events</div><div class="col-sub">Breaking topics · current affairs</div></div></div>
        <div id="eventsCol">${ Array(3).fill(0).map(()=>`<div style="background:var(--bg2);border:1px solid var(--border);border-radius:16px;padding:18px;margin-bottom:10px"><div class="skel" style="height:12px;width:35%;margin-bottom:12px"></div><div class="skel" style="height:16px;width:90%;margin-bottom:6px"></div><div class="skel" style="height:16px;width:60%;margin-bottom:14px"></div><div class="skel" style="height:3px;border-radius:999px"></div></div>`).join("") }</div>
      </div>
      <div>
        <div class="col-header"><span class="col-icon">💭</span><div><div class="col-title question">Questions</div><div class="col-sub">Society · life · the future</div></div></div>
        <div id="questionsCol">${ Array(3).fill(0).map(()=>`<div style="background:var(--bg2);border:1px solid var(--border);border-radius:16px;padding:18px;margin-bottom:10px"><div class="skel" style="height:12px;width:35%;margin-bottom:12px"></div><div class="skel" style="height:16px;width:90%;margin-bottom:6px"></div><div class="skel" style="height:16px;width:60%;margin-bottom:14px"></div><div class="skel" style="height:3px;border-radius:999px"></div></div>`).join("") }</div>
      </div>
    </div>
  </div>
</div>
<script>
let allDebates=[],currentCat="All",currentSort="hot",searchTimer=null;
function debateCard(d,sq){
  const total=d.yes_count+d.no_count,yp=total>0?Math.round(d.yes_count/total*100):50,t=d.type||"question";
  let q=esc(d.question);
  if(sq){const parts=q.split(esc(sq));if(parts.length>1)q=parts.join('<mark class="highlight">'+esc(sq)+'</mark>');}
  return '<a class="dcard" href="/debate/'+d.id+'"><div class="dcard-top"><span class="cat-tag '+t+'">'+esc(d.category)+'</span><span class="arg-ct">'+d.arg_count+' args</span></div><div class="dcard-q">'+q+'</div><div class="dcard-bar"><div class="dcard-yes" style="width:'+yp+'%"></div></div><div class="dcard-nums"><span style="color:var(--yes)">YES '+yp+'%</span><span style="color:var(--no)">'+(100-yp)+'% NO</span></div><div class="dcard-open">Debate this →</div></a>';
}
function renderColumns(){
  const ca=currentCat==="All";
  const events=allDebates.filter(d=>(d.type||"question")==="event"&&(ca||d.category===currentCat));
  const qs=allDebates.filter(d=>(d.type||"question")==="question"&&(ca||d.category===currentCat));
  document.getElementById("eventsCol").innerHTML=events.length?events.map(d=>debateCard(d)).join(""):'<div class="empty-col">No events yet.</div>';
  document.getElementById("questionsCol").innerHTML=qs.length?qs.map(d=>debateCard(d)).join(""):'<div class="empty-col">No questions yet.</div>';
}
function buildFilters(){
  const cats=["All",...new Set(allDebates.map(d=>d.category))];
  document.getElementById("filterRow").innerHTML=cats.map(c=>'<button class="filter-btn '+(c===currentCat?"on":"")+'" data-cat="'+esc(c)+'">'+esc(c)+'</button>').join("");
  document.getElementById("filterRow").querySelectorAll(".filter-btn").forEach(b=>{
    b.addEventListener("click",()=>{currentCat=b.getAttribute("data-cat");document.querySelectorAll(".filter-btn").forEach(x=>x.classList.toggle("on",x.getAttribute("data-cat")===currentCat));renderColumns();});
  });
}
async function loadDebates(){
  const data=await api("/api/debates?sort="+currentSort)||[];
  allDebates=data; buildFilters(); renderColumns();
}
document.querySelectorAll(".sort-tab").forEach(btn=>{
  btn.addEventListener("click",()=>{currentSort=btn.getAttribute("data-sort");document.querySelectorAll(".sort-tab").forEach(b=>b.classList.toggle("on",b===btn));loadDebates();});
});
const searchInput=document.getElementById("searchInput");
searchInput.addEventListener("input",()=>{
  clearTimeout(searchTimer); const q=searchInput.value.trim();
  if(!q){document.getElementById("searchResults").style.display="none";document.getElementById("mainCols").style.display="block";return;}
  searchTimer=setTimeout(async()=>{
    if(q.length<2)return;
    const results=await api("/api/search?q="+encodeURIComponent(q))||[];
    document.getElementById("mainCols").style.display="none";
    const sr=document.getElementById("searchResults"); sr.style.display="block";
    document.getElementById("srLabel").textContent=results.length+' result'+(results.length!==1?"s":"")+ ' for "'+q+'"';
    document.getElementById("srGrid").innerHTML=results.length?'<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px">'+results.map(d=>debateCard(d,q)).join("")+'</div>':'<div class="empty-col">No results for "'+esc(q)+'"</div>';
  },280);
});
searchInput.addEventListener("keydown",e=>{if(e.key==="Escape"){searchInput.value="";searchInput.dispatchEvent(new Event("input"));}});
async function loadNav(){
  const d=await api("/me"); const me=d&&d.user;
  const navRight=document.getElementById("navRight"), bar=document.getElementById("authBar");
  if(!me){
    navRight.innerHTML='';
    bar.innerHTML='<a href="/auth/google" style="display:inline-flex;align-items:center;gap:7px;padding:9px 16px;border-radius:10px;border:1px solid var(--border2);background:var(--bg3);color:var(--text);font-size:13px;font-weight:600;text-decoration:none;transition:background .15s" onmouseover="this.style.background=\'var(--bg4)\'" onmouseout="this.style.background=\'var(--bg3)\'"><svg width="15" height="15" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.31-8.16 2.31-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>Continue with Google</a><span style="font-size:12px;color:var(--muted)">or:</span><input class="auth-input" id="usernameIn" placeholder="username…" maxlength="20"/><button class="btn-primary" id="joinBtn" style="padding:9px 18px">Join</button><span style="font-size:11px;color:var(--muted);margin-left:auto">Sign in to post & vote</span>';
    document.getElementById("joinBtn").addEventListener("click",async()=>{
      const u=document.getElementById("usernameIn").value.trim(); if(!u)return;
      const r=await api("/auth/login",{method:"POST",body:JSON.stringify({username:u})});
      if(r&&r.error){showToast(r.error,"error");return;} showToast("Welcome, "+r.user.username+"! 👋","success"); await loadNav();
    });
  }else{
    const b=getBadge(me.rating);
    navRight.innerHTML='<a href="/u/'+esc(me.username)+'" style="font-weight:600;display:flex;align-items:center;gap:5px">'+esc(me.username)+(b?'<span>'+b+'</span>':'')+'</a><span style="color:var(--gold)">★'+me.rating+'</span>';
    bar.innerHTML='<span style="font-size:13px">👋 <strong>'+esc(me.username)+'</strong> &nbsp;<span style="color:var(--gold)">'+b+' ★ '+me.rating+' pts</span></span><a href="/u/'+esc(me.username)+'" class="btn-out" style="margin-left:auto">Profile</a><button class="btn-out" id="logoutBtn">Sign out</button>';
    document.getElementById("logoutBtn").addEventListener("click",async()=>{await api("/auth/logout",{method:"POST"});showToast("Signed out","info");await loadNav();});
  }
}
loadNav(); loadDebates();
</script></body></html>`;
}
// ── Debate page ───────────────────────────────────────────
function debatePage(debateId,question,category,type){
const ESCAPED_Q=esc(question), ESCAPED_CAT=esc(category), ESCAPED_TYPE=esc(type||"question");
return `<!doctype html><html lang="en">
<head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${ESCAPED_Q} — ARGU</title>
<meta property="og:title" content="${ESCAPED_Q}"/>
<meta property="og:description" content="Join the debate on ARGU. Vote YES or NO."/>
${BASE_CSS}
<style>
.page{max-width:1100px;margin:0 auto;padding:0 24px 80px;position:relative;z-index:1;}
.hero{padding:36px 0 24px;}
.back-link{font-size:13px;color:var(--muted2);display:inline-flex;align-items:center;gap:5px;margin-bottom:20px;transition:color .15s;padding:5px 0;}
.back-link:hover{color:var(--text);}
.debate-eyebrow{display:inline-flex;align-items:center;gap:6px;font-size:10px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;padding:4px 13px;border-radius:999px;margin-bottom:14px;}
.debate-eyebrow.event{color:var(--gold);background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.2);}
.debate-eyebrow.question{color:var(--accent);background:var(--yes-dim);border:1px solid rgba(59,130,246,.2);}
.hero-q{font-family:'Unbounded',sans-serif;font-size:clamp(20px,3.2vw,38px);font-weight:700;line-height:1.12;letter-spacing:-0.02em;max-width:760px;margin-bottom:22px;}
.scoreboard{display:flex;gap:10px;margin-bottom:8px;}
.score-side{flex:1;padding:16px 20px;border-radius:16px;border:1px solid;display:flex;align-items:center;justify-content:space-between;transition:all .3s;}
.score-side.yes{background:var(--yes-dim);border-color:rgba(59,130,246,.2);}
.score-side.no{background:var(--no-dim);border-color:rgba(239,68,68,.2);}
.score-lbl{font-family:'Unbounded',sans-serif;font-size:12px;font-weight:700;}
.score-lbl.yes{color:var(--yes);}.score-lbl.no{color:var(--no);}
.score-big{font-family:'Unbounded',sans-serif;font-size:32px;font-weight:900;line-height:1;}
.score-big.yes{color:var(--yes);}.score-big.no{color:var(--no);}
.score-pct{font-size:11px;color:var(--muted2);margin-top:3px;}
.progress-bar{height:4px;background:var(--bg4);border-radius:999px;overflow:hidden;margin-bottom:28px;}
.progress-yes{height:100%;background:linear-gradient(90deg,var(--yes),var(--accent2));border-radius:999px;transition:width .6s cubic-bezier(.34,1,.64,1);}
.main{display:grid;grid-template-columns:1fr 272px;gap:20px;align-items:start;}
@media(max-width:820px){.main{grid-template-columns:1fr;}}
.composer{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r);padding:20px;margin-bottom:20px;transition:border-color .2s;}
.composer:focus-within{border-color:rgba(59,130,246,.3);}
.side-row{display:flex;gap:8px;margin-bottom:14px;}
.side-btn{flex:1;padding:10px;border-radius:10px;border:1px solid var(--border);background:var(--bg3);color:var(--muted2);font-family:'Unbounded',sans-serif;font-size:11px;font-weight:700;cursor:pointer;transition:all .18s;}
.side-btn:hover{color:var(--text);border-color:var(--border2);}
.side-btn.yes-on{background:var(--yes-dim);border-color:var(--yes);color:var(--yes);box-shadow:0 0 16px var(--yes-glow);}
.side-btn.no-on{background:var(--no-dim);border-color:var(--no);color:var(--no);box-shadow:0 0 16px var(--no-glow);}
.composer-textarea{width:100%;min-height:88px;resize:vertical;padding:13px 14px;border-radius:10px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-family:'Manrope',sans-serif;font-size:14px;line-height:1.58;outline:none;transition:border-color .18s;}
.composer-textarea:focus{border-color:rgba(59,130,246,.4);}
.composer-textarea::placeholder{color:var(--muted);}
.post-btn{padding:11px 22px;border-radius:10px;border:none;background:var(--accent);color:#fff;font-family:'Unbounded',sans-serif;font-weight:700;font-size:11px;letter-spacing:.04em;cursor:pointer;transition:all .18s;white-space:nowrap;}
.post-btn:hover{opacity:.88;transform:translateY(-1px);}
.sec-hdr{font-family:'Unbounded',sans-serif;font-size:12px;font-weight:700;letter-spacing:.04em;margin-bottom:14px;display:flex;align-items:center;gap:10px;}
.live-indicator{display:flex;align-items:center;gap:5px;font-size:10px;font-weight:600;color:var(--green);background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.2);padding:3px 10px;border-radius:999px;}
.rdot{width:5px;height:5px;border-radius:50%;background:var(--green);animation:blink 1.4s infinite;}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
.sort-bar{display:flex;align-items:center;gap:6px;}
.sort-lbl{font-size:12px;color:var(--muted);}
.sort-btn{padding:6px 13px;border-radius:8px;border:1px solid var(--border);background:transparent;color:var(--muted);font-size:12px;font-weight:600;cursor:pointer;transition:all .15s;}
.sort-btn.on{background:var(--bg3);color:var(--text);border-color:var(--border2);}
.msg{display:grid;grid-template-columns:44px 1fr;gap:12px;background:var(--bg2);border:1px solid var(--border);border-radius:14px;padding:14px;margin-bottom:8px;animation:slideUp .22s cubic-bezier(.34,1.2,.64,1) both;transition:border-color .18s;}
.msg:hover{border-color:var(--border2);}
.msg.new-msg{border-color:rgba(59,130,246,.3);box-shadow:0 0 16px rgba(59,130,246,.1);}
@keyframes slideUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
.vcol{display:flex;flex-direction:column;align-items:center;gap:5px;}
.vscore{font-family:'Unbounded',sans-serif;font-weight:800;font-size:15px;line-height:1;transition:color .2s,transform .2s;}
.vscore.pos{color:var(--yes);}.vscore.neg{color:var(--no);}.vscore.zero{color:var(--muted);}
.vscore.bump{transform:scale(1.3);}
.vbtn{width:30px;height:26px;border-radius:7px;border:1px solid var(--border);background:var(--bg3);color:var(--muted);font-size:11px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .15s;}
.vbtn.up:hover,.vbtn.up.active{background:var(--yes-dim);border-color:var(--yes);color:var(--yes);}
.vbtn.down:hover,.vbtn.down.active{background:var(--no-dim);border-color:var(--no);color:var(--no);}
.msg-head{display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-bottom:7px;}
.msg-author{font-size:13px;font-weight:700;}
.msg-author:hover{color:var(--accent);}
.msg-time{margin-left:auto;font-size:11px;color:var(--muted);}
.msg-body{font-size:14px;color:rgba(234,237,243,.84);line-height:1.62;margin-bottom:10px;}
.msg-actions{display:flex;gap:5px;flex-wrap:wrap;align-items:center;}
.react-btn{display:inline-flex;align-items:center;gap:4px;padding:4px 9px;border-radius:8px;border:1px solid var(--border);background:var(--bg3);color:var(--muted2);font-size:12px;cursor:pointer;transition:all .15s;}
.react-btn:hover{border-color:var(--border2);color:var(--text);}
.react-btn.active{background:rgba(245,158,11,.1);border-color:rgba(245,158,11,.3);color:var(--gold);}
.reply-btn{display:inline-flex;align-items:center;gap:4px;padding:4px 9px;border-radius:8px;border:1px solid transparent;background:transparent;color:var(--muted);font-size:11px;cursor:pointer;transition:all .15s;}
.reply-btn:hover{color:var(--text);border-color:var(--border);}
.share-btn{display:inline-flex;align-items:center;gap:4px;padding:4px 9px;border-radius:8px;border:1px solid transparent;background:transparent;color:var(--muted);font-size:11px;cursor:pointer;margin-left:auto;transition:all .15s;}
.share-btn:hover{color:var(--text);border-color:var(--border);}
.replies-box{margin-top:10px;padding-top:10px;border-top:1px solid var(--border);}
.reply-item{display:flex;gap:10px;padding:9px 0;border-bottom:1px solid rgba(255,255,255,.04);}
.reply-item:last-child{border-bottom:none;}
.reply-composer{margin-top:10px;display:flex;gap:8px;}
.reply-input{flex:1;padding:9px 12px;border-radius:9px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-family:'Manrope',sans-serif;font-size:13px;outline:none;transition:border-color .18s;}
.reply-input:focus{border-color:rgba(59,130,246,.4);}
.me-card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r);padding:18px;margin-bottom:14px;}
.lb-item{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);font-size:13px;}
.lb-item:last-child{border-bottom:none;}
.lb-num{font-family:'Unbounded',sans-serif;font-size:10px;font-weight:700;color:var(--muted);width:20px;text-align:center;flex-shrink:0;}
.lb-num.t1{color:var(--gold);}
.lb-name{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.lb-pts{font-size:11px;color:var(--muted2);}
.join-btn{width:100%;margin-top:10px;padding:11px;border-radius:10px;border:1px solid rgba(59,130,246,.35);background:var(--yes-dim);color:var(--accent);font-size:13px;font-weight:600;cursor:pointer;transition:background .18s;}
.join-btn:hover{background:rgba(59,130,246,.22);}
.leave-btn{width:100%;margin-top:10px;padding:10px;border-radius:10px;border:1px solid var(--border);background:var(--bg3);color:var(--muted2);font-size:13px;cursor:pointer;transition:all .15s;}
.leave-btn:hover{border-color:var(--border2);color:var(--text);}
.auth-input-sm{width:100%;padding:10px 12px;border-radius:10px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-family:'Manrope',sans-serif;font-size:13px;outline:none;margin-bottom:8px;transition:border-color .18s;}
.auth-input-sm:focus{border-color:rgba(59,130,246,.4);}
.empty-list{text-align:center;padding:48px 20px;color:var(--muted);font-size:14px;}
</style>
</head>
<body>
${SHARED_JS}
<nav>
  <div class="nav-inner">
    <a class="logo" href="/">ARGU<span>.</span></a>
    <div class="nav-right" id="navRight"></div>
  </div>
</nav>
<div class="page">
  <div class="hero">
    <a class="back-link" href="/explore">← All debates</a>
    <div class="debate-eyebrow ${ESCAPED_TYPE}">${ESCAPED_TYPE==="event"?"🌍 Event":"💭 Question"} · ${ESCAPED_CAT}</div>
    <h1 class="hero-q">${ESCAPED_Q}</h1>
    <div class="scoreboard">
      <div class="score-side yes"><span class="score-lbl yes">YES</span><div style="text-align:right"><div class="score-big yes" id="yesCount">0</div><div class="score-pct" id="yesPct">—</div></div></div>
      <div class="score-side no"><div><div class="score-big no" id="noCount">0</div><div class="score-pct" id="noPct">—</div></div><span class="score-lbl no">NO</span></div>
    </div>
    <div class="progress-bar"><div class="progress-yes" id="progressYes" style="width:50%"></div></div>
  </div>
  <div class="main">
    <div>
      <div class="composer" id="composerCard">
        <div class="card-label">Your argument</div>
        <div class="side-row">
          <button class="side-btn yes-on" id="yesBtn">✓ YES</button>
          <button class="side-btn" id="noBtn">✗ NO</button>
        </div>
        <textarea class="composer-textarea" id="text" placeholder="Make your case clearly and persuasively… (max 300 chars)" maxlength="300"></textarea>
        <div style="display:flex;align-items:center;justify-content:space-between;margin-top:10px;gap:10px;">
          <svg width="28" height="28" viewBox="0 0 28 28" id="charRing">
            <circle cx="14" cy="14" r="11" fill="none" stroke="var(--border)" stroke-width="2.5"/>
            <circle cx="14" cy="14" r="11" fill="none" stroke="var(--accent)" stroke-width="2.5" stroke-dasharray="69.12" stroke-dashoffset="69.12" stroke-linecap="round" transform="rotate(-90 14 14)" id="charArc" style="transition:stroke-dashoffset .2s,stroke .2s"/>
          </svg>
          <span style="font-size:11px;color:var(--muted);flex:1" id="charCount">0 / 300</span>
          <button class="post-btn" id="sendBtn">Post argument →</button>
        </div>
      </div>
      <div class="sec-hdr">
        <span id="argCount">Arguments</span>
        <span class="live-indicator" id="sseStatus"><span class="rdot"></span>Live</span>
        <div class="sort-bar" style="margin:0 0 0 auto">
          <span class="sort-lbl">Sort:</span>
          <button class="sort-btn on" id="sortNew">New</button>
          <button class="sort-btn" id="sortTop">Top</button>
        </div>
      </div>
      <div id="list">
        ${ Array(3).fill(0).map(()=>`<div style="background:var(--bg2);border:1px solid var(--border);border-radius:14px;padding:14px;margin-bottom:8px;display:grid;grid-template-columns:44px 1fr;gap:12px"><div style="display:flex;flex-direction:column;align-items:center;gap:5px"><div class="skel" style="width:28px;height:18px;border-radius:4px"></div><div class="skel" style="width:30px;height:26px;border-radius:7px"></div><div class="skel" style="width:30px;height:26px;border-radius:7px"></div></div><div><div style="display:flex;gap:7px;margin-bottom:10px"><div class="skel" style="width:32px;height:18px;border-radius:999px"></div><div class="skel" style="width:80px;height:14px;border-radius:4px"></div></div><div class="skel" style="height:14px;width:100%;margin-bottom:6px"></div><div class="skel" style="height:14px;width:75%"></div></div></div>`).join("") }
      </div>
    </div>
    <div>
      <div class="me-card">
        <div class="card-label">Account</div>
        <div id="meBox"><div class="skel" style="height:14px;width:60%;margin-bottom:8px"></div><div class="skel" style="height:12px;width:40%"></div></div>
        <div id="loginBox" style="display:none">
          <a href="/auth/google" style="display:flex;align-items:center;justify-content:center;gap:8px;padding:10px;border-radius:10px;border:1px solid var(--border2);background:var(--bg3);color:var(--text);font-size:13px;font-weight:600;text-decoration:none;margin-bottom:10px;transition:background .15s" onmouseover="this.style.background='var(--bg4)'" onmouseout="this.style.background='var(--bg3)'"><svg width="15" height="15" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.31-8.16 2.31-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>Continue with Google</a>
          <div style="text-align:center;font-size:11px;color:var(--muted);margin-bottom:8px">or choose a username</div>
          <input class="auth-input-sm" id="username" placeholder="username…" maxlength="20"/>
          <button class="join-btn" id="loginBtn">Join debate →</button>
        </div>
        <div id="logoutBox" style="display:none"><button class="leave-btn" id="logoutBtn">Sign out</button></div>
      </div>
      <div class="card">
        <div class="card-label">Top Debaters</div>
        <div id="lb"><div style="display:flex;flex-direction:column;gap:6px">${ Array(5).fill(0).map(()=>`<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)"><div class="skel" style="width:18px;height:12px;border-radius:4px"></div><div class="skel" style="flex:1;height:13px;border-radius:4px"></div><div class="skel" style="width:36px;height:11px;border-radius:4px"></div></div>`).join("") }</div></div>
      </div>
    </div>
  </div>
</div>
<script>
const DEBATE_ID=${debateId};
const EMOJI_MAP={fire:"🔥",think:"🤔",idea:"💡"};
let side="YES",sort="new",me=null,messages=[],sseConn=null;

document.getElementById("text").addEventListener("input",function(){
  const n=this.value.length,pct=n/300,c=69.12,off=c*(1-pct);
  const arc=document.getElementById("charArc");
  arc.setAttribute("stroke-dashoffset",off);
  arc.setAttribute("stroke",pct>0.9?"var(--no)":pct>0.7?"var(--gold)":"var(--accent)");
  document.getElementById("charCount").textContent=n+" / 300";
  document.getElementById("charCount").style.color=pct>0.9?"var(--no)":"var(--muted)";
});

function setSide(s){
  side=s;
  document.getElementById("yesBtn").className="side-btn"+(s==="YES"?" yes-on":"");
  document.getElementById("noBtn").className="side-btn"+(s==="NO"?" no-on":"");
}
document.getElementById("yesBtn").addEventListener("click",()=>setSide("YES"));
document.getElementById("noBtn").addEventListener("click",()=>setSide("NO"));

document.getElementById("sortNew").addEventListener("click",()=>{sort="new";document.getElementById("sortNew").classList.add("on");document.getElementById("sortTop").classList.remove("on");loadMessages();});
document.getElementById("sortTop").addEventListener("click",()=>{sort="top";document.getElementById("sortTop").classList.add("on");document.getElementById("sortNew").classList.remove("on");loadMessages();});

function connectSSE(){
  if(sseConn)sseConn.close();
  sseConn=new EventSource("/api/events/debate/"+DEBATE_ID);
  sseConn.addEventListener("connected",()=>{
    const s=document.getElementById("sseStatus");
    s.className="live-indicator";s.style.color="var(--green)";
    s.innerHTML='<span class="rdot"></span>Live';
  });
  sseConn.addEventListener("new_message",e=>{
    const msg=JSON.parse(e.data);
    if(sort==="new"){messages.unshift(msg);prependMessage(msg,true);}
    updateScores();
  });
  sseConn.addEventListener("vote_update",e=>{
    const {messageId,newScore}=JSON.parse(e.data);
    messages=messages.map(m=>m.id===messageId?Object.assign({},m,{score:newScore}):m);
    const sc=document.getElementById("score-"+messageId);
    if(sc){sc.textContent=newScore;sc.className="vscore"+(newScore>0?" pos":newScore<0?" neg":" zero");sc.classList.add("bump");setTimeout(()=>sc.classList.remove("bump"),300);}
  });
  sseConn.addEventListener("new_reply",e=>{
    const r=JSON.parse(e.data);
    const rc=document.getElementById("rc-"+r.parent_id);
    if(rc){const cur=parseInt(rc.textContent)||0;rc.textContent=(cur+1)+" replies";}
  });
  sseConn.onerror=()=>{
    const s=document.getElementById("sseStatus");
    s.style.color="var(--no)";s.innerHTML="⚠ Reconnecting…";
    setTimeout(connectSSE,5000);
  };
}

function updateScores(){
  const yes=messages.filter(m=>m.side==="YES").length, no=messages.filter(m=>m.side==="NO").length;
  const total=yes+no, yp=total>0?Math.round(yes/total*100):50;
  document.getElementById("yesCount").textContent=yes;
  document.getElementById("noCount").textContent=no;
  document.getElementById("yesPct").textContent=total>0?yp+"% of args":"—";
  document.getElementById("noPct").textContent=total>0?(100-yp)+"% of args":"—";
  document.getElementById("progressYes").style.width=yp+"%";
  document.getElementById("argCount").textContent=messages.length+" Argument"+(messages.length!==1?"s":"");
}

function buildMsgHTML(m,delay){
  const sc=m.score>0?"pos":m.score<0?"neg":"zero";
  const pc=m.side==="YES"?"yes":"no";
  return '<div class="msg" id="msg-'+m.id+'" style="animation-delay:'+(delay||0)+'s">'
    +'<div class="vcol"><div class="vscore '+sc+'" id="score-'+m.id+'">'+m.score+'</div><button class="vbtn up" data-id="'+m.id+'" data-v="1">▲</button><button class="vbtn down" data-id="'+m.id+'" data-v="-1">▼</button></div>'
    +'<div><div class="msg-head"><span class="pill '+pc+'">'+m.side+'</span><a class="msg-author" href="/u/'+esc(m.username)+'">'+esc(m.username)+'</a><span class="msg-time">'+ago(m.created_at)+'</span></div>'
    +'<div class="msg-body">'+esc(m.text)+'</div>'
    +'<div class="msg-actions">'
    +['fire','think','idea'].map(e=>'<button class="react-btn" data-id="'+m.id+'" data-emoji="'+e+'">'+EMOJI_MAP[e]+' <span id="rc-'+e+'-'+m.id+'">'+(m[e+"_count"]||0)+'</span></button>').join('')
    +'<button class="reply-btn" data-id="'+m.id+'">💬 <span id="rc-'+m.id+'">'+(m.reply_count>0?m.reply_count+" replies":"Reply")+'</span></button>'
    +'<button class="share-btn" data-url="'+location.origin+'/debate/'+DEBATE_ID+'#msg-'+m.id+'">🔗</button>'
    +'</div><div class="replies-box" id="replies-'+m.id+'" style="display:none"></div></div></div>';
}

function attachMsgListeners(el){
  if(!el)return;
  el.querySelectorAll(".vbtn").forEach(btn=>{
    btn.addEventListener("click",async()=>{
      if(!me){showToast("Login to vote","error");return;}
      const id=btn.getAttribute("data-id"),v=parseInt(btn.getAttribute("data-v"),10);
      btn.disabled=true;
      const r=await api("/messages/"+id+"/vote",{method:"POST",body:JSON.stringify({value:v})});
      btn.disabled=false;
      if(!r||r.error){showToast((r&&r.error)||"Error","error");return;}
      if(r.newScore!==null&&r.newScore!==undefined){
        const sc=document.getElementById("score-"+id);
        if(sc){sc.textContent=r.newScore;sc.className="vscore"+(r.newScore>0?" pos":r.newScore<0?" neg":" zero");sc.classList.add("bump");setTimeout(()=>sc.classList.remove("bump"),300);}
        messages=messages.map(m=>m.id==id?Object.assign({},m,{score:r.newScore}):m);
      }
      const me2=await api("/me"); if(me2&&me2.user)updateMeBox(me2.user);
      loadLeaderboard();
    });
  });
  el.querySelectorAll(".react-btn").forEach(btn=>{
    btn.addEventListener("click",async()=>{
      if(!me){showToast("Login to react","error");return;}
      const id=btn.getAttribute("data-id"),emoji=btn.getAttribute("data-emoji");
      const r=await api("/messages/"+id+"/react",{method:"POST",body:JSON.stringify({emoji})});
      if(!r||r.error){showToast((r&&r.error)||"Error","error");return;}
      const cEl=document.getElementById("rc-"+emoji+"-"+id);
      if(cEl){const cur=parseInt(cEl.textContent)||0;cEl.textContent=r.action==="added"?cur+1:Math.max(0,cur-1);btn.classList.toggle("active",r.action==="added");}
    });
  });
  el.querySelectorAll(".reply-btn").forEach(btn=>{
    btn.addEventListener("click",()=>toggleReplies(btn.getAttribute("data-id")));
  });
  el.querySelectorAll(".share-btn").forEach(btn=>{
    btn.addEventListener("click",()=>{
      navigator.clipboard.writeText(btn.getAttribute("data-url")).then(()=>showToast("Link copied!","success")).catch(()=>showToast("Copy: "+btn.getAttribute("data-url"),"info"));
    });
  });
}

async function toggleReplies(msgId){
  const box=document.getElementById("replies-"+msgId); if(!box)return;
  if(box.style.display==="block"){box.style.display="none";return;}
  box.style.display="block";
  box.innerHTML='<div class="skel" style="height:40px;border-radius:8px;margin-bottom:8px"></div>';
  const replies=await api("/messages/"+msgId+"/replies")||[];
  box.innerHTML='';
  replies.forEach(r=>{
    const d=document.createElement("div"); d.className="reply-item";
    d.innerHTML='<div style="flex-shrink:0;width:24px;text-align:center;font-size:11px;font-weight:700;color:var(--muted);padding-top:2px">↳</div><div style="flex:1"><div style="display:flex;align-items:center;gap:6px;margin-bottom:5px"><span class="pill '+(r.side==="YES"?"yes":"no")+'">'+r.side+'</span><a href="/u/'+esc(r.username)+'" style="font-size:12px;font-weight:700">'+esc(r.username)+'</a><span style="font-size:10px;color:var(--muted);margin-left:auto">'+ago(r.created_at)+'</span></div><div style="font-size:13px;color:rgba(234,237,243,.8);line-height:1.5">'+esc(r.text)+'</div></div>';
    box.appendChild(d);
  });
  const rc=document.createElement("div"); rc.className="reply-composer";
  rc.innerHTML='<input class="reply-input" id="ri-'+msgId+'" placeholder="Reply…" maxlength="300"/><button onclick="postReply('+msgId+')" style="padding:9px 16px;border-radius:9px;border:none;background:var(--accent);color:#fff;font-size:11px;font-weight:700;cursor:pointer;white-space:nowrap;font-family:\'Unbounded\',sans-serif">Reply</button>';
  box.appendChild(rc);
}

async function postReply(parentId){
  if(!me){showToast("Login to reply","error");return;}
  const input=document.getElementById("ri-"+parentId);
  const text=(input&&input.value||"").trim(); if(!text)return;
  const r=await api("/messages/"+parentId+"/reply",{method:"POST",body:JSON.stringify({text})});
  if(!r||r.error){showToast((r&&r.error)||"Error","error");return;}
  if(input)input.value="";
  showToast("Reply posted!","success");
  const box=document.getElementById("replies-"+parentId);
  if(box){box.style.display="none";setTimeout(()=>toggleReplies(parentId),100);}
}

function prependMessage(m,isNew){
  const list=document.getElementById("list");
  list.querySelector(".empty-list")&&list.querySelector(".empty-list").remove();
  const wrap=document.createElement("div"); wrap.innerHTML=buildMsgHTML(m,0);
  const el=wrap.firstChild;
  if(isNew){el.classList.add("new-msg");setTimeout(()=>el.classList.remove("new-msg"),2000);}
  list.insertBefore(el,list.firstChild); attachMsgListeners(el);
}

function renderMessages(rows){
  messages=rows; updateScores();
  const list=document.getElementById("list");
  if(!rows.length){list.innerHTML='<div class="empty-list">No arguments yet — be the first!</div>';return;}
  list.innerHTML=rows.map((m,i)=>buildMsgHTML(m,Math.min(i,6)*0.04)).join("");
  list.querySelectorAll(".msg").forEach(el=>attachMsgListeners(el));
}

async function loadMessages(){
  const rows=await api("/debate/"+DEBATE_ID+"/messages?sort="+sort)||[];
  renderMessages(Array.isArray(rows)?rows:[]);
}

function updateMeBox(u){
  me=u; const b=getBadge(u.rating);
  document.getElementById("meBox").innerHTML='<a href="/u/'+esc(u.username)+'" style="font-weight:700;font-size:14px;display:flex;align-items:center;gap:6px">'+esc(u.username)+(b?'<span>'+b+'</span>':'')+'</a><div style="color:var(--gold);font-size:12px;margin-top:3px">★ '+u.rating+' pts</div>';
  document.getElementById("loginBox").style.display="none";
  document.getElementById("logoutBox").style.display="block";
  const nr=document.getElementById("navRight");
  if(nr)nr.innerHTML='<a href="/u/'+esc(u.username)+'" style="font-weight:600;display:flex;align-items:center;gap:5px">'+esc(u.username)+(b?'<span>'+b+'</span>':'')+'</a><span style="color:var(--gold)">★'+u.rating+'</span>';
}

async function loadMe(){
  const d=await api("/me"); if(d&&d.user){updateMeBox(d.user);}
  else{
    me=null;
    document.getElementById("meBox").innerHTML='<div style="font-size:13px;color:var(--muted2)">Not signed in</div><div style="font-size:11px;color:var(--muted);margin-top:4px">Join to post & vote</div>';
    document.getElementById("loginBox").style.display="block";
    document.getElementById("logoutBox").style.display="none";
    const nr=document.getElementById("navRight"); if(nr)nr.innerHTML='';
  }
}

async function loadLeaderboard(){
  const rows=await api("/leaderboard/users?limit=7")||[];
  document.getElementById("lb").innerHTML=rows.length
    ?rows.map((u,i)=>{const b=getBadge(u.rating);return '<div class="lb-item"><span class="lb-num '+(i===0?"t1":"")+'">&#35;'+(i+1)+'</span><a class="lb-name" href="/u/'+esc(u.username)+'">'+esc(u.username)+(b?'<span style="margin-left:4px">'+b+'</span>':'')+'</a><span class="lb-pts">'+u.rating+'</span></div>';}).join("")
    :'<div style="color:var(--muted);font-size:13px">No users yet</div>';
}

document.getElementById("loginBtn").addEventListener("click",async()=>{
  const u=(document.getElementById("username")||{}).value||"";
  if(!u.trim())return;
  const r=await api("/auth/login",{method:"POST",body:JSON.stringify({username:u.trim()})});
  if(!r||r.error){showToast((r&&r.error)||"Error","error");return;}
  showToast("Welcome, "+r.user.username+"! 👋","success");
  await Promise.all([loadMe(),loadLeaderboard()]);
});

document.getElementById("logoutBtn").addEventListener("click",async()=>{
  await api("/auth/logout",{method:"POST"});
  showToast("Signed out","info"); me=null;
  await Promise.all([loadMe(),loadLeaderboard()]);
});

document.getElementById("sendBtn").addEventListener("click",async()=>{
  if(!me){showToast("Login to post an argument","error");return;}
  const text=document.getElementById("text").value.trim();
  if(!text){showToast("Write your argument first","error");return;}
  document.getElementById("sendBtn").disabled=true;document.getElementById("sendBtn").textContent="Posting…";
  const r=await api("/debate/"+DEBATE_ID+"/messages",{method:"POST",body:JSON.stringify({text,side})});
  document.getElementById("sendBtn").disabled=false;document.getElementById("sendBtn").textContent="Post argument →";
  if(!r||r.error){showToast((r&&r.error)||"Error","error");return;}
  document.getElementById("text").value="";
  document.getElementById("text").dispatchEvent(new Event("input"));
  showToast("Argument posted! 🔥","success");
  if(sort==="new")await loadMessages();
});

connectSSE();
Promise.all([loadMe(),loadLeaderboard(),loadMessages()]);
</script></body></html>`;
}
// ── Profile page ──────────────────────────────────────────
function profilePage(username){
return `<!doctype html><html lang="en">
<head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${esc(username)} — ARGU</title>
${BASE_CSS}
<style>
.page{max-width:760px;margin:0 auto;padding:40px 24px 80px;position:relative;z-index:1;}
.back-link{font-size:13px;color:var(--muted2);display:inline-flex;align-items:center;gap:5px;margin-bottom:28px;transition:color .15s;}
.back-link:hover{color:var(--text);}
.profile-top{display:flex;align-items:center;gap:22px;margin-bottom:32px;padding:24px;background:var(--bg2);border:1px solid var(--border);border-radius:20px;}
.avatar{width:68px;height:68px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-family:'Unbounded',sans-serif;font-size:24px;font-weight:900;flex-shrink:0;border:2px solid var(--border2);}
.profile-name{font-family:'Unbounded',sans-serif;font-size:22px;font-weight:900;display:flex;align-items:center;gap:10px;}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:10px;margin-bottom:28px;}
.stat-card{background:var(--bg2);border:1px solid var(--border);border-radius:14px;padding:16px;text-align:center;transition:border-color .2s;}
.stat-card:hover{border-color:var(--border2);}
.stat-n{font-family:'Unbounded',sans-serif;font-size:26px;font-weight:900;}
.stat-l{font-size:10px;color:var(--muted);margin-top:5px;letter-spacing:.08em;text-transform:uppercase;font-weight:700;}
.arg-card{background:var(--bg2);border:1px solid var(--border);border-radius:14px;padding:16px;margin-bottom:10px;transition:all .18s;}
.arg-card:hover{border-color:var(--border2);transform:translateY(-1px);}
.arg-head{display:flex;align-items:center;gap:8px;margin-bottom:9px;flex-wrap:wrap;}
.arg-text{font-size:14px;color:rgba(234,237,243,.84);line-height:1.6;}
.score-tag{font-family:'Unbounded',sans-serif;font-size:12px;font-weight:800;padding:3px 10px;border-radius:8px;margin-left:auto;}
.score-tag.pos{color:var(--yes);background:var(--yes-dim);}
.score-tag.neg{color:var(--no);background:var(--no-dim);}
.score-tag.zero{color:var(--muted);background:var(--bg3);}
.section-title{font-family:'Unbounded',sans-serif;font-size:13px;font-weight:700;margin-bottom:16px;}
</style>
</head>
<body>
${SHARED_JS}
<nav>
  <div class="nav-inner">
    <a class="logo" href="/">ARGU<span>.</span></a>
    <div class="nav-right" id="navRight"></div>
  </div>
</nav>
<div class="page">
  <a class="back-link" href="/">← Back</a>
  <div id="content">
    <div class="profile-top">
      <div class="skel avatar" style="background:var(--bg3)"></div>
      <div style="flex:1">
        <div class="skel" style="height:22px;width:55%;margin-bottom:10px;border-radius:6px"></div>
        <div class="skel" style="height:14px;width:35%;margin-bottom:6px;border-radius:4px"></div>
        <div class="skel" style="height:14px;width:25%;border-radius:4px"></div>
      </div>
    </div>
    <div class="stats-grid">${ Array(5).fill(0).map(()=>`<div class="stat-card"><div class="skel" style="height:26px;width:60%;margin:0 auto 8px;border-radius:6px"></div><div class="skel" style="height:10px;width:70%;margin:0 auto;border-radius:4px"></div></div>`).join("") }</div>
  </div>
</div>
<script>
const USERNAME="${esc(username)}";
async function load(){
  const [pd,md]=await Promise.all([api("/api/user/"+USERNAME),api("/me")]);
  const me=md&&md.user;
  if(me){const b=getBadge(me.rating);document.getElementById("navRight").innerHTML='<a href="/u/'+esc(me.username)+'" style="font-weight:600;display:flex;align-items:center;gap:5px">'+esc(me.username)+(b?'<span>'+b+'</span>':'')+'</a><span style="color:var(--gold)">★'+me.rating+'</span>';}
  if(!pd||pd.error){document.getElementById("content").innerHTML='<div style="text-align:center;padding:60px;color:var(--muted)">User not found</div>';return;}
  const {user,stats,top_messages,rank}=pd;
  const initial=user.username[0].toUpperCase();
  const b=getBadge(user.rating);
  const joined=new Date(user.created_at).toLocaleDateString("en-US",{month:"long",year:"numeric"});
  const hue=(user.username.split("").reduce((a,c)=>a+c.charCodeAt(0),0)*47)%360;
  document.getElementById("content").innerHTML=
    '<div class="profile-top">'
      +'<div class="avatar" style="background:linear-gradient(135deg,hsl('+hue+',55%,20%),hsl('+hue+',45%,28%));border-color:hsl('+hue+',50%,35%)">'+initial+'</div>'
      +'<div><div class="profile-name">'+esc(user.username)+(b?'<span>'+b+'</span>':'')+'</div>'
      +'<div style="font-size:12px;color:var(--muted2);margin-top:4px">Rank #'+rank+' globally</div>'
      +'<div style="font-size:12px;color:var(--muted);margin-top:2px">Joined '+joined+'</div>'
      +'<div style="font-family:\'Unbounded\',sans-serif;font-size:16px;font-weight:700;color:var(--gold);background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.2);padding:6px 14px;border-radius:10px;margin-top:10px;display:inline-block">★ '+user.rating+' pts</div>'
      +'</div></div>'
    +'<div class="stats-grid">'
      +'<div class="stat-card"><div class="stat-n">'+stats.total_args+'</div><div class="stat-l">Arguments</div></div>'
      +'<div class="stat-card"><div class="stat-n" style="color:var(--yes)">'+stats.yes_args+'</div><div class="stat-l">YES side</div></div>'
      +'<div class="stat-card"><div class="stat-n" style="color:var(--no)">'+stats.no_args+'</div><div class="stat-l">NO side</div></div>'
      +'<div class="stat-card"><div class="stat-n" style="color:var(--gold)">'+stats.total_upvotes+'</div><div class="stat-l">Upvotes</div></div>'
      +'<div class="stat-card"><div class="stat-n">'+stats.best_score+'</div><div class="stat-l">Best score</div></div>'
    +'</div>'
    +'<div class="section-title">Top Arguments</div>'
    +(top_messages.length?top_messages.map(m=>{
      const pc=m.side==="YES"?"yes":"no";
      const sc=m.score>0?"pos":m.score<0?"neg":"zero";
      return '<div class="arg-card"><div class="arg-head"><span class="pill '+pc+'">'+m.side+'</span>'
        +'<a href="/debate/'+(m.debate_id||'')+'" style="font-size:12px;color:var(--muted2);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(m.question||'')+'</a>'
        +'<span class="score-tag '+sc+'">'+(m.score>0?"+":"")+m.score+'</span></div>'
        +'<div class="arg-text">'+esc(m.text)+'</div></div>';
    }).join(""):'<div style="color:var(--muted);font-size:14px;text-align:center;padding:40px">No arguments yet</div>');
}
load();
</script></body></html>`;
}

// ── Live page ─────────────────────────────────────────────
function livePage(){
return `<!doctype html><html lang="en">
<head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Live Debate — ARGU</title>
${BASE_CSS}
<style>
.page{max-width:760px;margin:0 auto;padding:40px 24px 80px;position:relative;z-index:1;text-align:center;}
.live-badge{display:inline-flex;align-items:center;gap:7px;font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--accent);border:1px solid rgba(59,130,246,.3);background:rgba(59,130,246,.07);padding:6px 16px;border-radius:999px;margin-bottom:28px;}
.live-dot{width:7px;height:7px;border-radius:50%;background:var(--accent);animation:blink 1.4s infinite;}
@keyframes blink{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(59,130,246,.4)}50%{opacity:.3;box-shadow:0 0 0 4px rgba(59,130,246,0)}}
.phase-banner{display:inline-block;padding:6px 20px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;margin-bottom:18px;}
.phase-read{background:rgba(99,102,241,.12);color:var(--accent2);border:1px solid rgba(99,102,241,.3);}
.phase-argue{background:var(--yes-dim);color:var(--yes);border:1px solid rgba(59,130,246,.3);}
.phase-vote{background:rgba(245,158,11,.1);color:var(--gold);border:1px solid rgba(245,158,11,.3);}
.live-question{font-family:'Unbounded',sans-serif;font-size:clamp(22px,4vw,42px);font-weight:900;letter-spacing:-0.025em;line-height:1.1;margin-bottom:28px;}
.timer-ring{display:inline-block;margin-bottom:28px;}
.timer-text{font-family:'Unbounded',sans-serif;font-size:36px;font-weight:900;line-height:1;}
.timer-sub{font-size:11px;color:var(--muted);margin-top:4px;letter-spacing:.06em;text-transform:uppercase;font-weight:700;}
.scoreboard{display:flex;gap:12px;justify-content:center;margin-bottom:24px;}
.sb-side{flex:1;max-width:200px;padding:18px;border-radius:16px;border:1px solid;}
.sb-side.yes{background:var(--yes-dim);border-color:rgba(59,130,246,.2);}
.sb-side.no{background:var(--no-dim);border-color:rgba(239,68,68,.2);}
.sb-num{font-family:'Unbounded',sans-serif;font-size:40px;font-weight:900;line-height:1;}
.sb-num.yes{color:var(--yes);}.sb-num.no{color:var(--no);}
.sb-lbl{font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;margin-top:4px;}
.sb-lbl.yes{color:var(--yes);}.sb-lbl.no{color:var(--no);}
.progress-bar{height:6px;background:var(--bg4);border-radius:999px;overflow:hidden;margin-bottom:28px;max-width:440px;margin-left:auto;margin-right:auto;}
.progress-yes{height:100%;background:linear-gradient(90deg,var(--yes),var(--accent2));border-radius:999px;transition:width .8s cubic-bezier(.34,1,.64,1);}
.next-card{background:var(--bg2);border:1px solid var(--border);border-radius:16px;padding:18px 22px;margin:0 auto 24px;max-width:440px;text-align:left;}
.next-label{font-size:10px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-bottom:8px;}
.next-q{font-family:'Unbounded',sans-serif;font-size:14px;font-weight:700;line-height:1.3;}
.action-btn{display:inline-block;padding:14px 32px;border-radius:14px;background:var(--accent);color:#fff;font-family:'Unbounded',sans-serif;font-size:12px;font-weight:700;letter-spacing:.04em;text-decoration:none;transition:all .2s;box-shadow:0 0 24px rgba(59,130,246,.3);}
.action-btn:hover{opacity:.88;transform:translateY(-2px);}
</style>
</head>
<body>
${SHARED_JS}
<nav>
  <div class="nav-inner">
    <a class="logo" href="/">ARGU<span>.</span></a>
    <div class="nav-right"><a href="/explore" style="font-size:13px;color:var(--muted2);padding:5px 10px;border-radius:8px;transition:all .15s" onmouseover="this.style.color='var(--text)'" onmouseout="this.style.color='var(--muted2)'">All debates</a></div>
  </div>
</nav>
<div class="page">
  <div class="live-badge"><span class="live-dot"></span>Live now</div>
  <div id="phaseBanner" class="phase-banner phase-read">📖 Read the question</div>
  <div class="live-question" id="liveQ">
    <div class="skel" style="height:36px;max-width:600px;margin:0 auto 12px;border-radius:8px"></div>
    <div class="skel" style="height:36px;max-width:400px;margin:0 auto;border-radius:8px"></div>
  </div>
  <div class="timer-ring">
    <svg width="120" height="120" viewBox="0 0 120 120">
      <circle cx="60" cy="60" r="52" fill="none" stroke="var(--border)" stroke-width="6"/>
      <circle cx="60" cy="60" r="52" fill="none" stroke="var(--accent)" stroke-width="6"
        stroke-dasharray="326.73" stroke-dashoffset="0" stroke-linecap="round"
        transform="rotate(-90 60 60)" id="timerArc" style="transition:stroke-dashoffset .9s linear,stroke .5s"/>
      <text x="60" y="56" text-anchor="middle" fill="var(--text)" font-family="Unbounded,sans-serif" font-weight="900" font-size="26" id="timerNum">—</text>
      <text x="60" y="72" text-anchor="middle" fill="var(--muted)" font-family="Manrope,sans-serif" font-size="9" font-weight="700" letter-spacing="1" id="timerSub">LOADING</text>
    </svg>
  </div>
  <div class="scoreboard">
    <div class="sb-side yes"><div class="sb-num yes" id="livYes">0</div><div class="sb-lbl yes">YES</div></div>
    <div class="sb-side no"><div class="sb-num no" id="livNo">0</div><div class="sb-lbl no">NO</div></div>
  </div>
  <div class="progress-bar"><div class="progress-yes" id="livProgress" style="width:50%"></div></div>
  <div id="actionArea" style="margin-bottom:24px"></div>
  <div class="next-card" id="nextCard" style="display:none">
    <div class="next-label">Up next</div>
    <div class="next-q" id="nextQ">—</div>
  </div>
  <a href="/explore" style="font-size:13px;color:var(--muted2);display:inline-block;margin-top:8px;transition:color .15s" onmouseover="this.style.color='var(--text)'" onmouseout="this.style.color='var(--muted2)'">← Browse all debates</a>
</div>
<script>
let localRemaining=null, localPhase=null, tickInterval=null, lastDebateId=null;
const PHASE_INFO={
  read:{label:"📖 Read the question",cls:"phase-read",color:"var(--accent2)",sub:"READ"},
  argue:{label:"⚔️ Time to argue!",cls:"phase-argue",color:"var(--yes)",sub:"ARGUE"},
  vote:{label:"🗳️ Vote on arguments",cls:"phase-vote",color:"var(--gold)",sub:"VOTE"},
};

function setTimer(remaining,duration,phase){
  const info=PHASE_INFO[phase]||PHASE_INFO.read;
  const r=Math.max(0,remaining);
  document.getElementById("timerNum").textContent=r;
  document.getElementById("timerNum").setAttribute("fill",info.color);
  document.getElementById("timerSub").textContent=info.sub;
  const arc=document.getElementById("timerArc");
  const circ=326.73, pct=duration>0?r/duration:0;
  arc.setAttribute("stroke-dashoffset",circ*(1-pct));
  arc.setAttribute("stroke",info.color);
  const banner=document.getElementById("phaseBanner");
  banner.textContent=info.label; banner.className="phase-banner "+info.cls;
}

async function poll(){
  const d=await api("/api/live-state"); if(!d||d.error)return;
  const debate=d.debate;
  if(debate){
    if(debate.id!==lastDebateId){
      lastDebateId=debate.id;
      document.getElementById("liveQ").textContent=debate.question;
    }
    const yes=debate.yes_count||0, no=debate.no_count||0, total=yes+no;
    document.getElementById("livYes").textContent=yes;
    document.getElementById("livNo").textContent=no;
    const yp=total>0?Math.round(yes/total*100):50;
    document.getElementById("livProgress").style.width=yp+"%";
  }
  const next=d.next;
  const nc=document.getElementById("nextCard");
  if(next&&next.id!==lastDebateId){
    nc.style.display="block";
    document.getElementById("nextQ").textContent=next.question;
  } else nc.style.display="none";

  localRemaining=d.remaining; localPhase=d.phase;
  setTimer(d.remaining,d.duration,d.phase);

  const aa=document.getElementById("actionArea");
  if(d.phase==="argue"&&debate){
    aa.innerHTML='<a href="/debate/'+debate.id+'" class="action-btn">⚔️ Jump into debate →</a>';
  }else if(d.phase==="vote"&&debate){
    aa.innerHTML='<a href="/debate/'+debate.id+'" class="action-btn">🗳️ Vote on arguments →</a>';
  }else if(debate){
    aa.innerHTML='<a href="/debate/'+debate.id+'" class="action-btn">👀 See full debate →</a>';
  }
}

function tick(){
  if(localRemaining===null)return;
  localRemaining=Math.max(0,localRemaining-1);
  if(document.getElementById("timerNum"))document.getElementById("timerNum").textContent=localRemaining;
  const arc=document.getElementById("timerArc");
  if(arc&&localPhase){
    const durations={read:15,argue:60,vote:45};
    const dur=durations[localPhase]||60, circ=326.73, pct=dur>0?localRemaining/dur:0;
    arc.setAttribute("stroke-dashoffset",circ*(1-pct));
  }
}

clearInterval(tickInterval);
tickInterval=setInterval(tick,1000);
poll();
setInterval(poll,4000);
</script></body></html>`;
}

// ── Admin login / dashboard pages ─────────────────────────
function adminLoginPage(err){
return `<!doctype html><html lang="en">
<head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Admin — ARGU</title>${BASE_CSS}
<style>
.center{display:flex;align-items:center;justify-content:center;min-height:100vh;}
.box{background:var(--bg2);border:1px solid var(--border2);border-radius:24px;padding:36px;width:100%;max-width:360px;position:relative;z-index:1;box-shadow:var(--shadow2);}
h2{font-family:'Unbounded',sans-serif;font-size:18px;font-weight:800;margin-bottom:24px;}
.field{margin-bottom:14px;}
.field label{display:block;font-size:11px;color:var(--muted);margin-bottom:7px;letter-spacing:.06em;text-transform:uppercase;font-weight:700;}
.field input{width:100%;padding:12px 14px;border-radius:10px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-size:14px;outline:none;transition:border-color .18s;}
.field input:focus{border-color:rgba(59,130,246,.5);}
.err{background:var(--no-dim);border:1px solid rgba(239,68,68,.3);border-radius:9px;padding:11px 14px;font-size:13px;color:var(--no);margin-bottom:14px;}
</style>
</head>
<body>${SHARED_JS}
<div class="center"><div class="box">
  <h2>Admin Login</h2>
  ${err?`<div class="err">${esc(err)}</div>`:""}
  <div class="field"><label>Password</label><input type="password" id="pw" placeholder="Enter admin password…" autofocus/></div>
  <button class="btn-primary" style="width:100%;padding:13px" id="loginBtn">Enter Admin Panel →</button>
</div></div>
<script>
async function doLogin(){
  const pw=document.getElementById("pw").value; if(!pw)return;
  document.getElementById("loginBtn").textContent="Checking…";
  const r=await fetch("/admin/login",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({password:pw})});
  const d=await r.json();
  if(d.error){showToast(d.error,"error");document.getElementById("loginBtn").textContent="Enter Admin Panel →";return;}
  window.location="/admin";
}
document.getElementById("loginBtn").addEventListener("click",doLogin);
document.getElementById("pw").addEventListener("keydown",e=>{if(e.key==="Enter")doLogin();});
</script></body></html>`;
}
function adminPage(){
const CATS=["Technology","Economy","Society","Politics","Education","Life","Work","General"];
const catOpts=CATS.map(c=>'<option value="'+esc(c)+'">'+esc(c)+'</option>').join("");
return `<!doctype html><html lang="en">
<head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Admin — ARGU</title>${BASE_CSS}
<style>
.page{max-width:1240px;margin:0 auto;padding:32px 24px 80px;position:relative;z-index:1;}
h2{font-family:'Unbounded',sans-serif;font-size:20px;font-weight:800;margin-bottom:22px;}
h3{font-family:'Unbounded',sans-serif;font-size:13px;font-weight:700;margin-bottom:14px;}
.tabs{display:flex;gap:4px;margin-bottom:28px;background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:4px;width:fit-content;}
.tab{padding:9px 20px;border-radius:9px;font-size:11px;font-weight:700;cursor:pointer;color:var(--muted2);border:none;background:transparent;transition:all .15s;font-family:'Unbounded',sans-serif;letter-spacing:.04em;white-space:nowrap;}
.tab.active{background:var(--bg3);color:var(--text);border:1px solid var(--border2);}
.panel{display:none;}.panel.active{display:block;}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.8);z-index:200;display:flex;align-items:center;justify-content:center;padding:20px;backdrop-filter:blur(4px);}
.modal-bg.hidden{display:none;}
.modal{background:var(--bg2);border:1px solid var(--border2);border-radius:20px;padding:28px;width:100%;max-width:500px;box-shadow:var(--shadow2);}
.modal-actions{display:flex;gap:8px;margin-top:20px;justify-content:flex-end;}
.stats-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px;}
.kpi{background:var(--bg2);border:1px solid var(--border);border-radius:14px;padding:18px 22px;min-width:130px;}
.kpi-n{font-family:'Unbounded',sans-serif;font-size:26px;font-weight:900;}
.kpi-l{font-size:10px;color:var(--muted);margin-top:4px;letter-spacing:.08em;text-transform:uppercase;font-weight:700;}
.chart-bar{height:120px;display:flex;align-items:flex-end;gap:3px;margin-top:10px;}
.chart-col{flex:1;display:flex;flex-direction:column;align-items:center;gap:3px;}
.chart-fill{width:100%;background:linear-gradient(0deg,var(--accent),var(--accent2));border-radius:3px 3px 0 0;min-height:2px;}
.chart-lbl{font-size:8px;color:var(--muted);writing-mode:vertical-rl;transform:rotate(180deg);}
.field{margin-bottom:11px;}
.field label{display:block;font-size:11px;color:var(--muted);margin-bottom:6px;letter-spacing:.04em;text-transform:uppercase;font-weight:700;}
.field input,.field select{width:100%;padding:10px 12px;border-radius:9px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-family:'Manrope',sans-serif;font-size:13px;outline:none;transition:border-color .18s;}
.field input:focus,.field select:focus{border-color:rgba(59,130,246,.5);}
.tbl{width:100%;border-collapse:collapse;font-size:13px;}
.tbl th{text-align:left;font-size:10px;font-weight:700;letter-spacing:.08em;color:var(--muted);text-transform:uppercase;padding:9px 10px;border-bottom:1px solid var(--border);}
.tbl td{padding:10px 10px;border-bottom:1px solid var(--border);vertical-align:middle;}
.tbl tr:last-child td{border-bottom:none;}
.tbl tr:hover td{background:rgba(255,255,255,.02);}
.badge2{display:inline-block;padding:2px 9px;border-radius:999px;font-size:10px;font-weight:700;}
.badge-on{background:rgba(34,197,94,.12);color:var(--green);border:1px solid rgba(34,197,94,.25);}
.badge-off{background:var(--bg3);color:var(--muted);border:1px solid var(--border);}
.badge-event{background:rgba(245,158,11,.1);color:var(--gold);border:1px solid rgba(245,158,11,.25);}
.badge-q{background:var(--yes-dim);color:var(--accent);border:1px solid rgba(59,130,246,.25);}
.btn-sm{padding:5px 12px;border-radius:7px;font-size:11px;font-weight:600;cursor:pointer;border:1px solid var(--border);background:var(--bg3);color:var(--muted2);transition:all .15s;white-space:nowrap;}
.btn-sm:hover{border-color:var(--border2);color:var(--text);}
.btn-danger{border-color:rgba(239,68,68,.3);color:var(--no);}
.btn-danger:hover{background:var(--no-dim);border-color:var(--no);}
.btn-success{border-color:rgba(34,197,94,.3);color:var(--green);}
.btn-success:hover{background:rgba(34,197,94,.08);border-color:var(--green);}
.btn-edit{border-color:rgba(59,130,246,.3);color:var(--accent);}
.btn-edit:hover{background:var(--yes-dim);border-color:var(--accent);}
.args-hidden{display:none;}
.cat-card{background:var(--bg2);border:1px solid var(--border);border-radius:16px;padding:20px;margin-bottom:12px;}
.cat-header{display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap;}
.cat-name{font-family:'Unbounded',sans-serif;font-size:14px;font-weight:700;flex:1;}
.cat-pills{display:flex;flex-wrap:wrap;gap:5px;}
.cat-pill{font-size:11px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:3px 9px;color:var(--muted2);}
.two-col{display:grid;grid-template-columns:360px 1fr;gap:20px;align-items:start;margin-bottom:24px;}
@media(max-width:760px){.two-col{grid-template-columns:1fr;}}
.logout-btn{padding:8px 16px;border-radius:9px;border:1px solid var(--border);background:transparent;color:var(--muted2);font-size:12px;cursor:pointer;transition:all .15s;}
.logout-btn:hover{border-color:var(--border2);color:var(--text);}
.err-box{background:var(--no-dim);border:1px solid rgba(239,68,68,.3);border-radius:9px;padding:11px 14px;font-size:13px;color:var(--no);margin-bottom:14px;}
.err-banner{background:var(--no-dim);border:1px solid rgba(239,68,68,.3);border-radius:12px;padding:14px 18px;font-size:13px;color:var(--no);margin-bottom:20px;}
.search-admin{padding:9px 12px;border-radius:10px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-size:13px;outline:none;width:240px;transition:border-color .18s;margin-bottom:16px;}
.search-admin:focus{border-color:rgba(59,130,246,.5);}
</style>
</head>
<body>
${SHARED_JS}
<nav>
  <div class="nav-inner">
    <a class="logo" href="/">ARGU<span>.</span></a>
    <div class="nav-right">
      <span style="font-size:12px;color:var(--muted2)">Admin Panel</span>
      <form action="/admin/logout" method="POST" style="display:inline"><button class="logout-btn">Sign out</button></form>
    </div>
  </div>
</nav>
<div class="page">
  <h2>Admin Dashboard</h2>
  <div id="globalErr"></div>
  <div class="tabs">
    <button class="tab active" data-panel="overview">📊 Overview</button>
    <button class="tab" data-panel="debates">💬 Debates</button>
    <button class="tab" data-panel="categories">🗂️ Categories</button>
    <button class="tab" data-panel="users">👥 Users</button>
  </div>
  <div class="panel active" id="panel-overview">
    <div id="kpiRow" class="stats-row"><div style="color:var(--muted)">Loading…</div></div>
    <div class="card"><h3>Unique Visitors — 14 days</h3><div class="chart-bar" id="chartBar"><div style="color:var(--muted);font-size:13px">Loading…</div></div></div>
  </div>
  <div class="panel" id="panel-debates">
    <div class="two-col">
      <div class="card">
        <h3>Add New Debate</h3>
        <div class="field"><label>Question</label><input id="newQ" placeholder="Should AI have rights?"/></div>
        <div class="field"><label>Category</label><select id="newCat">${catOpts}</select></div>
        <div class="field"><label>Type</label><select id="newType"><option value="question">Question</option><option value="event">Event</option></select></div>
        <button class="btn-primary" id="addBtn" style="width:100%;padding:12px;margin-top:6px">Add Debate</button>
      </div>
      <div></div>
    </div>
    <div class="card">
      <h3>All Debates</h3>
      <input class="search-admin" id="debateSearch" placeholder="Filter debates…"/>
      <div id="debatesTable"><div style="color:var(--muted)">Loading…</div></div>
    </div>
  </div>
  <div class="panel" id="panel-categories">
    <p style="font-size:13px;color:var(--muted2);margin-bottom:24px">Manage categories — move or delete debates in bulk.</p>
    <div id="catPanel"><div style="color:var(--muted)">Loading…</div></div>
  </div>
  <div class="panel" id="panel-users">
    <div class="card">
      <h3>Users</h3>
      <input class="search-admin" id="userSearch" placeholder="Filter users…"/>
      <div id="usersTable"><div style="color:var(--muted)">Loading…</div></div>
    </div>
  </div>
</div>
<div class="modal-bg hidden" id="editModal">
  <div class="modal">
    <h3 style="font-family:'Unbounded',sans-serif;font-size:14px;font-weight:700;margin-bottom:18px">Edit Debate</h3>
    <div id="editErr"></div>
    <div class="field"><label>Question</label><input id="editQ"/></div>
    <div class="field"><label>Category</label><select id="editCat">${catOpts}</select></div>
    <div class="field"><label>Type</label><select id="editType"><option value="question">Question</option><option value="event">Event</option></select></div>
    <div class="modal-actions"><button class="btn-sm" id="editCancel">Cancel</button><button class="btn-primary" id="editSave">Save changes</button></div>
  </div>
</div>
<script>
function $(id){return document.getElementById(id);}
function escA(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");}
async function req(url,opts){
  try{const r=await fetch(url,{credentials:"same-origin",headers:{"content-type":"application/json"},...(opts||{})});const t=await r.text();try{return JSON.parse(t);}catch{return{error:"Bad response ("+r.status+")"};}}
  catch(e){return{error:"Network error: "+e.message};}
}
document.querySelectorAll(".tab").forEach(tab=>{
  tab.addEventListener("click",()=>{
    document.querySelectorAll(".tab").forEach(t=>t.classList.remove("active"));
    document.querySelectorAll(".panel").forEach(p=>p.classList.remove("active"));
    tab.classList.add("active"); $("panel-"+tab.getAttribute("data-panel"))&&$("panel-"+tab.getAttribute("data-panel")).classList.add("active");
  });
});
const editModal=$("editModal"); let currentEditId=null;
$("editCancel").addEventListener("click",()=>editModal.classList.add("hidden"));
editModal.addEventListener("click",e=>{if(e.target===editModal)editModal.classList.add("hidden");});
let allDebates=[],allUsers=[];
function openEdit(id){
  const d=allDebates.find(x=>x.id===id); if(!d)return;
  currentEditId=id;$("editQ").value=d.question;$("editCat").value=d.category||"General";$("editType").value=d.type||"question";$("editErr").innerHTML="";
  editModal.classList.remove("hidden");setTimeout(()=>$("editQ").focus(),50);
}
$("editSave").addEventListener("click",async()=>{
  const q=$("editQ").value.trim(),cat=$("editCat").value,typ=$("editType").value;
  if(!q){$("editErr").innerHTML='<div class="err-box">Question cannot be empty</div>';return;}
  $("editSave").textContent="Saving…";
  const r=await req("/admin/debates/"+currentEditId,{method:"PATCH",body:JSON.stringify({question:q,category:cat,type:typ})});
  $("editSave").textContent="Save changes";
  if(r.error){$("editErr").innerHTML='<div class="err-box">'+escA(r.error)+'</div>';return;}
  editModal.classList.add("hidden");showToast("Debate updated","success");loadAll();
});
async function loadAll(){
  const d=await req("/admin/api/stats");
  if(!d||d.error){$("globalErr").innerHTML='<div class="err-banner">Failed to load stats: '+(d&&d.error||"unknown error")+'</div>';return;}
  $("globalErr").innerHTML=""; allDebates=d.top_debates||[]; allUsers=d.recent_users||[];
  renderOverview(d); renderDebates(); renderCategories(); renderUsers();
}
function renderOverview(d){
  $("kpiRow").innerHTML=[[d.debates||0,"Debates"],[d.users||0,"Users"],[d.messages||0,"Arguments"],[d.total_views||0,"Page Views"],[d.unique_visitors||0,"Unique Visitors","var(--accent)"]].map(([n,l,c])=>'<div class="kpi"><div class="kpi-n"'+(c?' style="color:'+c+'"':'')+'">'+n+'</div><div class="kpi-l">'+l+'</div></div>').join("");
  const daily=(d.daily||[]).slice().reverse();
  if(!daily.length){$("chartBar").innerHTML='<div style="color:var(--muted);font-size:13px">No data yet</div>';return;}
  const maxV=Math.max(...daily.map(r=>Number(r.uniq)||0),1);
  $("chartBar").innerHTML=daily.map(r=>{const h=Math.max(4,Math.round((Number(r.uniq)||0)/maxV*100));const date=r.day?new Date(r.day).toLocaleDateString("en-US",{month:"short",day:"numeric"}):"?";return '<div class="chart-col"><div class="chart-fill" style="height:'+h+'px" title="'+(r.uniq||0)+' unique"></div><div class="chart-lbl">'+date+'</div></div>';}).join("");
}
let debateFilter="";
function renderDebates(){
  const fl=allDebates.filter(d=>!debateFilter||d.question.toLowerCase().includes(debateFilter));
  if(!fl.length){$("debatesTable").innerHTML='<div style="color:var(--muted);padding:16px 0">No debates found</div>';return;}
  $("debatesTable").innerHTML='<table class="tbl"><thead><tr><th>Question</th><th>Category</th><th>Type</th><th>Args</th><th>Status</th><th>Actions</th></tr></thead><tbody>'+
    fl.map(d=>'<tr><td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+escA(d.question)+'">'+escA(d.question)+'</td><td><span style="font-size:11px;color:var(--muted2)">'+escA(d.category||"")+'</span></td><td>'+(d.type==="event"?'<span class="badge2 badge-event">event</span>':'<span class="badge2 badge-q">q</span>')+'</td><td style="font-weight:700">'+(d.arg_count||0)+'</td><td>'+(d.active?'<span class="badge2 badge-on">Active</span>':'<span class="badge2 badge-off">Hidden</span>')+'</td><td><div style="display:flex;gap:4px;flex-wrap:wrap"><button class="btn-sm btn-edit" onclick="openEdit('+d.id+')">✏️</button><button class="btn-sm btn-success" onclick="toggleDebate('+d.id+')">'+(d.active?"Hide":"Show")+'</button><button class="btn-sm btn-danger" onclick="delDebate('+d.id+')">Del</button><button class="btn-sm" onclick="toggleArgs('+d.id+',this)">▶ args</button></div></td></tr><tr id="args-row-'+d.id+'" class="args-hidden"><td colspan="6" style="padding:0;background:var(--bg3)"><div id="args-inner-'+d.id+'" style="padding:0 10px 12px"></div></td></tr>').join("")+'</tbody></table>';
}
$("debateSearch").addEventListener("input",e=>{debateFilter=e.target.value.toLowerCase();renderDebates();});
function toggleArgs(id,btn){
  const row=$("args-row-"+id);
  if(row.classList.contains("args-hidden")){row.classList.remove("args-hidden");btn.textContent="▼ args";loadArgs(id);}
  else{row.classList.add("args-hidden");btn.textContent="▶ args";}
}
async function loadArgs(did){
  const inner=$("args-inner-"+did); if(!inner)return;
  inner.innerHTML='<div style="color:var(--muted);font-size:12px;padding:10px 0">Loading…</div>';
  const msgs=await req("/debate/"+did+"/messages?limit=200&sort=new");
  if(!msgs||msgs.error||!msgs.length){inner.innerHTML='<div style="color:var(--muted);font-size:12px;padding:10px 0">No arguments</div>';return;}
  inner.innerHTML=msgs.map(m=>'<div style="display:flex;align-items:flex-start;gap:10px;padding:10px 0;border-bottom:1px solid var(--border)"><span class="badge2 '+(m.side==="YES"?"badge-on":"badge-off")+'">'+m.side+'</span><div style="flex:1;font-size:13px;line-height:1.5"><span style="font-weight:700;font-size:12px">'+escA(m.username)+'</span> <span style="color:var(--muted);font-size:11px">score:'+m.score+'</span><br>'+escA(m.text)+'</div><div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px"><span style="font-size:11px;color:var(--muted)">'+new Date(m.created_at).toLocaleDateString()+'</span><button class="btn-sm btn-danger" onclick="delMsg('+m.id+','+did+')">Del</button></div></div>').join("");
}
let userFilter="";
function renderUsers(){
  const fl=allUsers.filter(u=>!userFilter||u.username.toLowerCase().includes(userFilter));
  if(!fl.length){$("usersTable").innerHTML='<div style="color:var(--muted);padding:16px 0">No users found</div>';return;}
  $("usersTable").innerHTML='<table class="tbl"><thead><tr><th>Username</th><th>Rating</th><th>Args</th><th>Joined</th><th>Actions</th></tr></thead><tbody>'+
    fl.map(u=>{const uid="rat_"+u.username.replace(/\W/g,"_"),b=getBadge(u.rating);return '<tr><td><a href="/u/'+escA(u.username)+'" style="font-weight:700;display:flex;align-items:center;gap:5px">'+escA(u.username)+(b?'<span>'+b+'</span>':'')+'</a></td><td><input type="number" id="'+uid+'" value="'+u.rating+'" style="width:72px;padding:5px 8px;border-radius:7px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-size:13px;text-align:center;outline:none"/></td><td style="font-weight:700">'+(u.arg_count||0)+'</td><td style="color:var(--muted);font-size:12px">'+(u.created_at?new Date(u.created_at).toLocaleDateString():"—")+'</td><td><div style="display:flex;gap:4px"><button class="btn-sm btn-edit" onclick="saveRating(\''+escA(u.username)+'\',\''+uid+'\')">Save</button><button class="btn-sm btn-danger" onclick="delUser(\''+escA(u.username)+'\')">Delete</button></div></td></tr>';}).join("")+'</tbody></table>';
}
$("userSearch").addEventListener("input",e=>{userFilter=e.target.value.toLowerCase();renderUsers();});
function renderCategories(){
  const cm={};allDebates.forEach(d=>{const c=d.category||"General";if(!cm[c])cm[c]=[];cm[c].push(d);});
  const cats=Object.keys(cm).sort();
  if(!cats.length){$("catPanel").innerHTML='<div style="color:var(--muted)">No categories</div>';return;}
  const ALL=["Technology","Economy","Society","Politics","Education","Life","Work","General"];
  $("catPanel").innerHTML=cats.map(cat=>{
    const items=cm[cat],targets=ALL.filter(c=>c!==cat),selId="ms_"+cat.replace(/\W/g,"_");
    return '<div class="cat-card"><div class="cat-header"><span class="cat-name">'+escA(cat)+'</span><span style="font-size:12px;color:var(--muted)">'+items.length+' debate'+(items.length!==1?"s":"")+'</span><select id="'+selId+'" style="padding:6px 10px;border-radius:8px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-size:12px;outline:none">'+targets.map(c=>'<option value="'+escA(c)+'">'+escA(c)+'</option>').join("")+'</select><button class="btn-sm btn-edit" onclick="moveCat(\''+escA(cat)+'\',document.getElementById(\''+selId+'\').value)">Move all</button><button class="btn-sm btn-danger" onclick="delCat(\''+escA(cat)+'\')">Delete all</button></div><div class="cat-pills">'+items.map(d=>'<span class="cat-pill">'+escA(d.question.length>45?d.question.slice(0,45)+"…":d.question)+'</span>').join("")+'</div></div>';
  }).join("");
}
async function toggleDebate(id){const r=await req("/admin/debates/"+id+"/toggle",{method:"POST"});if(r.error)showToast(r.error,"error");else{showToast("Toggled","success");loadAll();}}
async function delDebate(id){if(!confirm("Delete debate + all arguments?"))return;const r=await req("/admin/debates/"+id,{method:"DELETE"});if(r.error)showToast(r.error,"error");else{showToast("Deleted","success");loadAll();}}
async function delMsg(mid,did){if(!confirm("Delete this argument?"))return;const r=await req("/admin/messages/"+mid,{method:"DELETE"});if(r.error)showToast(r.error,"error");else{showToast("Deleted","success");loadArgs(did);}}
async function moveCat(from,to){if(!to||!confirm('Move "'+from+'" → "'+to+'"?'))return;const r=await req("/admin/category/"+encodeURIComponent(from),{method:"DELETE",body:JSON.stringify({action:"move",target:to})});if(r.error)showToast(r.error,"error");else{showToast("Moved","success");loadAll();}}
async function delCat(name){if(!confirm('Delete category "'+name+'" AND all its debates?'))return;const r=await req("/admin/category/"+encodeURIComponent(name),{method:"DELETE",body:JSON.stringify({action:"delete"})});if(r.error)showToast(r.error,"error");else{showToast("Deleted","success");loadAll();}}
async function saveRating(username,inputId){const val=parseInt((document.getElementById(inputId)||{}).value,10);if(isNaN(val))return;const r=await req("/admin/users/"+encodeURIComponent(username)+"/rating",{method:"PATCH",body:JSON.stringify({rating:val})});if(r.error)showToast(r.error,"error");else{showToast("Rating saved","success");loadAll();}}
async function delUser(username){if(!confirm('Delete "'+username+'" and ALL data?'))return;const r=await req("/admin/users/"+encodeURIComponent(username),{method:"DELETE"});if(r.error)showToast(r.error,"error");else{showToast("User deleted","success");loadAll();}}
$("addBtn").addEventListener("click",async()=>{
  const q=$("newQ").value.trim(),cat=$("newCat").value,typ=$("newType").value;
  if(!q)return showToast("Enter a question","error");
  $("addBtn").textContent="Adding…";
  const r=await req("/admin/debates",{method:"POST",body:JSON.stringify({question:q,category:cat,type:typ})});
  $("addBtn").textContent="Add Debate";
  if(r.error)return showToast(r.error,"error");
  $("newQ").value=""; showToast("Debate added!","success"); loadAll();
});
loadAll();
</script></body></html>`;
}

// ── Server start ──────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("ARGU running on port " + PORT));