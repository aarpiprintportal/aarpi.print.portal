require("dotenv").config();
const express = require("express");
const session = require("express-session");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const nodemailer = require("nodemailer");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const APP_URL = (process.env.APP_URL || `http://localhost:${PORT}`).replace(/\/$/, "");

if (!process.env.SESSION_SECRET) console.warn("WARNING: Set SESSION_SECRET in .env before production.");

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false, limit: "100kb" }));
app.use(express.json({ limit: "100kb" }));

const db = new Database(path.join(__dirname, "data.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  phone TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'member',
  wallet_balance INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_login_at TEXT
);
CREATE TABLE IF NOT EXISTS password_resets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  icon TEXT NOT NULL DEFAULT '📄',
  description TEXT NOT NULL DEFAULT 'Service module',
  active INTEGER NOT NULL DEFAULT 1,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS wallet_transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('credit','debit')),
  amount INTEGER NOT NULL CHECK(amount >= 0),
  description TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS activity (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  service TEXT NOT NULL,
  type TEXT NOT NULL,
  amount INTEGER NOT NULL DEFAULT 0,
  description TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Success',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);
`);

// Safe migration for databases created by the previous version.
const cols = db.prepare("PRAGMA table_info(users)").all().map(x => x.name);
if (!cols.includes("role")) db.exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'member'");

const serviceSeed = [
  ["Aadhaar Services","🪪"],["PAN Card Services","💳"],["Aadhaar To PAN","🪪"],
  ["Vehical Services","🏍️"],["Ration Services","🍚"],["Voter Services","🗳️"],
  ["Farmer Services","🌾"],["ElectriBill Services","📄"],["RTPS Services","📜"],
  ["JanAadhar Services","🧾"],["FamilyID Services","👨‍👩‍👧"],["Learning Exam","📚"],
  ["Other Services","📥"],["Instant Voter PDF","🗳️"],["Manual Certificate","📜"]
];
if (db.prepare("SELECT COUNT(*) c FROM services").get().c === 0) {
  const ins = db.prepare("INSERT INTO services(name,icon,description,sort_order) VALUES(?,?,?,?)");
  const tx = db.transaction(() => serviceSeed.forEach((s,i)=>ins.run(s[0],s[1],"Service module",i)));
  tx();
}

const authLimiter = rateLimit({windowMs:15*60*1000,max:30,standardHeaders:true,legacyHeaders:false});
const adminLimiter = rateLimit({windowMs:15*60*1000,max:40,standardHeaders:true,legacyHeaders:false});
const resetLimiter = rateLimit({windowMs:15*60*1000,max:10,standardHeaders:true,legacyHeaders:false});

app.use(session({
  name:"aarpi.sid",
  secret:process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
  resave:false, saveUninitialized:false,
  cookie:{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:8*60*60*1000}
}));

function clean(v){return String(v||"").trim();}
function validEmail(v){return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);}
function validPhone(v){return /^[0-9]{10,15}$/.test(v);}
function csrfToken(req){if(!req.session.csrf)req.session.csrf=crypto.randomBytes(24).toString("hex");return req.session.csrf;}
function checkCsrf(req){return Boolean(req.body._csrf && req.session.csrf && req.body._csrf===req.session.csrf);}
function esc(s){return String(s).replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]));}

function currentUser(req){
  if(!req.session.userId)return null;
  return db.prepare("SELECT id,name,email,phone,role,wallet_balance,created_at,last_login_at FROM users WHERE id=?").get(req.session.userId);
}
function requireAuth(req,res,next){
  const u=currentUser(req); if(!u){return res.redirect("/login");} req.user=u; next();
}
function requireAdmin(req,res,next){
  const u=currentUser(req);
  if(!u || u.role!=="admin"){return res.redirect("/admin/login?error="+encodeURIComponent("Admin access required."));}
  req.user=u; next();
}
function page(title,body,req,admin=false){
  const u=currentUser(req);
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} — AARPI Print Portal</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:Arial,Helvetica,sans-serif;background:#f4f6f8;color:#24313c}
.top{height:62px;background:linear-gradient(90deg,#225f9e,#2d75b9);color:#fff;display:flex;align-items:center;padding:0 18px}.brand{font-weight:800;font-size:18px}.brand span{display:inline-grid;place-items:center;width:38px;height:38px;background:#fff;color:#1769aa;border-radius:10px;margin-right:9px}.top a,.top button{color:#fff;text-decoration:none;margin-left:auto;background:none;border:0;cursor:pointer;font-size:14px}.wrap{max-width:1200px;margin:24px auto;padding:0 15px}.panel{background:#fff;border:1px solid #ddd;border-radius:10px;box-shadow:0 2px 8px #0001;padding:20px}.auth{max-width:480px;margin:45px auto}.h1{margin:0 0 8px;font-size:25px}.muted{color:#697580;font-size:14px}.label{display:block;font-size:13px;font-weight:700;margin:15px 0 6px}.input,.select{width:100%;padding:11px;border:1px solid #cfd7df;border-radius:7px;font-size:14px}.btn{display:inline-block;border:0;background:#1769aa;color:#fff;padding:10px 15px;border-radius:7px;font-weight:700;cursor:pointer;text-decoration:none}.btn.green{background:#12ae72}.btn.red{background:#df3c4c}.btn.gray{background:#66727d}.error{background:#ffe8e8;color:#a52323;padding:10px;border-radius:7px;margin:14px 0;font-size:14px}.ok{background:#e5fff3;color:#08784f;padding:10px;border-radius:7px;margin:14px 0;font-size:14px}.links{margin-top:16px;font-size:14px}.links a{color:#1769aa}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.card{background:#fff;border:1px solid #ddd;border-radius:8px;padding:18px}.service{min-height:110px;display:flex;align-items:center;justify-content:center;text-align:center;font-weight:700}.service small{display:block;font-weight:400;color:#6b7480;margin-top:6px}.grid2{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}.stat{font-size:28px;font-weight:800;color:#1769aa}.tablewrap{overflow:auto}table{width:100%;border-collapse:collapse;font-size:12px;min-width:760px}th,td{padding:9px;border-bottom:1px solid #eee;text-align:left}th{background:#f7f9fb}.badge{display:inline-block;padding:5px 8px;border-radius:14px;background:#eaf4ff;color:#1769aa;font-size:11px}.badge.green{background:#e5fff3;color:#08784f}.badge.red{background:#ffe8e8;color:#a52323}.adminnav{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}.adminnav a{padding:9px 11px;border-radius:7px;background:#fff;border:1px solid #ddd;color:#1769aa;text-decoration:none;font-size:13px}.row{display:flex;gap:10px;align-items:end;flex-wrap:wrap}.row>*{flex:1}.row .fit{flex:0 0 auto}@media(max-width:800px){.cards,.grid2{grid-template-columns:1fr}.top{padding:0 10px}.brand{font-size:15px}}
</style></head><body>
<header class="top"><div class="brand"><span>ARP</span>AARPI PRINT PORTAL</div>
${u?`<form method="post" action="/logout" style="margin-left:auto"><input type="hidden" name="_csrf" value="${csrfToken(req)}"><button>Logout</button></form>`:""}</header>${body}</body></html>`;
}

function redirectError(res,url,msg){return res.redirect(url+"?error="+encodeURIComponent(msg));}

app.get("/",(req,res)=>res.redirect(req.session.userId?"/dashboard":"/login"));

app.get("/register",(req,res)=>{
 if(req.session.userId)return res.redirect("/dashboard");
 res.send(page("Register",`<div class="wrap"><div class="panel auth"><h1 class="h1">Create member account</h1><p class="muted">Register for AARPI Print Portal.</p>
${req.query.error?`<div class="error">${esc(req.query.error)}</div>`:""}<form method="post"><input type="hidden" name="_csrf" value="${csrfToken(req)}">
<label class="label">Full name</label><input class="input" name="name" required maxlength="80">
<label class="label">Email</label><input class="input" name="email" type="email" required maxlength="160">
<label class="label">Mobile</label><input class="input" name="phone" required maxlength="15">
<label class="label">Password</label><input class="input" name="password" type="password" minlength="8" required>
<label class="label">Confirm password</label><input class="input" name="confirmPassword" type="password" minlength="8" required>
<br><br><button class="btn green">Create account</button></form><div class="links">Already registered? <a href="/login">Login</a></div></div></div>`,req));
});
app.post("/register",authLimiter,(req,res)=>{
 if(!checkCsrf(req))return res.status(403).send("Invalid request token.");
 const name=clean(req.body.name),email=clean(req.body.email).toLowerCase(),phone=clean(req.body.phone),pw=String(req.body.password||""),cp=String(req.body.confirmPassword||"");
 if(name.length<2||!validEmail(email)||!validPhone(phone)||pw.length<8||pw!==cp)return redirectError(res,"/register","Please enter valid details. Password must be at least 8 characters.");
 try{
  const r=db.prepare("INSERT INTO users(name,email,phone,password_hash) VALUES(?,?,?,?)").run(name,email,phone,bcrypt.hashSync(pw,12));
  req.session.regenerate(()=>{req.session.userId=Number(r.lastInsertRowid);req.session.csrf=crypto.randomBytes(24).toString("hex");res.redirect("/dashboard");});
 }catch(e){return redirectError(res,"/register",String(e.message).includes("UNIQUE")?"An account with this email already exists.":"Registration failed.");}
});

app.get("/login",(req,res)=>res.send(page("Login",`<div class="wrap"><div class="panel auth"><h1 class="h1">Member Login</h1><p class="muted">Sign in to your AARPI Print Portal account.</p>
${req.query.error?`<div class="error">${esc(req.query.error)}</div>`:""}${req.query.ok?`<div class="ok">${esc(req.query.ok)}</div>`:""}
<form method="post"><input type="hidden" name="_csrf" value="${csrfToken(req)}"><label class="label">Email</label><input class="input" name="email" type="email" required>
<label class="label">Password</label><input class="input" name="password" type="password" required><br><br><button class="btn">Login</button></form>
<div class="links"><a href="/forgot-password">Forgot password?</a> · <a href="/register">Create account</a></div></div></div>`,req)));

app.post("/login",authLimiter,(req,res)=>{
 if(!checkCsrf(req))return res.status(403).send("Invalid request token.");
 const email=clean(req.body.email).toLowerCase(),pw=String(req.body.password||"");
 const u=db.prepare("SELECT * FROM users WHERE email=?").get(email);
 if(!u||!bcrypt.compareSync(pw,u.password_hash))return redirectError(res,"/login","Invalid email or password.");
 db.prepare("UPDATE users SET last_login_at=datetime('now') WHERE id=?").run(u.id);
 req.session.regenerate(()=>{req.session.userId=u.id;req.session.csrf=crypto.randomBytes(24).toString("hex");res.redirect(u.role==="admin"?"/admin":"/dashboard");});
});

app.post("/logout",(req,res)=>{if(!checkCsrf(req))return res.status(403).send("Invalid request token.");req.session.destroy(()=>res.redirect("/login?ok="+encodeURIComponent("You have been logged out.")));});

app.get("/forgot-password",(req,res)=>res.send(page("Forgot Password",`<div class="wrap"><div class="panel auth"><h1 class="h1">Reset password</h1><p class="muted">Enter your registered email. If it exists, a reset link will be sent.</p>
${req.query.ok?`<div class="ok">${esc(req.query.ok)}</div>`:""}<form method="post"><input type="hidden" name="_csrf" value="${csrfToken(req)}"><label class="label">Email</label><input class="input" name="email" type="email" required><br><br><button class="btn">Send reset link</button></form>
<div class="links"><a href="/login">Back to login</a></div></div></div>`,req)));

app.post("/forgot-password",resetLimiter,async(req,res)=>{
 if(!checkCsrf(req))return res.status(403).send("Invalid request token.");
 const email=clean(req.body.email).toLowerCase(),u=db.prepare("SELECT id,email,name FROM users WHERE email=?").get(email);
 const generic="If an account exists for that email, password-reset instructions have been sent.";
 if(!u)return res.redirect("/forgot-password?ok="+encodeURIComponent(generic));
 db.prepare("UPDATE password_resets SET used_at=? WHERE user_id=? AND used_at IS NULL").run(Date.now(),u.id);
 const raw=crypto.randomBytes(32).toString("hex"),hash=crypto.createHash("sha256").update(raw).digest("hex"),expires=Date.now()+30*60*1000;
 db.prepare("INSERT INTO password_resets(user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?)").run(u.id,hash,expires,Date.now());
 const link=`${APP_URL}/reset-password/${raw}`; await sendResetEmail(u,link);
 res.redirect("/forgot-password?ok="+encodeURIComponent(generic));
});

app.get("/reset-password/:token",(req,res)=>{
 const hash=crypto.createHash("sha256").update(String(req.params.token)).digest("hex");
 const r=db.prepare("SELECT id FROM password_resets WHERE token_hash=? AND used_at IS NULL AND expires_at>?").get(hash,Date.now());
 if(!r)return res.status(400).send(page("Reset Password",`<div class="wrap"><div class="panel auth"><h1 class="h1">Invalid or expired link</h1><a class="btn" href="/forgot-password">Request new link</a></div></div>`,req));
 res.send(page("Reset Password",`<div class="wrap"><div class="panel auth"><h1 class="h1">Choose a new password</h1><form method="post"><input type="hidden" name="_csrf" value="${csrfToken(req)}">
<label class="label">New password</label><input class="input" name="password" type="password" minlength="8" required><label class="label">Confirm password</label><input class="input" name="confirmPassword" type="password" minlength="8" required><br><br><button class="btn green">Update password</button></form></div></div>`,req));
});
app.post("/reset-password/:token",authLimiter,(req,res)=>{
 if(!checkCsrf(req))return res.status(403).send("Invalid request token.");
 const pw=String(req.body.password||""),cp=String(req.body.confirmPassword||"");
 if(pw.length<8||pw!==cp)return res.status(400).send("Passwords must match and be at least 8 characters.");
 const hash=crypto.createHash("sha256").update(String(req.params.token)).digest("hex");
 const r=db.prepare("SELECT id,user_id FROM password_resets WHERE token_hash=? AND used_at IS NULL AND expires_at>?").get(hash,Date.now());
 if(!r)return res.status(400).send("Invalid or expired reset link.");
 const tx=db.transaction(()=>{db.prepare("UPDATE users SET password_hash=? WHERE id=?").run(bcrypt.hashSync(pw,12),r.user_id);db.prepare("UPDATE password_resets SET used_at=? WHERE user_id=? AND used_at IS NULL").run(Date.now(),r.user_id);});
 tx();req.session.destroy(()=>res.redirect("/login?ok="+encodeURIComponent("Password updated. Please log in.")));
});

app.get("/dashboard",requireAuth,(req,res)=>{
 const services=db.prepare("SELECT * FROM services WHERE active=1 ORDER BY sort_order,id").all();
 const cards=services.map(s=>`<div class="card service"><div style="font-size:30px">${esc(s.icon)}<div>${esc(s.name)}</div><small>${esc(s.description)}</small></div></div>`).join("");
 const acts=db.prepare("SELECT * FROM activity WHERE user_id=? ORDER BY id DESC LIMIT 10").all(req.user.id);
 const rows=acts.length?acts.map(a=>`<tr><td>${esc(a.service)}</td><td>${esc(a.type)}</td><td>₹${a.amount}</td><td>${esc(a.description)}</td><td>${esc(a.created_at)}</td><td><span class="badge green">${esc(a.status)}</span></td></tr>`).join(""):`<tr><td colspan="6">No account activity yet.</td></tr>`;
 const body=`<div class="wrap"><div class="panel"><h1 class="h1">Hi, ${esc(req.user.name)}</h1><p class="muted">${esc(req.user.email)} · ${esc(req.user.phone)}</p><div class="grid2"><div class="card"><div class="muted">Wallet Balance</div><div class="stat">₹${req.user.wallet_balance}</div></div><div class="card"><div class="muted">Member Since</div><div class="stat" style="font-size:20px">${esc(req.user.created_at)}</div></div></div></div>
<h2 style="font-size:18px;margin:22px 0 10px">Services</h2><div class="cards">${cards}</div>
<div class="panel" style="margin-top:18px"><h2 style="font-size:16px">Last Account Activity</h2><div class="tablewrap"><table><tr><th>Service</th><th>Type</th><th>Amount</th><th>Description</th><th>Date</th><th>Status</th></tr>${rows}</table></div></div></div>`;
 res.send(page("Dashboard",body,req));
});

/* ---------------- ADMIN ---------------- */

function adminLayout(req,content){
 const nav=`<div class="adminnav"><a href="/admin">Overview</a><a href="/admin/members">Members</a><a href="/admin/resets">Reset Requests</a><a href="/admin/services">Service Cards</a><a href="/admin/activity">Account Activity</a><a href="/admin/wallets">Wallets</a></div>`;
 return `<div class="wrap"><h1 class="h1">Admin Panel</h1><p class="muted">AARPI Print Portal management console</p>${nav}${content}</div>`;
}
app.get("/admin/login",(req,res)=>{
 if(req.session.userId && currentUser(req)?.role==="admin")return res.redirect("/admin");
 res.send(page("Admin Login",`<div class="wrap"><div class="panel auth"><h1 class="h1">Admin Login</h1><p class="muted">Restricted administrator access.</p>
${req.query.error?`<div class="error">${esc(req.query.error)}</div>`:""}<form method="post"><input type="hidden" name="_csrf" value="${csrfToken(req)}"><label class="label">Admin email</label><input class="input" name="email" type="email" required><label class="label">Password</label><input class="input" name="password" type="password" required><br><br><button class="btn">Admin Login</button></form></div></div>`,req));
});
app.post("/admin/login",adminLimiter,(req,res)=>{
 if(!checkCsrf(req))return res.status(403).send("Invalid request token.");
 const email=clean(req.body.email).toLowerCase(),pw=String(req.body.password||""),u=db.prepare("SELECT * FROM users WHERE email=? AND role='admin'").get(email);
 if(!u||!bcrypt.compareSync(pw,u.password_hash))return redirectError(res,"/admin/login","Invalid admin credentials.");
 req.session.regenerate(()=>{req.session.userId=u.id;req.session.csrf=crypto.randomBytes(24).toString("hex");res.redirect("/admin");});
});

app.get("/admin",requireAdmin,(req,res)=>{
 const stats={
  members:db.prepare("SELECT COUNT(*) c FROM users WHERE role='member'").get().c,
  admins:db.prepare("SELECT COUNT(*) c FROM users WHERE role='admin'").get().c,
  resets:db.prepare("SELECT COUNT(*) c FROM password_resets WHERE used_at IS NULL AND expires_at>?").get(Date.now()).c,
  services:db.prepare("SELECT COUNT(*) c FROM services WHERE active=1").get().c,
  wallet:db.prepare("SELECT COALESCE(SUM(wallet_balance),0) s FROM users").get().s
 };
 const content=`<div class="cards">
 <div class="card"><div class="muted">Members</div><div class="stat">${stats.members}</div></div>
 <div class="card"><div class="muted">Active Services</div><div class="stat">${stats.services}</div></div>
 <div class="card"><div class="muted">Pending Reset Requests</div><div class="stat">${stats.resets}</div></div>
 <div class="card"><div class="muted">Total Wallet Balance</div><div class="stat">₹${stats.wallet}</div></div>
 </div><div class="panel" style="margin-top:16px"><b>Logged in as:</b> ${esc(req.user.email)} <span class="badge">Administrator</span>
 <p class="muted">Use the sections above to manage members, reset requests, service cards, wallet balances and account activity.</p></div>`;
 res.send(page("Admin",adminLayout(req,content),req,true));
});

app.get("/admin/members",requireAdmin,(req,res)=>{
 const members=db.prepare("SELECT id,name,email,phone,role,wallet_balance,created_at,last_login_at FROM users ORDER BY id DESC").all();
 const rows=members.map(u=>`<tr><td>${u.id}</td><td>${esc(u.name)}</td><td>${esc(u.email)}</td><td>${esc(u.phone)}</td><td><span class="badge">${esc(u.role)}</span></td><td>₹${u.wallet_balance}</td><td>${esc(u.created_at)}</td><td>${esc(u.last_login_at||"Never")}</td><td>${u.role==="member"?`<form method="post" action="/admin/members/${u.id}/delete" style="display:inline"><input type="hidden" name="_csrf" value="${csrfToken(req)}"><button class="btn red" onclick="return confirm('Delete this member?')">Delete</button></form>`:""}</td></tr>`).join("");
 const content=`<div class="panel"><h2 style="font-size:17px">Members</h2><div class="tablewrap"><table><tr><th>ID</th><th>Name</th><th>Email</th><th>Phone</th><th>Role</th><th>Wallet</th><th>Created</th><th>Last login</th><th>Action</th></tr>${rows}</table></div></div>`;
 res.send(page("Members",adminLayout(req,content),req,true));
});
app.post("/admin/members/:id/delete",requireAdmin,(req,res)=>{
 if(!checkCsrf(req))return res.status(403).send("Invalid request token.");
 const id=Number(req.params.id); if(id===req.user.id)return redirectError(res,"/admin/members","You cannot delete your own admin account.");
 db.prepare("DELETE FROM users WHERE id=? AND role='member'").run(id);res.redirect("/admin/members");
});

app.get("/admin/resets",requireAdmin,(req,res)=>{
 const rows=db.prepare(`SELECT pr.id,pr.created_at,pr.expires_at,u.name,u.email
 FROM password_resets pr JOIN users u ON u.id=pr.user_id
 WHERE pr.used_at IS NULL AND pr.expires_at>? ORDER BY pr.id DESC`).all(Date.now());
 const html=rows.length?rows.map(r=>`<tr><td>${r.id}</td><td>${esc(r.name)}</td><td>${esc(r.email)}</td><td>${new Date(r.created_at).toLocaleString()}</td><td>${new Date(r.expires_at).toLocaleString()}</td><td><form method="post" action="/admin/resets/${r.id}/invalidate"><input type="hidden" name="_csrf" value="${csrfToken(req)}"><button class="btn red">Invalidate</button></form></td></tr>`).join(""):`<tr><td colspan="6">No active reset requests.</td></tr>`;
 const content=`<div class="panel"><h2 style="font-size:17px">Active Password Reset Requests</h2><div class="tablewrap"><table><tr><th>ID</th><th>Member</th><th>Email</th><th>Created</th><th>Expires</th><th>Action</th></tr>${html}</table></div></div>`;
 res.send(page("Reset Requests",adminLayout(req,content),req,true));
});
app.post("/admin/resets/:id/invalidate",requireAdmin,(req,res)=>{
 if(!checkCsrf(req))return res.status(403).send("Invalid request token.");
 db.prepare("UPDATE password_resets SET used_at=? WHERE id=?").run(Date.now(),Number(req.params.id));res.redirect("/admin/resets");
});

app.get("/admin/services",requireAdmin,(req,res)=>{
 const services=db.prepare("SELECT * FROM services ORDER BY sort_order,id").all();
 const rows=services.map(s=>`<tr><td>${s.id}</td><td>${esc(s.icon)}</td><td>${esc(s.name)}</td><td>${esc(s.description)}</td><td>${s.sort_order}</td><td><span class="badge ${s.active?"green":"red"}">${s.active?"Active":"Hidden"}</span></td><td>
 <form method="post" action="/admin/services/${s.id}/toggle" style="display:inline"><input type="hidden" name="_csrf" value="${csrfToken(req)}"><button class="btn gray">${s.active?"Hide":"Activate"}</button></form>
 <form method="post" action="/admin/services/${s.id}/delete" style="display:inline;margin-left:4px"><input type="hidden" name="_csrf" value="${csrfToken(req)}"><button class="btn red" onclick="return confirm('Delete service card?')">Delete</button></form></td></tr>`).join("");
 const content=`<div class="grid2"><div class="panel"><h2 style="font-size:17px">Add Service Card</h2><form method="post" action="/admin/services">
<input type="hidden" name="_csrf" value="${csrfToken(req)}"><label class="label">Name</label><input class="input" name="name" required maxlength="80">
<label class="label">Icon / emoji</label><input class="input" name="icon" value="📄" maxlength="8"><label class="label">Description</label><input class="input" name="description" value="Service module" maxlength="120">
<label class="label">Sort order</label><input class="input" name="sort_order" type="number" value="0"><br><br><button class="btn green">Add card</button></form></div>
<div class="panel"><h2 style="font-size:17px">Service cards</h2><div class="tablewrap"><table><tr><th>ID</th><th>Icon</th><th>Name</th><th>Description</th><th>Order</th><th>Status</th><th>Actions</th></tr>${rows}</table></div></div></div>`;
 res.send(page("Service Cards",adminLayout(req,content),req,true));
});
app.post("/admin/services",requireAdmin,(req,res)=>{
 if(!checkCsrf(req))return res.status(403).send("Invalid request token.");
 const name=clean(req.body.name),icon=clean(req.body.icon)||"📄",desc=clean(req.body.description)||"Service module",order=Number(req.body.sort_order||0);
 if(!name)return redirectError(res,"/admin/services","Service name is required.");
 db.prepare("INSERT INTO services(name,icon,description,sort_order) VALUES(?,?,?,?)").run(name,icon,desc,order);res.redirect("/admin/services");
});
app.post("/admin/services/:id/toggle",requireAdmin,(req,res)=>{
 if(!checkCsrf(req))return res.status(403).send("Invalid request token.");
 db.prepare("UPDATE services SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=?").run(Number(req.params.id));res.redirect("/admin/services");
});
app.post("/admin/services/:id/delete",requireAdmin,(req,res)=>{
 if(!checkCsrf(req))return res.status(403).send("Invalid request token.");
 db.prepare("DELETE FROM services WHERE id=?").run(Number(req.params.id));res.redirect("/admin/services");
});

function walletPage(req,err=""){
 const members=db.prepare("SELECT id,name,email,wallet_balance FROM users WHERE role='member' ORDER BY name").all();
 const rows=members.map(u=>`<tr><td>${u.id}</td><td>${esc(u.name)}</td><td>${esc(u.email)}</td><td>₹${u.wallet_balance}</td><td>
 <form method="post" action="/admin/wallets/${u.id}" class="row"><input type="hidden" name="_csrf" value="${csrfToken(req)}"><select class="select" name="type"><option value="credit">Credit</option><option value="debit">Debit</option></select><input class="input" name="amount" type="number" min="1" step="1" placeholder="Amount" required><input class="input" name="description" placeholder="Description" required><button class="btn">Apply</button></form></td></tr>`).join("");
 return `<div class="panel">${err?`<div class="error">${esc(err)}</div>`:""}<h2 style="font-size:17px">Wallet Balances</h2><div class="tablewrap"><table><tr><th>ID</th><th>Member</th><th>Email</th><th>Balance</th><th>Adjustment</th></tr>${rows}</table></div></div>`;
}
app.get("/admin/wallets",requireAdmin,(req,res)=>res.send(page("Wallets",adminLayout(req,walletPage(req)),req,true)));
app.post("/admin/wallets/:id",requireAdmin,(req,res)=>{
 if(!checkCsrf(req))return res.status(403).send("Invalid request token.");
 const id=Number(req.params.id),amount=Number(req.body.amount),type=req.body.type,description=clean(req.body.description);
 const u=db.prepare("SELECT id,wallet_balance FROM users WHERE id=? AND role='member'").get(id);
 if(!u||!Number.isInteger(amount)||amount<=0||!["credit","debit"].includes(type)||!description)return res.send(page("Wallets",adminLayout(req,walletPage(req,"Invalid wallet adjustment.")),req,true));
 if(type==="debit"&&u.wallet_balance<amount)return res.send(page("Wallets",adminLayout(req,walletPage(req,"Insufficient wallet balance.")),req,true));
 const tx=db.transaction(()=>{
  const next=type==="credit"?u.wallet_balance+amount:u.wallet_balance-amount;
  db.prepare("UPDATE users SET wallet_balance=? WHERE id=?").run(next,id);
  db.prepare("INSERT INTO wallet_transactions(user_id,type,amount,description) VALUES(?,?,?,?)").run(id,type,amount,description);
  db.prepare("INSERT INTO activity(user_id,service,type,amount,description,status) VALUES(?,?,?,?,?,?)").run(id,"Wallet",type==="credit"?"Credit":"Debit",amount,description,"Success");
 });
 tx();res.redirect("/admin/wallets");
});

app.get("/admin/activity",requireAdmin,(req,res)=>{
 const rows=db.prepare(`SELECT a.*,u.name,u.email FROM activity a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 500`).all();
 const html=rows.length?rows.map(a=>`<tr><td>${a.id}</td><td>${esc(a.name||"Deleted user")}</td><td>${esc(a.email||"")}</td><td>${esc(a.service)}</td><td>${esc(a.type)}</td><td>₹${a.amount}</td><td>${esc(a.description)}</td><td>${esc(a.created_at)}</td><td><span class="badge green">${esc(a.status)}</span></td></tr>`).join(""):`<tr><td colspan="9">No activity.</td></tr>`;
 const content=`<div class="panel"><h2 style="font-size:17px">Account Activity</h2><div class="tablewrap"><table><tr><th>ID</th><th>Member</th><th>Email</th><th>Service</th><th>Type</th><th>Amount</th><th>Description</th><th>Date</th><th>Status</th></tr>${html}</table></div></div>`;
 res.send(page("Account Activity",adminLayout(req,content),req,true));
});

app.use((req,res)=>res.status(404).send(page("Not Found",`<div class="wrap"><div class="panel"><h1 class="h1">404</h1><a class="btn" href="${req.session.userId?(currentUser(req)?.role==="admin"?"/admin":"/dashboard"):"/login"}">Go back</a></div></div>`,req)));

async function sendResetEmail(user,link){
 if(!process.env.SMTP_HOST||!process.env.SMTP_USER||!process.env.SMTP_PASS){
   console.log(`\n[AARPI PASSWORD RESET - DEV MODE]\nTo: ${user.email}\nReset link: ${link}\nExpires in 30 minutes.\n`); return;
 }
 const transporter=nodemailer.createTransport({host:process.env.SMTP_HOST,port:Number(process.env.SMTP_PORT||587),secure:String(process.env.SMTP_SECURE).toLowerCase()==="true",auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}});
 await transporter.sendMail({from:process.env.MAIL_FROM||process.env.SMTP_USER,to:user.email,subject:"AARPI Print Portal password reset",text:`Hello ${user.name},\n\nReset your password using this link (valid for 30 minutes):\n${link}\n\nIf you did not request this, ignore this email.`});
}

// Optional first-admin bootstrap. Only creates an admin when both variables are explicitly provided.
function bootstrapAdmin(){
 const email=clean(process.env.ADMIN_EMAIL).toLowerCase(),pw=String(process.env.ADMIN_PASSWORD||"");
 if(!email||!pw)return;
 if(!validEmail(email)||pw.length<12){console.warn("ADMIN_EMAIL/ADMIN_PASSWORD supplied but password must be >=12 chars; admin bootstrap skipped.");return;}
 const existing=db.prepare("SELECT id,role FROM users WHERE email=?").get(email);
 const hash=bcrypt.hashSync(pw,12);
 if(!existing){
   db.prepare("INSERT INTO users(name,email,phone,password_hash,role) VALUES(?,?,?,?,?)").run("AARPI Administrator",email,"0000000000",hash,"admin");
   console.log(`Admin account created for ${email}`);
 } else if(existing.role!=="admin"){
   db.prepare("UPDATE users SET role='admin',password_hash=? WHERE id=?").run(hash,existing.id);
   console.log(`Existing account promoted to admin: ${email}`);
 }
}
bootstrapAdmin();

app.listen(PORT,()=>console.log(`AARPI Print Portal running at ${APP_URL}`));
