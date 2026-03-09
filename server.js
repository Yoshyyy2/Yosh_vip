const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const CONFIG_FILE = path.join(__dirname, 'config.json');
const DB_FILE = path.join(__dirname, 'accounts.json');

// ── Config ────────────────────────────────────────────────
const PANEL_PASSWORD = 'Yoshyyydark_theuknown273572';
const MAX_SESSIONS = 5;
const DAILY_LIMIT_SSH = 2;
const DAILY_LIMIT_V2RAY = 2;
const SESSION_TTL = 24 * 60 * 60 * 1000;

const SESSIONS_FILE = path.join(__dirname, 'sessions.json');

function loadSessions() {
  if (!fs.existsSync(SESSIONS_FILE)) return {};
  try { return JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8')); }
  catch { return {}; }
}
function saveSessions(s) { fs.writeFileSync(SESSIONS_FILE, JSON.stringify(s, null, 2)); }

function cleanSessions() {
  const s = loadSessions(); const now = Date.now(); let changed = false;
  for (const [token, data] of Object.entries(s)) {
    if (now - data.createdAt > SESSION_TTL) { delete s[token]; changed = true; }
  }
  if (changed) saveSessions(s);
}
cleanSessions();
setInterval(cleanSessions, 60 * 60 * 1000);

app.use(cors());
app.use(express.json());

function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.headers['x-real-ip'] || req.socket.remoteAddress || 'unknown';
}

function requireAuth(req, res, next) {
  const token = req.headers['x-auth-token'] || req.query.token;
  const sessions = loadSessions();
  if (!token || !sessions[token]) return res.status(401).json({ error: 'Unauthorized' });
  sessions[token].lastActive = Date.now();
  saveSessions(sessions);
  next();
}


// ── Telegram Notify ───────────────────────────────────────
const TG_TOKEN = '8699561853:AAEfgO2yHpLYEDjEjXnw07IBZK03ykhLbdY';
const TG_CHAT_ID = '6601184733';
const ADMIN_PASSWORD = 'Admin_yosh123';

function tgNotify(msg) {
  const https = require('https');
  const body = JSON.stringify({ chat_id: TG_CHAT_ID, text: msg, parse_mode: 'HTML' });
  const req = https.request(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`,
    { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } });
  req.on('error', e => console.error('[TG ERROR]', e.message));
  req.write(body); req.end();
}

function requireAdmin(req, res, next) {
  const token = req.headers['x-auth-token'] || req.query.token;
  const sessions = loadSessions();
  const session = sessions[token];
  if (!session || !session.isAdmin) return res.status(401).json({ error: 'Admin only.' });
  next();
}

// ── Daily limit check ─────────────────────────────────────
function getDailyCount(ip, types) {
  const db = loadDB();
  const todayStart = new Date(); todayStart.setHours(0,0,0,0);
  return db.accounts.filter(a =>
    a.ip === ip &&
    types.includes(a.type) &&
    new Date(a.createdAt) >= todayStart
  ).length;
}

// ── Login ─────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required.' });
  const sessions = loadSessions();
  const token = crypto.randomBytes(32).toString('hex');
  if (password === ADMIN_PASSWORD) {
    sessions[token] = { createdAt: Date.now(), lastActive: Date.now(), isAdmin: true };
    saveSessions(sessions);
    return res.json({ success: true, token, isAdmin: true });
  }
  if (password !== PANEL_PASSWORD) return res.status(401).json({ error: 'Wrong password!' });
  sessions[token] = { createdAt: Date.now(), lastActive: Date.now(), isAdmin: false };
  saveSessions(sessions);
  return res.json({ success: true, token, isAdmin: false });
});

// ── Heartbeat ─────────────────────────────────────────────
app.post('/api/heartbeat', (req, res) => {
  const token = req.headers['x-auth-token'];
  const sessions = loadSessions();
  if (!token || !sessions[token]) return res.status(401).json({ error: 'Unauthorized' });
  sessions[token].lastActive = Date.now();
  saveSessions(sessions);
  res.json({ ok: true });
});

// ── Logout ────────────────────────────────────────────────
app.post('/api/logout', (req, res) => {
  const token = req.headers['x-auth-token'];
  const sessions = loadSessions();
  delete sessions[token];
  saveSessions(sessions);
  res.json({ success: true });
});


// ── Remote Servers Config ─────────────────────────────────
const SERVERS = {
  sg: { host: null, port: null, label: 'Singapore', flag: '🇸🇬', v2ray: true },
  jp: { host: '46.250.251.246', port: 5050, label: 'Japan', flag: '🇯🇵', v2ray: true },
  es: { host: '212.227.134.178', port: 5050, label: 'Spain', flag: '🇪🇸', v2ray: true }
};
const SSH_KEY = '/root/.ssh/id_rsa';

function runRemoteExpect(remoteHost, remotePort, script) {
  return new Promise((resolve, reject) => {
    const tmp = `/tmp/vipweb_${Date.now()}.exp`;
    // Wrap the script to run via SSH
    const sshScript = `set timeout 120
spawn ssh -i ${SSH_KEY} -p ${remotePort} -o StrictHostKeyChecking=no root@${remoteHost} menu
${script.replace(/^spawn menu$/m, '').trim()}`;
    fs.writeFileSync(tmp, sshScript);
    exec(`expect "${tmp}"`, { timeout: 120000 }, (err, stdout, stderr) => {
      try { fs.unlinkSync(tmp); } catch (_) {}
      const output = stdout + stderr;
      if (err && !output) return reject('Timeout: ' + (err.message || ''));
      resolve(output);
    });
  });
}

async function createSSHRemote(remoteHost, remotePort, username, password, days) {
  const script = `expect "Option:"
send "1\r"
expect "Option:"
send "1\r"
expect "Enter username:"
send "${username}\r"
expect "Enter password:"
send "${password}\r"
expect "Expiration"
send "${days}\r"
expect "Max Sessions"
send "5\r"
expect "Press Enter"
send "\r"
expect "Option:"
send "0\r"
expect "Option:"
send "0\r"
expect eof`;
  const out = await runRemoteExpect(remoteHost, remotePort, script);
  console.log('[SSH REMOTE DEBUG]', out.slice(-400));
  if (!out.toLowerCase().includes('created')) throw new Error('SSH creation failed on remote');
}

async function createVLESSRemote(remoteHost, remotePort, username, days, sni) {
  const script = `expect "Option:"
send "2\r"
expect "Option:"
send "1\r"
expect "Option:"
send "1\r"
expect "Enter username:"
send "${username}\r"
expect "Expiration (days):"
send "${days}\r"
expect "Enter SNI :"
send "${sni}\r"
expect "Press Enter to continue..."
send "\r"
expect "Option:"
send "0\r"
expect "Option:"
send "0\r"
expect "Option:"
send "0\r"
expect eof`;
  const out = await runRemoteExpect(remoteHost, remotePort, script);
  console.log('[VLESS REMOTE DEBUG]', out.slice(-600));
  const all = out.match(/vless:\/\/\S+/g) || [];
  if (all.length === 0) throw new Error('VLESS creation failed on remote');
  return { tls: all.find(l => l.includes('443'))?.trim() || null, nonTls: all.find(l => l.includes(':80'))?.trim() || null };
}

async function createVMessRemote(remoteHost, remotePort, username, days, sni) {
  const script = `expect "Option:"
send "2\r"
expect "Option:"
send "1\r"
expect "Option:"
send "2\r"
expect "Enter username:"
send "${username}\r"
expect "Expiration (days):"
send "${days}\r"
expect "Enter SNI :"
send "${sni}\r"
expect "Press Enter to continue..."
send "\r"
expect "Option:"
send "0\r"
expect "Option:"
send "0\r"
expect "Option:"
send "0\r"
expect eof`;
  const out = await runRemoteExpect(remoteHost, remotePort, script);
  console.log('[VMESS REMOTE DEBUG]', out.slice(-600));
  const all = out.match(/vmess:\/\/\S+/g) || [];
  if (all.length === 0) throw new Error('VMess creation failed on remote');
  return { tls: all.find(l => l.includes('443'))?.trim() || null, nonTls: all.find(l => l.includes(':80'))?.trim() || null };
}

async function createTrojanRemote(remoteHost, remotePort, password, days, sni) {
  const script = `expect "Option:"
send "2\r"
expect "Option:"
send "1\r"
expect "Option:"
send "3\r"
expect "Enter password:"
send "${password}\r"
expect "Expiration (days):"
send "${days}\r"
expect "Enter SNI :"
send "${sni}\r"
expect "Press Enter to continue..."
send "\r"
expect "Option:"
send "0\r"
expect "Option:"
send "0\r"
expect "Option:"
send "0\r"
expect eof`;
  const out = await runRemoteExpect(remoteHost, remotePort, script);
  console.log('[TROJAN REMOTE DEBUG]', out.slice(-600));
  const all = out.match(/trojan:\/\/\S+/g) || [];
  if (all.length === 0) throw new Error('Trojan creation failed on remote');
  return { tls: all.find(l => l.includes('443'))?.trim() || null, nonTls: all.find(l => l.includes(':80'))?.trim() || null };
}

const REMOTE_CONFIGS = {
  "jp": {
    "SERVER_HOST": "chard.yoshpan.com",
    "SERVER_NS": "ns.chard.yoshpan.com",
    "SERVER_PUBKEY": "e1f0e9a42618b7c54f673390cd729bbf4c98b90d83e8be196c40eab66b4b4a27"
  },
  "es": {
    "SERVER_HOST": "privateserver.yoshpan.com",
    "SERVER_NS": "ns.privateserver.yoshpan.com",
    "SERVER_PUBKEY": "9b16a744dadbc40b26e2b9ccabbe7c3903971681646e92f4621d4df71a5f3f6e"
  }
};

// ── DB helpers ────────────────────────────────────────────
function loadConfig() { return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); }

function loadDB() {
  if (!fs.existsSync(DB_FILE)) { const e = { accounts: [] }; fs.writeFileSync(DB_FILE, JSON.stringify(e, null, 2)); return e; }
  try { const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); if (!db.accounts) db.accounts = []; return db; }
  catch { return { accounts: [] }; }
}
function saveDB(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
function expiryISO(days) { const d = new Date(); d.setDate(d.getDate() + days); return d.toISOString(); }

function cleanExpired() {
  const db = loadDB(); const now = new Date(); const before = db.accounts.length;
  db.accounts = db.accounts.filter(a => new Date(a.expiry) > now);
  if (db.accounts.length < before) saveDB(db);
}
setInterval(cleanExpired, 60 * 60 * 1000);
cleanExpired();

function runExpect(script) {
  return new Promise((resolve, reject) => {
    const tmp = `/tmp/vipweb_${Date.now()}.exp`;
    fs.writeFileSync(tmp, script);
    exec(`expect "${tmp}"`, { timeout: 90000 }, (err, stdout, stderr) => {
      try { fs.unlinkSync(tmp); } catch (_) {}
      const output = stdout + stderr;
      if (err && !output) return reject('Timeout: ' + (err.message || ''));
      resolve(output);
    });
  });
}

// ── SSH (SG server - has Max Sessions prompt) ─────────────
async function createSSH(username, password, days) {
  const script = `set timeout 60
spawn menu
expect "Option:"
send "1\r"
expect "Option:"
send "1\r"
expect "Enter username:"
send "${username}\r"
expect "Enter password:"
send "${password}\r"
expect "Expiration"
send "${days}\r"
expect "Max Sessions"
send "${MAX_SESSIONS}\r"
expect "Press Enter"
send "\r"
expect "Option:"
send "0\r"
expect "Option:"
send "0\r"
expect eof`;
  const out = await runExpect(script);
  console.log('[SSH DEBUG]', out.slice(-400));
  if (!out.toLowerCase().includes('created')) throw new Error('SSH creation failed');
}

// ── VLESS (menu 2 → 1) ────────────────────────────────────
async function createVLESS(username, days) {
  const cfg = loadConfig();
  const sni = cfg.SERVER_HOST;
  const script = `set timeout 90
spawn menu
expect "Option:"
send "2\r"
expect "Option:"
send "1\r"
expect "Option:"
send "1\r"
expect "Enter username:"
send "${username}\r"
expect "Expiration (days):"
send "${days}\r"
expect "Enter SNI :"
send "${sni}\r"
expect "Press Enter to continue..."
send "\r"
expect "Option:"
send "0\r"
expect "Option:"
send "0\r"
expect "Option:"
send "0\r"
expect eof`;
  const out = await runExpect(script);
  console.log('[VLESS DEBUG]', out.slice(-600));
  const all = out.match(/vless:\/\/\S+/g) || [];
  if (all.length === 0) throw new Error('VLESS creation failed');
  return { tls: all.find(l => l.includes('443'))?.trim() || null, nonTls: all.find(l => l.includes(':80'))?.trim() || null };
}

// ── VMess (menu 2 → 1 → 2) ───────────────────────────────
async function createVMess(username, days) {
  const cfg = loadConfig();
  const sni = cfg.SERVER_HOST;
  const script = `set timeout 90
spawn menu
expect "Option:"
send "2\r"
expect "Option:"
send "1\r"
expect "Option:"
send "2\r"
expect "Enter username:"
send "${username}\r"
expect "Expiration (days):"
send "${days}\r"
expect "Enter SNI :"
send "${sni}\r"
expect "Press Enter to continue..."
send "\r"
expect "Option:"
send "0\r"
expect "Option:"
send "0\r"
expect "Option:"
send "0\r"
expect eof`;
  const out = await runExpect(script);
  console.log('[VMESS DEBUG]', out.slice(-600));
  const all = out.match(/vmess:\/\/\S+/g) || [];
  if (all.length === 0) throw new Error('VMess creation failed');
  return { tls: all.find(l => l.includes('443'))?.trim() || null, nonTls: all.find(l => l.includes(':80'))?.trim() || null };
}

// ── Trojan (menu 2 → 1 → 3) ──────────────────────────────
async function createTrojan(password, days) {
  const cfg = loadConfig();
  const sni = cfg.SERVER_HOST;
  const script = `set timeout 90
spawn menu
expect "Option:"
send "2\r"
expect "Option:"
send "1\r"
expect "Option:"
send "3\r"
expect "Enter password:"
send "${password}\r"
expect "Expiration (days):"
send "${days}\r"
expect "Enter SNI :"
send "${sni}\r"
expect "Press Enter to continue..."
send "\r"
expect "Option:"
send "0\r"
expect "Option:"
send "0\r"
expect "Option:"
send "0\r"
expect eof`;
  const out = await runExpect(script);
  console.log('[TROJAN DEBUG]', out.slice(-600));
  const all = out.match(/trojan:\/\/\S+/g) || [];
  if (all.length === 0) throw new Error('Trojan creation failed');
  return { tls: all.find(l => l.includes('443'))?.trim() || null, nonTls: all.find(l => l.includes(':80'))?.trim() || null };
}

// ═══════════════════════════════════════════════════════════
//  API ROUTES
// ═══════════════════════════════════════════════════════════

app.get('/api/stats', requireAuth, (req, res) => {
  const db = loadDB(); const now = new Date();
  const active = db.accounts.filter(a => new Date(a.expiry) > now);
  res.json({
    total: active.length,
    ssh:   active.filter(a => a.type === 'ssh').length,
    v2ray: active.filter(a => ['vless','vmess','trojan'].includes(a.type)).length
  });
});

app.get('/api/config', requireAuth, (req, res) => {
  const cfg = loadConfig();
  res.json({ SERVER_HOST: cfg.SERVER_HOST, SERVER_NS: cfg.SERVER_NS, SERVER_PUBKEY: cfg.SERVER_PUBKEY, EXPIRY_DAYS: cfg.EXPIRY_DAYS || 5 });
});

// POST /api/create/ssh
app.post('/api/create/ssh', requireAuth, async (req, res) => {
  const ip = getIP(req);
  const used = getDailyCount(ip, ['ssh']);
  if (used >= DAILY_LIMIT_SSH) return res.status(429).json({ error: `❌ Daily limit reached! You can only create ${DAILY_LIMIT_SSH} SSH accounts per day. Try again tomorrow.` });
  const { username, password, days } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password are required.' });
  if (!/^[a-zA-Z0-9_]{3,16}$/.test(username)) return res.status(400).json({ error: 'Username must be 3–16 characters.' });
  if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  const cfg = loadConfig();
  const expDays = Math.min(Math.max(parseInt(days) || cfg.EXPIRY_DAYS || 5, 1), 90);
  try {
    await createSSH(username, password, expDays);
    const expiry = expiryISO(expDays);
    const db = loadDB();
    db.accounts.push({ id: Date.now().toString(), username, password, type: 'ssh', expiry, ip: getIP(req), createdAt: new Date().toISOString() });
    saveDB(db);
    const sshExp = new Date(expiry).toLocaleString('en-PH',{timeZone:'Asia/Manila'});
    tgNotify(`🖥️ <b>SSH CREATED</b>\n👤 User: <code>${username}</code>\n🔐 Pass: <code>${password}</code>\n⏳ Expires: ${sshExp}\n🌐 Host: ${cfg.SERVER_HOST}\n📍 IP: ${ip}`);
    res.json({ success: true, type: 'ssh', username, password, host: cfg.SERVER_HOST, ns: cfg.SERVER_NS, pubkey: cfg.SERVER_PUBKEY, expiry, days: expDays });
  } catch (e) {
    console.error('[SSH ERROR]', e);
    res.status(500).json({ error: 'Failed to create SSH account. Please try again.' });
  }
});

// POST /api/create/vless
app.post('/api/create/vless', requireAuth, async (req, res) => {
  const ip = getIP(req);
  const used = getDailyCount(ip, ['vless','vmess','trojan']);
  if (used >= DAILY_LIMIT_V2RAY) return res.status(429).json({ error: `❌ Daily limit reached! You can only create ${DAILY_LIMIT_V2RAY} V2Ray accounts per day. Try again tomorrow.` });
  const { username, password, days } = req.body;
  if (!username) return res.status(400).json({ error: 'Username is required.' });
  if (!/^[a-zA-Z0-9_]{3,16}$/.test(username)) return res.status(400).json({ error: 'Username must be 3–16 characters.' });
  if (!password || password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  const cfg = loadConfig();
  const expDays = Math.min(Math.max(parseInt(days) || cfg.EXPIRY_DAYS || 5, 1), 90);
  try {
    const { tls, nonTls } = await createVLESS(username, expDays);
    const expiry = expiryISO(expDays);
    const db = loadDB();
    db.accounts.push({ id: Date.now().toString(), username, password, type: 'vless', expiry, ip: getIP(req), createdAt: new Date().toISOString(), tls, nonTls });
    saveDB(db);
    const vlessExp = new Date(expiry).toLocaleString('en-PH',{timeZone:'Asia/Manila'});
    tgNotify(`📡 <b>VLESS CREATED</b>\n📧 User: <code>${username}</code>\n⏳ Expires: ${vlessExp}\n🌐 Host: ${cfg.SERVER_HOST}\n📍 IP: ${ip}`);
    res.json({ success: true, type: 'vless', username, password, host: cfg.SERVER_HOST, expiry, days: expDays, tls, nonTls });
  } catch (e) {
    console.error('[VLESS ERROR]', e);
    res.status(500).json({ error: 'Failed to create VLESS account. Please try again.' });
  }
});

// POST /api/create/vmess
app.post('/api/create/vmess', requireAuth, async (req, res) => {
  const ip = getIP(req);
  const used = getDailyCount(ip, ['vless','vmess','trojan']);
  if (used >= DAILY_LIMIT_V2RAY) return res.status(429).json({ error: `❌ Daily limit reached! You can only create ${DAILY_LIMIT_V2RAY} V2Ray accounts per day. Try again tomorrow.` });
  const { username, password, days } = req.body;
  if (!username) return res.status(400).json({ error: 'Username is required.' });
  if (!/^[a-zA-Z0-9_]{3,16}$/.test(username)) return res.status(400).json({ error: 'Username must be 3–16 characters.' });
  if (!password || password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  const cfg = loadConfig();
  const expDays = Math.min(Math.max(parseInt(days) || cfg.EXPIRY_DAYS || 5, 1), 90);
  try {
    const { tls, nonTls } = await createVMess(username, expDays);
    const expiry = expiryISO(expDays);
    const db = loadDB();
    db.accounts.push({ id: Date.now().toString(), username, password, type: 'vmess', expiry, ip: getIP(req), createdAt: new Date().toISOString(), tls, nonTls });
    saveDB(db);
    const vmessExp = new Date(expiry).toLocaleString('en-PH',{timeZone:'Asia/Manila'});
    tgNotify(`📡 <b>VMESS CREATED</b>\n📧 User: <code>${username}</code>\n⏳ Expires: ${vmessExp}\n🌐 Host: ${cfg.SERVER_HOST}\n📍 IP: ${ip}`);
    res.json({ success: true, type: 'vmess', username, password, host: cfg.SERVER_HOST, expiry, days: expDays, tls, nonTls });
  } catch (e) {
    console.error('[VMESS ERROR]', e);
    res.status(500).json({ error: 'Failed to create VMess account. Please try again.' });
  }
});

// POST /api/create/trojan
app.post('/api/create/trojan', requireAuth, async (req, res) => {
  const ip = getIP(req);
  const used = getDailyCount(ip, ['vless','vmess','trojan']);
  if (used >= DAILY_LIMIT_V2RAY) return res.status(429).json({ error: `❌ Daily limit reached! You can only create ${DAILY_LIMIT_V2RAY} V2Ray accounts per day. Try again tomorrow.` });
  const { password, days } = req.body;
  if (!password) return res.status(400).json({ error: 'Password is required.' });
  if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  const cfg = loadConfig();
  const expDays = Math.min(Math.max(parseInt(days) || cfg.EXPIRY_DAYS || 5, 1), 90);
  try {
    const { tls, nonTls } = await createTrojan(password, expDays);
    const expiry = expiryISO(expDays);
    const db = loadDB();
    db.accounts.push({ id: Date.now().toString(), username: password, type: 'trojan', expiry, ip: getIP(req), createdAt: new Date().toISOString(), tls, nonTls });
    saveDB(db);
    const trojanExp = new Date(expiry).toLocaleString('en-PH',{timeZone:'Asia/Manila'});
    tgNotify(`📡 <b>TROJAN CREATED</b>\n🔐 Pass: <code>${password}</code>\n⏳ Expires: ${trojanExp}\n🌐 Host: ${cfg.SERVER_HOST}\n📍 IP: ${ip}`);
    res.json({ success: true, type: 'trojan', password, host: cfg.SERVER_HOST, expiry, days: expDays, tls, nonTls });
  } catch (e) {
    console.error('[TROJAN ERROR]', e);
    res.status(500).json({ error: 'Failed to create Trojan account. Please try again.' });
  }
});

// GET /api/limit
app.get('/api/limit', requireAuth, (req, res) => {
  const ip = getIP(req);
  const sshUsed = getDailyCount(ip, ['ssh']);
  const v2rayUsed = getDailyCount(ip, ['vless','vmess','trojan']);
  res.json({
    ssh:   { used: sshUsed,   remaining: Math.max(0, DAILY_LIMIT_SSH - sshUsed),     limit: DAILY_LIMIT_SSH },
    v2ray: { used: v2rayUsed, remaining: Math.max(0, DAILY_LIMIT_V2RAY - v2rayUsed), limit: DAILY_LIMIT_V2RAY }
  });
});



// ── Remote server routes (JP, ES) ────────────────────────
// Helper to get remote config
function getRemoteConfig(srv) {
  return REMOTE_CONFIGS[srv] || null;
}

// POST /api/create/:srv/ssh  (srv = jp | es)
app.post('/api/create/:srv/ssh', requireAuth, async (req, res) => {
  const { srv } = req.params;
  const srvInfo = SERVERS[srv];
  if (!srvInfo || !srvInfo.host) return res.status(400).json({ error: 'Invalid server.' });
  const ip = getIP(req);
  const used = getDailyCount(ip, ['ssh_'+srv, 'ssh']);
  if (used >= DAILY_LIMIT_SSH) return res.status(429).json({ error: `❌ Daily limit reached! Max ${DAILY_LIMIT_SSH} SSH per day.` });
  const { username, password, days } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });
  if (!/^[a-zA-Z0-9_]{3,16}$/.test(username)) return res.status(400).json({ error: 'Username must be 3-16 chars.' });
  if (password.length < 4) return res.status(400).json({ error: 'Password min 4 chars.' });
  const cfg = getRemoteConfig(srv);
  const expDays = parseInt(days) || 3;
  try {
    await createSSHRemote(srvInfo.host, srvInfo.port, username, password, expDays);
    const expiry = expiryISO(expDays);
    const db = loadDB();
    db.accounts.push({ id: Date.now().toString(), username, password, type: 'ssh', server: srv, expiry, ip, createdAt: new Date().toISOString() });
    saveDB(db);
    const exp = new Date(expiry).toLocaleString('en-PH',{timeZone:'Asia/Manila'});
    tgNotify(`🖥️ <b>SSH CREATED [${srvInfo.flag} ${srvInfo.label}]</b>\n👤 User: <code>${username}</code>\n🔐 Pass: <code>${password}</code>\n⏳ Expires: ${exp}\n🌐 Host: ${cfg.SERVER_HOST}\n📍 IP: ${ip}`);
    res.json({ success: true, type: 'ssh', server: srv, username, password, host: cfg.SERVER_HOST, ns: cfg.SERVER_NS, pubkey: cfg.SERVER_PUBKEY, expiry, days: expDays });
  } catch(e) {
    console.error(`[SSH ${srv.toUpperCase()} ERROR]`, e);
    res.status(500).json({ error: 'Failed to create SSH account. Try again.' });
  }
});

// POST /api/create/:srv/vless
app.post('/api/create/:srv/vless', requireAuth, async (req, res) => {
  const { srv } = req.params;
  const srvInfo = SERVERS[srv];
  if (!srvInfo || !srvInfo.host) return res.status(400).json({ error: 'Invalid server.' });
  const ip = getIP(req);
  const used = getDailyCount(ip, ['vless','vmess','trojan']);
  if (used >= DAILY_LIMIT_V2RAY) return res.status(429).json({ error: `❌ Daily limit reached! Max ${DAILY_LIMIT_V2RAY} V2Ray per day.` });
  const { username, password, days } = req.body;
  if (!username) return res.status(400).json({ error: 'Username required.' });
  if (!/^[a-zA-Z0-9_]{3,16}$/.test(username)) return res.status(400).json({ error: 'Username must be 3-16 chars.' });
  const cfg = getRemoteConfig(srv);
  const expDays = parseInt(days) || 3;
  try {
    const { tls, nonTls } = await createVLESSRemote(srvInfo.host, srvInfo.port, username, expDays, cfg.SERVER_HOST);
    const expiry = expiryISO(expDays);
    const db = loadDB();
    db.accounts.push({ id: Date.now().toString(), username, type: 'vless', server: srv, expiry, ip, createdAt: new Date().toISOString(), tls, nonTls });
    saveDB(db);
    const exp = new Date(expiry).toLocaleString('en-PH',{timeZone:'Asia/Manila'});
    tgNotify(`📡 <b>VLESS CREATED [${srvInfo.flag} ${srvInfo.label}]</b>\n📧 User: <code>${username}</code>\n⏳ Expires: ${exp}\n🌐 Host: ${cfg.SERVER_HOST}\n📍 IP: ${ip}`);
    res.json({ success: true, type: 'vless', server: srv, username, host: cfg.SERVER_HOST, expiry, days: expDays, tls, nonTls });
  } catch(e) {
    console.error(`[VLESS ${srv.toUpperCase()} ERROR]`, e);
    res.status(500).json({ error: 'Failed to create VLESS account. Try again.' });
  }
});

// POST /api/create/:srv/vmess  (ES only)
app.post('/api/create/:srv/vmess', requireAuth, async (req, res) => {
  const { srv } = req.params;
  const srvInfo = SERVERS[srv];
  if (!srvInfo || !srvInfo.host) return res.status(400).json({ error: 'Invalid server.' });
  const ip = getIP(req);
  const used = getDailyCount(ip, ['vless','vmess','trojan']);
  if (used >= DAILY_LIMIT_V2RAY) return res.status(429).json({ error: `❌ Daily limit reached! Max ${DAILY_LIMIT_V2RAY} V2Ray per day.` });
  const { username, days } = req.body;
  if (!username) return res.status(400).json({ error: 'Username required.' });
  if (!/^[a-zA-Z0-9_]{3,16}$/.test(username)) return res.status(400).json({ error: 'Username must be 3-16 chars.' });
  const cfg = getRemoteConfig(srv);
  const expDays = parseInt(days) || 3;
  try {
    const { tls, nonTls } = await createVMessRemote(srvInfo.host, srvInfo.port, username, expDays, cfg.SERVER_HOST);
    const expiry = expiryISO(expDays);
    const db = loadDB();
    db.accounts.push({ id: Date.now().toString(), username, type: 'vmess', server: srv, expiry, ip, createdAt: new Date().toISOString(), tls, nonTls });
    saveDB(db);
    const exp = new Date(expiry).toLocaleString('en-PH',{timeZone:'Asia/Manila'});
    tgNotify(`📡 <b>VMESS CREATED [${srvInfo.flag} ${srvInfo.label}]</b>\n📧 User: <code>${username}</code>\n⏳ Expires: ${exp}\n🌐 Host: ${cfg.SERVER_HOST}\n📍 IP: ${ip}`);
    res.json({ success: true, type: 'vmess', server: srv, username, host: cfg.SERVER_HOST, expiry, days: expDays, tls, nonTls });
  } catch(e) {
    console.error(`[VMESS ${srv.toUpperCase()} ERROR]`, e);
    res.status(500).json({ error: 'Failed to create VMess account. Try again.' });
  }
});

// POST /api/create/:srv/trojan  (ES only)
app.post('/api/create/:srv/trojan', requireAuth, async (req, res) => {
  const { srv } = req.params;
  const srvInfo = SERVERS[srv];
  if (!srvInfo || !srvInfo.host) return res.status(400).json({ error: 'Invalid server.' });
  const ip = getIP(req);
  const used = getDailyCount(ip, ['vless','vmess','trojan']);
  if (used >= DAILY_LIMIT_V2RAY) return res.status(429).json({ error: `❌ Daily limit reached! Max ${DAILY_LIMIT_V2RAY} V2Ray per day.` });
  const { password, days } = req.body;
  if (!password || password.length < 4) return res.status(400).json({ error: 'Password min 4 chars.' });
  const cfg = getRemoteConfig(srv);
  const expDays = parseInt(days) || 3;
  try {
    const { tls, nonTls } = await createTrojanRemote(srvInfo.host, srvInfo.port, password, expDays, cfg.SERVER_HOST);
    const expiry = expiryISO(expDays);
    const db = loadDB();
    db.accounts.push({ id: Date.now().toString(), username: password, type: 'trojan', server: srv, expiry, ip, createdAt: new Date().toISOString(), tls, nonTls });
    saveDB(db);
    const exp = new Date(expiry).toLocaleString('en-PH',{timeZone:'Asia/Manila'});
    tgNotify(`📡 <b>TROJAN CREATED [${srvInfo.flag} ${srvInfo.label}]</b>\n🔐 Pass: <code>${password}</code>\n⏳ Expires: ${exp}\n🌐 Host: ${cfg.SERVER_HOST}\n📍 IP: ${ip}`);
    res.json({ success: true, type: 'trojan', server: srv, password, host: cfg.SERVER_HOST, expiry, days: expDays, tls, nonTls });
  } catch(e) {
    console.error(`[TROJAN ${srv.toUpperCase()} ERROR]`, e);
    res.status(500).json({ error: 'Failed to create Trojan account. Try again.' });
  }
});



// GET /api/ping - SG self
app.get('/api/ping', (req, res) => res.json({ ok: true }));

// GET /api/ping/:srv - proxy ping to remote servers
app.get('/api/ping/:srv', async (req, res) => {
  const { srv } = req.params;
  if (srv === 'sg') return res.json({ ok: true });
  const srvInfo = SERVERS[srv];
  if (!srvInfo || !srvInfo.host) return res.status(400).json({ error: 'Invalid server' });
  const { exec } = require('child_process');
  exec(`ssh -i ${SSH_KEY} -p ${srvInfo.port} -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@${srvInfo.host} "echo ok"`,
    { timeout: 7000 }, (err, stdout) => {
      if (err || !stdout.includes('ok')) return res.status(503).json({ ok: false });
      res.json({ ok: true });
    }
  );
});

// GET /api/servers - return server info + stats per server
app.get('/api/servers', requireAuth, (req, res) => {
  const db = loadDB(); const now = new Date();
  const active = db.accounts.filter(a => new Date(a.expiry) > now);
  res.json({
    sg: { label: 'Singapore', flag: '🇸🇬', host: 'wangx.yoshpan.com', protocols: ['ssh','vless','vmess','trojan'], accounts: active.filter(a => !a.server || a.server === 'sg').length },
    jp: { label: 'Japan', flag: '🇯🇵', host: 'chard.yoshpan.com', protocols: ['ssh','vless'], accounts: active.filter(a => a.server === 'jp').length },
    es: { label: 'Spain', flag: '🇪🇸', host: 'privateserver.yoshpan.com', protocols: ['ssh','vless','vmess','trojan'], accounts: active.filter(a => a.server === 'es').length }
  });
});

// GET /api/accounts - admin only
app.get('/api/accounts', requireAdmin, (req, res) => {
  const db = loadDB();
  const now = new Date();
  const active = db.accounts
    .filter(a => new Date(a.expiry) > now)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ accounts: active });
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'index.html')); });

const PORT = process.env.PORT || 4573;
app.listen(PORT, () => console.log(`🚀 Yosh VIP Panel running on http://localhost:${PORT}`));
