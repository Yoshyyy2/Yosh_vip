const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const CONFIG_FILE = path.join(__dirname, 'config.json');
const DB_FILE = path.join(__dirname, 'accounts.json');
const PASSWORDS_FILE = path.join(__dirname, 'passwords.json');

// ── Config ────────────────────────────────────────────────
const ADMIN_PASSWORD = 'Yoshydark123';
const MAX_SESSIONS = 15; // SSH max sessions always 15
const SESSION_TTL = 24 * 60 * 60 * 1000; // 24 hours session life

// sessions stored in file so they survive pm2 restart!
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');

function loadSessions() {
  if (!fs.existsSync(SESSIONS_FILE)) return {};
  try { return JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8')); }
  catch { return {}; }
}

function saveSessions(s) {
  fs.writeFileSync(SESSIONS_FILE, JSON.stringify(s, null, 2));
}

// Clean expired sessions on startup
function cleanSessions() {
  const s = loadSessions();
  const now = Date.now();
  let changed = false;
  for (const [token, data] of Object.entries(s)) {
    if (now - data.createdAt > SESSION_TTL) {
      delete s[token];
      changed = true;
    }
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
  // Refresh session TTL on activity
  sessions[token].lastActive = Date.now();
  saveSessions(sessions);
  next();
}

function requireAdmin(req, res, next) {
  const token = req.headers['x-auth-token'] || req.query.token;
  const sessions = loadSessions();
  const session = sessions[token];
  if (!session || !session.isAdmin) return res.status(401).json({ error: 'Admin only.' });
  next();
}

// ── Passwords ─────────────────────────────────────────────
function loadPasswords() {
  if (!fs.existsSync(PASSWORDS_FILE)) { fs.writeFileSync(PASSWORDS_FILE, JSON.stringify({}, null, 2)); return {}; }
  try { return JSON.parse(fs.readFileSync(PASSWORDS_FILE, 'utf8')); }
  catch { return {}; }
}
function savePasswords(pw) { fs.writeFileSync(PASSWORDS_FILE, JSON.stringify(pw, null, 2)); }

// ── Login ─────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required.' });

  const sessions = loadSessions();

  // Admin
  if (password === ADMIN_PASSWORD) {
    const token = crypto.randomBytes(32).toString('hex');
    sessions[token] = { password, isAdmin: true, createdAt: Date.now(), lastActive: Date.now() };
    saveSessions(sessions);
    return res.json({ success: true, token, isAdmin: true });
  }

  // User password
  const passwords = loadPasswords();
  const entry = passwords[password];
  if (!entry) return res.status(401).json({ error: 'Wrong password!' });
  if (entry.inUse) return res.status(401).json({ error: 'Password already in use!' });

  passwords[password].inUse = true;
  passwords[password].usedAt = new Date().toISOString();
  savePasswords(passwords);

  const token = crypto.randomBytes(32).toString('hex');
  sessions[token] = { password, isAdmin: false, createdAt: Date.now(), lastActive: Date.now() };
  saveSessions(sessions);
  return res.json({ success: true, token, isAdmin: false });
});

// ── Heartbeat (keep session alive) ────────────────────────
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
  const session = sessions[token];
  if (session) {
    // If it's a regular user, free their password so they can log in again
    if (!session.isAdmin && session.password) {
      const passwords = loadPasswords();
      if (passwords[session.password]) {
        passwords[session.password].inUse = false;
        passwords[session.password].usedAt = null;
        savePasswords(passwords);
      }
    }
    delete sessions[token];
    saveSessions(sessions);
  }
  res.json({ success: true });
});

// ── Admin: manage passwords ───────────────────────────────
app.post('/api/admin/generate', requireAdmin, (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  const passwords = loadPasswords();
  if (passwords[password]) return res.status(400).json({ error: 'Password already exists!' });
  passwords[password] = { inUse: false, createdAt: new Date().toISOString() };
  savePasswords(passwords);
  res.json({ success: true, password });
});

app.get('/api/admin/passwords', requireAdmin, (req, res) => {
  const passwords = loadPasswords();
  const list = Object.entries(passwords).map(([pw, info]) => ({
    password: pw, inUse: info.inUse, createdAt: info.createdAt, usedAt: info.usedAt || null
  }));
  res.json({ passwords: list });
});

app.delete('/api/admin/passwords/:pw', requireAdmin, (req, res) => {
  const passwords = loadPasswords();
  const pw = decodeURIComponent(req.params.pw);
  if (!passwords[pw]) return res.status(404).json({ error: 'Password not found.' });
  delete passwords[pw];
  savePasswords(passwords);
  res.json({ success: true });
});

app.post('/api/admin/passwords/:pw/reset', requireAdmin, (req, res) => {
  const passwords = loadPasswords();
  const pw = decodeURIComponent(req.params.pw);
  if (!passwords[pw]) return res.status(404).json({ error: 'Password not found.' });
  passwords[pw].inUse = false;
  passwords[pw].usedAt = null;
  savePasswords(passwords);
  res.json({ success: true });
});

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
    res.json({ success: true, type: 'ssh', username, password, host: cfg.SERVER_HOST, ns: cfg.SERVER_NS, pubkey: cfg.SERVER_PUBKEY, expiry, days: expDays });
  } catch (e) {
    console.error('[SSH ERROR]', e);
    res.status(500).json({ error: 'Failed to create SSH account. Please try again.' });
  }
});

// POST /api/create/vless
app.post('/api/create/vless', requireAuth, async (req, res) => {
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
    res.json({ success: true, type: 'vless', username, password, host: cfg.SERVER_HOST, expiry, days: expDays, tls, nonTls });
  } catch (e) {
    console.error('[VLESS ERROR]', e);
    res.status(500).json({ error: 'Failed to create VLESS account. Please try again.' });
  }
});

// POST /api/create/vmess
app.post('/api/create/vmess', requireAuth, async (req, res) => {
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
    res.json({ success: true, type: 'vmess', username, password, host: cfg.SERVER_HOST, expiry, days: expDays, tls, nonTls });
  } catch (e) {
    console.error('[VMESS ERROR]', e);
    res.status(500).json({ error: 'Failed to create VMess account. Please try again.' });
  }
});

// POST /api/create/trojan
app.post('/api/create/trojan', requireAuth, async (req, res) => {
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
    res.json({ success: true, type: 'trojan', password, host: cfg.SERVER_HOST, expiry, days: expDays, tls, nonTls });
  } catch (e) {
    console.error('[TROJAN ERROR]', e);
    res.status(500).json({ error: 'Failed to create Trojan account. Please try again.' });
  }
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'index.html')); });

const PORT = process.env.PORT || 3855;
app.listen(PORT, () => console.log(`🚀 Yosh VIP Panel running on http://localhost:${PORT}`));
