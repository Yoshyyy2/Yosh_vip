const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const CONFIG_FILE  = path.join(__dirname, 'config.json');
const DB_FILE      = path.join(__dirname, 'accounts.json');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');
const PASSWORDS_FILE = path.join(__dirname, 'passwords.json');  // one-time passwords

// ── Constants ─────────────────────────────────────────────
const MAX_SESSIONS    = 5;
const DAILY_LIMIT_SSH   = 2;
const DAILY_LIMIT_V2RAY = 2;
// NOTE: Sessions are now PERSISTENT (no TTL). They only end on explicit logout.

const ADMIN_PASSWORD = 'Yoshpogi_123';


// ── Session helpers (PERSISTENT — no expiry) ──────────────
function loadSessions() {
  if (!fs.existsSync(SESSIONS_FILE)) return {};
  try { return JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8')); }
  catch { return {}; }
}
function saveSessions(s) { fs.writeFileSync(SESSIONS_FILE, JSON.stringify(s, null, 2)); }

// ── Password helpers ──────────────────────────────────────
// passwords.json format: { "list": [ { "id": "...", "value": "...", "label": "...", "createdAt": "..." } ] }
function loadPasswords() {
  if (!fs.existsSync(PASSWORDS_FILE)) { const d = { list: [] }; fs.writeFileSync(PASSWORDS_FILE, JSON.stringify(d, null, 2)); return d; }
  try { const d = JSON.parse(fs.readFileSync(PASSWORDS_FILE, 'utf8')); if (!d.list) d.list = []; return d; }
  catch { return { list: [] }; }
}
function savePasswords(d) { fs.writeFileSync(PASSWORDS_FILE, JSON.stringify(d, null, 2)); }

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

function requireAdmin(req, res, next) {
  const token = req.headers['x-auth-token'] || req.query.token;
  const sessions = loadSessions();
  const session = sessions[token];
  if (!session || !session.isAdmin) return res.status(401).json({ error: 'Admin only.' });
  next();
}

// ── DB helpers ────────────────────────────────────────────
function loadConfig() { return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); }

function loadDB() {
  if (!fs.existsSync(DB_FILE)) { const e = { accounts: [] }; fs.writeFileSync(DB_FILE, JSON.stringify(e, null, 2)); return e; }
  try { const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); if (!db.accounts) db.accounts = []; return db; }
  catch { return { accounts: [] }; }
}
function saveDB(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
function expiryISO(days) { const d = new Date(); d.setDate(d.getDate() + days); return d.toISOString(); }

function getDailyCount(ip, types) {
  const db = loadDB();
  const todayStart = new Date(); todayStart.setHours(0,0,0,0);
  return db.accounts.filter(a =>
    a.ip === ip && types.includes(a.type) && new Date(a.createdAt) >= todayStart
  ).length;
}

function cleanExpired() {
  const db = loadDB(); const now = new Date(); const before = db.accounts.length;
  db.accounts = db.accounts.filter(a => new Date(a.expiry) > now);
  if (db.accounts.length < before) saveDB(db);
}
setInterval(cleanExpired, 60 * 60 * 1000);
cleanExpired();

// ── Login — supports admin password OR one-time passwords ──
app.post('/api/login', (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required.' });

  const sessions = loadSessions();
  const token = crypto.randomBytes(32).toString('hex');

  // Admin password
  if (password === ADMIN_PASSWORD) {
    sessions[token] = { createdAt: Date.now(), lastActive: Date.now(), isAdmin: true };
    saveSessions(sessions);
    return res.json({ success: true, token, isAdmin: true });
  }

  // Check one-time passwords
  const pwdData = loadPasswords();
  const idx = pwdData.list.findIndex(p => p.value === password);
  if (idx !== -1) {
    // Valid one-time password — consume it (delete from list)
    const consumed = pwdData.list.splice(idx, 1)[0];
    savePasswords(pwdData);
    sessions[token] = { createdAt: Date.now(), lastActive: Date.now(), isAdmin: false, usedPassword: consumed.value };
    saveSessions(sessions);

    return res.json({ success: true, token, isAdmin: false });
  }

  return res.status(401).json({ error: 'Wrong password!' });
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

// ── Logout — ONLY explicit logout removes the session ─────
app.post('/api/logout', (req, res) => {
  const token = req.headers['x-auth-token'];
  const sessions = loadSessions();
  delete sessions[token];
  saveSessions(sessions);
  res.json({ success: true });
});

// ── Password Management (admin only) ─────────────────────

// GET /api/passwords — list all passwords
app.get('/api/passwords', requireAdmin, (req, res) => {
  const d = loadPasswords();
  res.json({ passwords: d.list });
});

// POST /api/passwords — add one or more passwords
app.post('/api/passwords', requireAdmin, (req, res) => {
  const { value, label, count } = req.body;
  const d = loadPasswords();

  if (value) {
    // Add single specific password
    if (d.list.find(p => p.value === value)) return res.status(409).json({ error: 'Password already exists.' });
    const entry = { id: crypto.randomBytes(8).toString('hex'), value, label: label || '', createdAt: new Date().toISOString() };
    d.list.push(entry);
    savePasswords(d);
    return res.json({ success: true, added: [entry] });
  }

  // Bulk generate random passwords
  const n = Math.min(parseInt(count) || 1, 50);
  const added = [];
  for (let i = 0; i < n; i++) {
    const pw = crypto.randomBytes(6).toString('hex'); // 12 char hex password
    const entry = { id: crypto.randomBytes(8).toString('hex'), value: pw, label: label || '', createdAt: new Date().toISOString() };
    d.list.push(entry);
    added.push(entry);
  }
  savePasswords(d);
  res.json({ success: true, added });
});

// DELETE /api/passwords/:id — remove a specific password
app.delete('/api/passwords/:id', requireAdmin, (req, res) => {
  const d = loadPasswords();
  const before = d.list.length;
  d.list = d.list.filter(p => p.id !== req.params.id);
  if (d.list.length === before) return res.status(404).json({ error: 'Password not found.' });
  savePasswords(d);
  res.json({ success: true });
});

// DELETE /api/passwords — clear all passwords
app.delete('/api/passwords', requireAdmin, (req, res) => {
  savePasswords({ list: [] });
  res.json({ success: true });
});

// ── Expect script runner ──────────────────────────────────
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

// ── SSH ───────────────────────────────────────────────────
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

// ── VLESS ─────────────────────────────────────────────────
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

// ── VMess ─────────────────────────────────────────────────
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

// ── Trojan ────────────────────────────────────────────────
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
  if (used >= DAILY_LIMIT_SSH) return res.status(429).json({ error: `❌ Daily limit reached! You can only create ${DAILY_LIMIT_SSH} SSH accounts per day.` });
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
    db.accounts.push({ id: Date.now().toString(), username, password, type: 'ssh', expiry, ip, createdAt: new Date().toISOString() });
    saveDB(db);
    const sshExp = new Date(expiry).toLocaleString('en-PH',{timeZone:'Asia/Manila'});

    res.json({ success: true, type: 'ssh', username, password, host: cfg.SERVER_HOST, ns: cfg.SERVER_NS, pubkey: cfg.SERVER_PUBKEY, expiry, days: expDays });
  } catch (e) {
    console.error('[SSH ERROR]', e);
    res.status(500).json({ error: 'Failed to create SSH account. Please try again.' });
  }
});

// POST /api/create/vless — no password needed
app.post('/api/create/vless', requireAuth, async (req, res) => {
  const ip = getIP(req);
  const used = getDailyCount(ip, ['vless','vmess','trojan']);
  if (used >= DAILY_LIMIT_V2RAY) return res.status(429).json({ error: `❌ Daily limit reached! You can only create ${DAILY_LIMIT_V2RAY} V2Ray accounts per day.` });
  const { username, days } = req.body;
  if (!username) return res.status(400).json({ error: 'Username is required.' });
  if (!/^[a-zA-Z0-9_]{3,16}$/.test(username)) return res.status(400).json({ error: 'Username must be 3–16 characters.' });
  const cfg = loadConfig();
  const expDays = Math.min(Math.max(parseInt(days) || cfg.EXPIRY_DAYS || 5, 1), 90);
  try {
    const { tls, nonTls } = await createVLESS(username, expDays);
    const expiry = expiryISO(expDays);
    const db = loadDB();
    db.accounts.push({ id: Date.now().toString(), username, type: 'vless', expiry, ip, createdAt: new Date().toISOString(), tls, nonTls });
    saveDB(db);
    const exp = new Date(expiry).toLocaleString('en-PH',{timeZone:'Asia/Manila'});

    res.json({ success: true, type: 'vless', username, host: cfg.SERVER_HOST, expiry, days: expDays, tls, nonTls });
  } catch (e) {
    console.error('[VLESS ERROR]', e);
    res.status(500).json({ error: 'Failed to create VLESS account. Please try again.' });
  }
});

// POST /api/create/vmess — no password needed
app.post('/api/create/vmess', requireAuth, async (req, res) => {
  const ip = getIP(req);
  const used = getDailyCount(ip, ['vless','vmess','trojan']);
  if (used >= DAILY_LIMIT_V2RAY) return res.status(429).json({ error: `❌ Daily limit reached! You can only create ${DAILY_LIMIT_V2RAY} V2Ray accounts per day.` });
  const { username, days } = req.body;
  if (!username) return res.status(400).json({ error: 'Username is required.' });
  if (!/^[a-zA-Z0-9_]{3,16}$/.test(username)) return res.status(400).json({ error: 'Username must be 3–16 characters.' });
  const cfg = loadConfig();
  const expDays = Math.min(Math.max(parseInt(days) || cfg.EXPIRY_DAYS || 5, 1), 90);
  try {
    const { tls, nonTls } = await createVMess(username, expDays);
    const expiry = expiryISO(expDays);
    const db = loadDB();
    db.accounts.push({ id: Date.now().toString(), username, type: 'vmess', expiry, ip, createdAt: new Date().toISOString(), tls, nonTls });
    saveDB(db);
    const exp = new Date(expiry).toLocaleString('en-PH',{timeZone:'Asia/Manila'});

    res.json({ success: true, type: 'vmess', username, host: cfg.SERVER_HOST, expiry, days: expDays, tls, nonTls });
  } catch (e) {
    console.error('[VMESS ERROR]', e);
    res.status(500).json({ error: 'Failed to create VMess account. Please try again.' });
  }
});

// POST /api/create/trojan
app.post('/api/create/trojan', requireAuth, async (req, res) => {
  const ip = getIP(req);
  const used = getDailyCount(ip, ['vless','vmess','trojan']);
  if (used >= DAILY_LIMIT_V2RAY) return res.status(429).json({ error: `❌ Daily limit reached! You can only create ${DAILY_LIMIT_V2RAY} V2Ray accounts per day.` });
  const { password, days } = req.body;
  if (!password) return res.status(400).json({ error: 'Password is required.' });
  if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  const cfg = loadConfig();
  const expDays = Math.min(Math.max(parseInt(days) || cfg.EXPIRY_DAYS || 5, 1), 90);
  try {
    const { tls, nonTls } = await createTrojan(password, expDays);
    const expiry = expiryISO(expDays);
    const db = loadDB();
    db.accounts.push({ id: Date.now().toString(), username: password, type: 'trojan', expiry, ip, createdAt: new Date().toISOString(), tls, nonTls });
    saveDB(db);
    const exp = new Date(expiry).toLocaleString('en-PH',{timeZone:'Asia/Manila'});

    res.json({ success: true, type: 'trojan', password, host: cfg.SERVER_HOST, expiry, days: expDays, tls, nonTls });
  } catch (e) {
    console.error('[TROJAN ERROR]', e);
    res.status(500).json({ error: 'Failed to create Trojan account. Please try again.' });
  }
});

app.get('/api/limit', requireAuth, (req, res) => {
  const ip = getIP(req);
  const sshUsed   = getDailyCount(ip, ['ssh']);
  const v2rayUsed = getDailyCount(ip, ['vless','vmess','trojan']);
  res.json({
    ssh:   { used: sshUsed,   remaining: Math.max(0, DAILY_LIMIT_SSH - sshUsed),     limit: DAILY_LIMIT_SSH },
    v2ray: { used: v2rayUsed, remaining: Math.max(0, DAILY_LIMIT_V2RAY - v2rayUsed), limit: DAILY_LIMIT_V2RAY }
  });
});

app.get('/api/accounts', requireAdmin, (req, res) => {
  const { execSync } = require('child_process');
  let realUsers = new Set();
  try {
    const passwd = fs.readFileSync('/etc/passwd', 'utf8');
    passwd.split('\n').forEach(line => {
      const parts = line.split(':');
      const uid = parseInt(parts[2]);
      const shell = parts[6] || '';
      if (uid >= 1000 && shell.includes('bash') && parts[5] && parts[5].includes('/home')) {
        realUsers.add(parts[0]);
      }
    });
  } catch(e) {}
  const db = loadDB(); const now = new Date();
  let changed = false;
  db.accounts = db.accounts.filter(a => {
    if (a.type === 'ssh' && !realUsers.has(a.username)) { changed = true; return false; }
    return new Date(a.expiry) > now;
  });
  if (changed) saveDB(db);
  res.json({ accounts: db.accounts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)) });
});

app.get('/api/ping', requireAuth, (req, res) => {
  res.json({ pong: true, ts: Date.now() });
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'index.html')); });

// ── PORT 3709 ─────────────────────────────────────────────
const PORT = process.env.PORT || 3709;
app.listen(PORT, () => console.log(`🚀 Yosh VIP Panel running on http://localhost:${PORT}`));
