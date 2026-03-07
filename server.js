const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

const app = express();
const CONFIG_FILE = path.join(__dirname, 'config.json');
const DB_FILE = path.join(__dirname, 'accounts.json');

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function loadConfig() {
  return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
}

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const empty = { accounts: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(empty, null, 2));
    return empty;
  }
  try {
    const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    if (!db.accounts) db.accounts = [];
    return db;
  } catch {
    return { accounts: [] };
  }
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function expiryISO(days) {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString();
}

function runExpect(script) {
  return new Promise((resolve, reject) => {
    const tmp = `/tmp/vipweb_${Date.now()}.exp`;
    fs.writeFileSync(tmp, script);
    exec(`expect "${tmp}"`, { timeout: 90000 }, (err, stdout, stderr) => {
      try { fs.unlinkSync(tmp); } catch (_) {}
      const output = stdout + stderr;
      if (err && !output) return reject('Timeout or error: ' + (err.message || ''));
      resolve(output);
    });
  });
}

// ── SSH ──────────────────────────────────────────────────
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
expect "Press Enter"
send "\r"
expect "Option:"
send "0\r"
expect "Option:"
send "0\r"
expect eof`;
  const out = await runExpect(script);
  if (!out.toLowerCase().includes('created')) throw new Error('SSH creation failed');
}

// ── VLESS ─────────────────────────────────────────────────
// Exact prompts from Japan server:
// "Enter username:"
// "Expiration (days):"
// "Enter SNI :"
// "Press Enter to continue..."
async function createVLESS(username, days) {
  const cfg = loadConfig();
  const sni = cfg.SERVER_HOST;
  const script = `set timeout 90
spawn menu
expect "Option:"
send "2\r"
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
expect eof`;
  const out = await runExpect(script);
  console.log('[VLESS DEBUG]', out.slice(-600));
  const allVless = out.match(/vless:\/\/\S+/g) || [];
  const tls    = allVless.find(l => l.includes('443')) || null;
  const nonTls = allVless.find(l => l.includes(':80'))  || null;
  if (allVless.length === 0) {
    console.error('[VLESS ERROR] Output:', out);
    throw new Error('VLESS creation failed');
  }
  return {
    tls:    tls    ? tls.trim()    : null,
    nonTls: nonTls ? nonTls.trim() : null
  };
}

// ── Auto-expiry cleanup ────────────────────────────────────
setInterval(() => {
  const db = loadDB();
  const now = new Date();
  const before = db.accounts.length;
  db.accounts = db.accounts.filter(a => new Date(a.expiry) > now);
  if (db.accounts.length < before) saveDB(db);
}, 60 * 60 * 1000);

// ── API ROUTES ────────────────────────────────────────────
app.get('/api/stats', (req, res) => {
  const db = loadDB();
  res.json({
    total: db.accounts.length,
    ssh:   db.accounts.filter(a => a.type === 'ssh').length,
    vless: db.accounts.filter(a => a.type === 'vless').length
  });
});

app.get('/api/config', (req, res) => {
  const cfg = loadConfig();
  res.json({
    SERVER_HOST:   cfg.SERVER_HOST,
    SERVER_NS:     cfg.SERVER_NS,
    SERVER_PUBKEY: cfg.SERVER_PUBKEY,
    EXPIRY_DAYS:   cfg.EXPIRY_DAYS || 5
  });
});

app.post('/api/create/ssh', async (req, res) => {
  const { username, password, days } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password are required.' });
  if (!/^[a-zA-Z0-9_]{3,16}$/.test(username))
    return res.status(400).json({ error: 'Username must be 3–16 characters (letters, numbers, underscore).' });
  if (password.length < 4)
    return res.status(400).json({ error: 'Password must be at least 4 characters.' });

  const cfg = loadConfig();
  const expDays = Math.min(Math.max(parseInt(days) || cfg.EXPIRY_DAYS || 5, 1), 90);
  try {
    await createSSH(username, password, expDays);
    const expiry = expiryISO(expDays);
    const db = loadDB();
    db.accounts.push({ id: Date.now().toString(), username, password, type: 'ssh', expiry, createdAt: new Date().toISOString() });
    saveDB(db);
    res.json({ success: true, type: 'ssh', username, password, host: cfg.SERVER_HOST, ns: cfg.SERVER_NS, pubkey: cfg.SERVER_PUBKEY, expiry, days: expDays });
  } catch (e) {
    console.error('[SSH ERROR]', e);
    res.status(500).json({ error: 'Failed to create SSH account. Please try again.' });
  }
});

app.post('/api/create/vless', async (req, res) => {
  const { username, days } = req.body;
  if (!username)
    return res.status(400).json({ error: 'Username is required.' });
  if (!/^[a-zA-Z0-9_]{3,16}$/.test(username))
    return res.status(400).json({ error: 'Username must be 3–16 characters (letters, numbers, underscore).' });

  const cfg = loadConfig();
  const expDays = Math.min(Math.max(parseInt(days) || cfg.EXPIRY_DAYS || 5, 1), 90);
  try {
    const { tls, nonTls } = await createVLESS(username, expDays);
    const expiry = expiryISO(expDays);
    const db = loadDB();
    db.accounts.push({ id: Date.now().toString(), username, type: 'vless', expiry, createdAt: new Date().toISOString(), tls, nonTls });
    saveDB(db);
    res.json({ success: true, type: 'vless', username, host: cfg.SERVER_HOST, expiry, days: expDays, tls, nonTls });
  } catch (e) {
    console.error('[VLESS ERROR]', e);
    res.status(500).json({ error: 'Failed to create VLESS account. Please try again.' });
  }
});

const PORT = process.env.PORT || 3855;
app.listen(PORT, () => console.log(`🚀 Yosh VIP Panel running on http://localhost:${PORT}`));
