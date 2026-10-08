require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Joan5078';
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const SESSION_SECRET =
  process.env.SESSION_SECRET || process.env.ADMIN_PASSWORD || 'Joan5078-session-secret';
const MAX_BODY_BYTES = 2 * 1024 * 1024;
const ALLOWED_EXTS = new Set(['.html', '.htm', '.css', '.js', '.json', '.txt', '.svg', '.xml']);

// On Vercel, set these so admin can save trade fields (filesystem is read-only)
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';
const GITHUB_REPO = process.env.GITHUB_REPO || 'ecocashloans/DERIV-APP';
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || 'main';
const GITHUB_TRADE_PATH = process.env.GITHUB_TRADE_PATH || 'public/trade-config.json';

const PUBLIC_DIR = path.join(__dirname, 'public');
const ADMIN_DIR = path.join(__dirname, 'admin');
const TRADE_CONFIG_FILE = path.join(PUBLIC_DIR, 'trade-config.json');
const IS_VERCEL = Boolean(process.env.VERCEL || process.env.NOW_REGION);

const DEFAULT_TRADE = {
  paymentMethod: 'Bank Transfer',
  tradeId: 'TR-88421',
  amount: '150.00 USD',
  status: 'waiting',
};

// Survives within a warm serverless instance; cold starts fall back to file/GitHub
let tradeCache = null;
let tradeCacheSavedAt = null;

// Best-effort rate limit (per instance only on Vercel)
const loginAttempts = new Map();

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '2mb' }));

// ---------------------------------------------------------------- helpers

function normalizeTradeStatus(status) {
  const value = String(status || '').toLowerCase().trim();
  if (value === 'complete' || value === 'transfer complete' || value === 'completed') {
    return 'complete';
  }
  return 'waiting';
}

function sanitizeTrade(raw = {}) {
  return {
    paymentMethod: String(raw.paymentMethod || DEFAULT_TRADE.paymentMethod).trim().slice(0, 200) || DEFAULT_TRADE.paymentMethod,
    tradeId: String(raw.tradeId || DEFAULT_TRADE.tradeId).trim().slice(0, 120) || DEFAULT_TRADE.tradeId,
    amount: String(raw.amount || DEFAULT_TRADE.amount).trim().slice(0, 80) || DEFAULT_TRADE.amount,
    status: normalizeTradeStatus(raw.status),
  };
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

/** Stateless signed session: base64url(exp).hmac */
function signSession() {
  const exp = String(Date.now() + SESSION_TTL_MS);
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(exp).digest('base64url');
  return `${exp}.${sig}`;
}

function verifySession(token) {
  if (!token || typeof token !== 'string') return false;
  const i = token.lastIndexOf('.');
  if (i <= 0) return false;
  const exp = token.slice(0, i);
  const sig = token.slice(i + 1);
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(exp).digest('base64url');
  try {
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  } catch {
    return false;
  }
  const expMs = Number(exp);
  if (!Number.isFinite(expMs) || expMs < Date.now()) return false;
  return true;
}

function isAuthenticated(req) {
  return verifySession(parseCookies(req).admin_session);
}

function sameOrigin(req) {
  const origin = req.get('origin');
  if (!origin) return false;
  try {
    const u = new URL(origin);
    return u.host === req.get('host') && (u.protocol === 'http:' || u.protocol === 'https:');
  } catch {
    return false;
  }
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

function requireAuth(req, res, next) {
  if (!isAuthenticated(req)) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

function cookieFlags(req) {
  const host = req.get('host') || '';
  const xfProto = (req.get('x-forwarded-proto') || '').split(',')[0].trim();
  const secure =
    process.env.FORCE_SECURE_COOKIE === '1' ||
    process.env.NODE_ENV === 'production' ||
    IS_VERCEL ||
    xfProto === 'https' ||
    host.includes('vercel.app');
  // Lax works better than Strict for top-level navigations on some browsers
  return `HttpOnly; SameSite=Lax; Path=/${secure ? '; Secure' : ''}`;
}

function setSessionCookie(req, res, token) {
  res.setHeader(
    'Set-Cookie',
    `admin_session=${encodeURIComponent(token)}; ${cookieFlags(req)}; Max-Age=${SESSION_TTL_MS / 1000}`
  );
}

function clearSessionCookie(req, res) {
  res.setHeader('Set-Cookie', `admin_session=; ${cookieFlags(req)}; Max-Age=0`);
}

function checkRateLimit(ip) {
  const rec = loginAttempts.get(ip);
  if (rec && rec.lockedUntil && rec.lockedUntil > Date.now()) {
    return { locked: true, retryAfter: Math.ceil((rec.lockedUntil - Date.now()) / 1000) };
  }
  return { locked: false };
}

function recordFailure(ip) {
  const now = Date.now();
  const rec = loginAttempts.get(ip) || { failures: 0, lockedUntil: 0 };
  rec.failures += 1;
  if (rec.failures >= 10) {
    rec.lockedUntil = now + 15 * 60 * 1000;
    rec.failures = 0;
  }
  loginAttempts.set(ip, rec);
}

function recordSuccess(ip) {
  loginAttempts.delete(ip);
}

function readTradeFromDisk() {
  try {
    if (fs.existsSync(TRADE_CONFIG_FILE)) {
      return sanitizeTrade(JSON.parse(fs.readFileSync(TRADE_CONFIG_FILE, 'utf8')));
    }
  } catch (err) {
    console.error('disk read trade-config:', err.message);
  }
  return null;
}

async function readTradeFromGitHub() {
  if (!GITHUB_TOKEN) return null;
  try {
    const url = `https://api.github.com/repos/${GITHUB_REPO}/contents/${GITHUB_TRADE_PATH}?ref=${encodeURIComponent(GITHUB_BRANCH)}`;
    const res = await fetch(url, {
      headers: {
        Authorization: `Bearer ${GITHUB_TOKEN}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'deriv-app-admin',
      },
    });
    if (!res.ok) {
      console.error('GitHub read failed:', res.status, await res.text());
      return null;
    }
    const data = await res.json();
    const text = Buffer.from(data.content.replace(/\n/g, ''), 'base64').toString('utf8');
    return { trade: sanitizeTrade(JSON.parse(text)), sha: data.sha };
  } catch (err) {
    console.error('GitHub read error:', err.message);
    return null;
  }
}

async function writeTradeToGitHub(trade) {
  if (!GITHUB_TOKEN) {
    const err = new Error(
      'Filesystem is read-only (Vercel). Set GITHUB_TOKEN env var so admin can save trade settings.'
    );
    err.code = 'NO_GITHUB_TOKEN';
    throw err;
  }
  const bodyText = JSON.stringify(trade, null, 2) + '\n';
  const existing = await readTradeFromGitHub();
  const url = `https://api.github.com/repos/${GITHUB_REPO}/contents/${GITHUB_TRADE_PATH}`;
  const payload = {
    message: `Update trade-config via admin (${trade.tradeId})`,
    content: Buffer.from(bodyText, 'utf8').toString('base64'),
    branch: GITHUB_BRANCH,
  };
  if (existing && existing.sha) payload.sha = existing.sha;

  const res = await fetch(url, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${GITHUB_TOKEN}`,
      Accept: 'application/vnd.github+json',
      'Content-Type': 'application/json',
      'User-Agent': 'deriv-app-admin',
    },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const t = await res.text();
    console.error('GitHub write failed:', res.status, t);
    const err = new Error(`GitHub save failed (${res.status}). Check GITHUB_TOKEN permissions (contents:write).`);
    err.code = 'GITHUB_WRITE_FAILED';
    throw err;
  }
  return true;
}

function writeTradeToDisk(trade) {
  if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });
  fs.writeFileSync(TRADE_CONFIG_FILE, JSON.stringify(trade, null, 2) + '\n', 'utf8');
}

async function readTradeConfig() {
  if (tradeCache) return { trade: tradeCache, savedAt: tradeCacheSavedAt };

  // On Vercel with a token, GitHub is the source of truth: the deployed
  // disk copy can be stale between an admin save and the next redeploy.
  if (IS_VERCEL && GITHUB_TOKEN) {
    const gh = await readTradeFromGitHub();
    if (gh && gh.trade) {
      tradeCache = gh.trade;
      tradeCacheSavedAt = new Date().toISOString();
      return { trade: tradeCache, savedAt: tradeCacheSavedAt };
    }
  }

  const disk = readTradeFromDisk();
  if (disk) {
    tradeCache = disk;
    try {
      tradeCacheSavedAt = fs.statSync(TRADE_CONFIG_FILE).mtime.toISOString();
    } catch {
      tradeCacheSavedAt = null;
    }
    return { trade: tradeCache, savedAt: tradeCacheSavedAt };
  }
  const gh = await readTradeFromGitHub();
  if (gh && gh.trade) {
    tradeCache = gh.trade;
    tradeCacheSavedAt = new Date().toISOString();
    return { trade: tradeCache, savedAt: tradeCacheSavedAt };
  }
  return { trade: { ...DEFAULT_TRADE }, savedAt: null };
}

async function writeTradeConfig(input) {
  const trade = sanitizeTrade(input);
  let savedVia = 'memory';
  let warn = '';

  // Prefer local disk when writable (local / VPS)
  try {
    writeTradeToDisk(trade);
    savedVia = 'disk';
  } catch (diskErr) {
    console.warn('Disk write failed (expected on Vercel):', diskErr.message);
    if (GITHUB_TOKEN) {
      try {
        await writeTradeToGitHub(trade);
        savedVia = 'github';
      } catch (ghErr) {
        console.warn('GitHub write failed, using in-memory cache:', ghErr.message);
        savedVia = 'memory';
        warn = `GitHub save failed (${ghErr.code || 'error'}): ${ghErr.message}`;
      }
    } else {
      // Still succeed so admin UI works; values live until this serverless instance cold-starts
      console.warn('No GITHUB_TOKEN; trade save is in-memory only on this instance');
      savedVia = 'memory';
      warn = 'No GITHUB_TOKEN set: save is temporary (lost on server restart). Set GITHUB_TOKEN in Vercel env for permanent saves.';
    }
  }

  // If disk worked but we also have a token and are on Vercel-like host, still sync GitHub
  if (savedVia === 'disk' && GITHUB_TOKEN && IS_VERCEL) {
    try {
      await writeTradeToGitHub(trade);
      savedVia = 'disk+github';
    } catch (err) {
      console.warn('Optional GitHub sync failed:', err.message);
      warn = `GitHub sync failed (${err.code || 'error'}): ${err.message}`;
    }
  }

  tradeCache = trade;
  tradeCacheSavedAt = new Date().toISOString();
  return { trade, savedAt: tradeCacheSavedAt, savedVia, warn };
}

function resolvePublicFile(relPath) {
  if (typeof relPath !== 'string' || !relPath.trim()) {
    return { ok: false, status: 400, error: 'file is required' };
  }
  let rel = relPath.replace(/\\/g, '/').replace(/^\/+/, '').trim();
  if (!rel || rel.includes('\0') || rel.includes('..')) {
    return { ok: false, status: 400, error: 'Invalid file path' };
  }
  const abs = path.resolve(PUBLIC_DIR, rel);
  const publicRoot = path.resolve(PUBLIC_DIR) + path.sep;
  if (abs !== path.resolve(PUBLIC_DIR) && !abs.startsWith(publicRoot)) {
    return { ok: false, status: 400, error: 'Invalid file path' };
  }
  const ext = path.extname(abs).toLowerCase();
  if (!ALLOWED_EXTS.has(ext)) {
    return { ok: false, status: 400, error: `File type not allowed (${ext || 'none'})` };
  }
  return { ok: true, abs, rel: path.relative(PUBLIC_DIR, abs).split(path.sep).join('/') };
}

function listPublicFiles(dir = PUBLIC_DIR, base = '') {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  for (const name of fs.readdirSync(dir)) {
    if (name.startsWith('.')) continue;
    const full = path.join(dir, name);
    const rel = base ? `${base}/${name}` : name;
    let st;
    try {
      st = fs.statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) out.push(...listPublicFiles(full, rel));
    else if (st.isFile()) {
      const ext = path.extname(name).toLowerCase();
      if (ALLOWED_EXTS.has(ext)) {
        out.push({ path: rel, size: st.size, mtime: st.mtime.toISOString() });
      }
    }
  }
  out.sort((a, b) => a.path.localeCompare(b.path));
  return out;
}

// ---------------------------------------------------------------- routes

app.get('/admin', (req, res) => {
  res.sendFile(path.join(ADMIN_DIR, 'index.html'));
});

app.get('/admin/api/session', (req, res) => {
  res.json({ authed: isAuthenticated(req) });
});

app.post('/admin/api/login', (req, res) => {
  const ip = req.ip || 'unknown';
  const rl = checkRateLimit(ip);
  if (rl.locked) {
    return res.status(429).json({ error: `Too many attempts. Try again in ${rl.retryAfter}s.` });
  }
  const { password } = req.body || {};
  if (typeof password !== 'string' || !safeEqual(password, ADMIN_PASSWORD)) {
    recordFailure(ip);
    return res.status(401).json({ error: 'Invalid password' });
  }
  recordSuccess(ip);
  const token = signSession();
  setSessionCookie(req, res, token);
  res.json({ ok: true });
});

app.post('/admin/api/logout', (req, res) => {
  clearSessionCookie(req, res);
  res.json({ ok: true });
});

// Public trade values for index.html (no auth)
app.get('/api/trade-public', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const { trade, savedAt } = await readTradeConfig();
    res.json({ ...trade, savedAt });
  } catch (err) {
    console.error(err);
    res.json({ ...DEFAULT_TRADE });
  }
});

// Also serve trade-config.json dynamically so stale CDN/static copies don't win
app.get('/trade-config.json', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.type('json');
  try {
    const { trade } = await readTradeConfig();
    res.send(JSON.stringify(trade, null, 2) + '\n');
  } catch {
    res.send(JSON.stringify(DEFAULT_TRADE, null, 2) + '\n');
  }
});

app.get('/admin/api/trade', requireAuth, async (req, res) => {
  try {
    const { trade, savedAt } = await readTradeConfig();
    res.json({ trade, savedAt });
  } catch (err) {
    console.error('Failed to load trade config:', err);
    res.json({ trade: { ...DEFAULT_TRADE }, savedAt: null, warning: 'Using defaults' });
  }
});

app.post('/admin/api/trade', requireAuth, async (req, res) => {
  if (!sameOrigin(req)) {
    return res.status(403).json({ error: 'Cross-origin request rejected' });
  }
  const body = req.body || {};
  if (!body.paymentMethod && !body.tradeId && !body.amount && !body.status) {
    return res.status(400).json({ error: 'Provide paymentMethod, tradeId, amount, and/or status' });
  }
  try {
    const current = (await readTradeConfig()).trade;
    const result = await writeTradeConfig({
      paymentMethod: body.paymentMethod != null ? body.paymentMethod : current.paymentMethod,
      tradeId: body.tradeId != null ? body.tradeId : current.tradeId,
      amount: body.amount != null ? body.amount : current.amount,
      status: body.status != null ? body.status : current.status,
    });
    res.json({ ok: true, trade: result.trade, savedAt: result.savedAt, savedVia: result.savedVia, warn: result.warn });
  } catch (err) {
    console.error('Failed to save trade config:', err);
    const msg =
      err.code === 'NO_GITHUB_TOKEN'
        ? err.message
        : err.message || 'Failed to save trade settings';
    res.status(500).json({ error: msg });
  }
});

app.get('/admin/api/files', requireAuth, (req, res) => {
  try {
    res.json({ files: listPublicFiles() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to list files' });
  }
});

app.get('/admin/api/content', requireAuth, (req, res) => {
  const resolved = resolvePublicFile(req.query.file || 'index.html');
  if (!resolved.ok) return res.status(resolved.status).json({ error: resolved.error });
  if (!fs.existsSync(resolved.abs) || !fs.statSync(resolved.abs).isFile()) {
    return res.status(404).json({ error: `File not found: ${resolved.rel}` });
  }
  try {
    const content = fs.readFileSync(resolved.abs, 'utf8');
    const stat = fs.statSync(resolved.abs);
    res.json({ file: resolved.rel, content, savedAt: stat.mtime.toISOString(), size: stat.size });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to read file' });
  }
});

app.post('/admin/api/content', requireAuth, (req, res) => {
  if (!sameOrigin(req)) {
    return res.status(403).json({ error: 'Cross-origin request rejected' });
  }
  if (IS_VERCEL) {
    return res.status(501).json({
      error: 'Raw file editing is not supported on Vercel (read-only disk). Use the Trade details form instead.',
    });
  }
  const { content, file } = req.body || {};
  const resolved = resolvePublicFile(file || 'index.html');
  if (!resolved.ok) return res.status(resolved.status).json({ error: resolved.error });
  if (typeof content !== 'string') {
    return res.status(400).json({ error: 'content must be a string' });
  }
  if (Buffer.byteLength(content, 'utf8') > MAX_BODY_BYTES) {
    return res.status(413).json({ error: 'Content too large (max 2 MB)' });
  }
  if (!fs.existsSync(resolved.abs)) {
    return res.status(404).json({ error: `File not found: ${resolved.rel}` });
  }
  try {
    fs.writeFileSync(resolved.abs, content, 'utf8');
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to save. Check filesystem permissions.' });
  }
  res.json({ ok: true, file: resolved.rel, savedAt: new Date().toISOString() });
});

app.use('/admin', express.static(ADMIN_DIR));
app.use(express.static(PUBLIC_DIR, { index: 'index.html' }));

app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Content too large (max 2 MB)' });
  }
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Malformed JSON body' });
  }
  next(err);
});

// Vercel serverless export
module.exports = app;

if (!IS_VERCEL) {
  app.listen(PORT, () => {
    console.log(`DERIV-APP running on http://localhost:${PORT}`);
    console.log(`Admin panel:   http://localhost:${PORT}/admin`);
    console.log(
      `Admin password: ${process.env.ADMIN_PASSWORD ? '(from env/.env)' : 'DEFAULT Joan5078'}`
    );
    if (IS_VERCEL || !GITHUB_TOKEN) {
      /* local ok without token */
    }
  });
}
