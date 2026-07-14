require('dotenv').config();
const express  = require('express');
const session  = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const multer   = require('multer');
const bcrypt   = require('bcryptjs');
const fetch    = require('node-fetch');
const xml2js   = require('xml2js');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const path = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

const SUPER_USER      = process.env.SUPER_ADMIN_USER     || 'superadmin';
const SUPER_PASS_HASH = bcrypt.hashSync(process.env.SUPER_ADMIN_PASSWORD || 'super123', 10);

// --- PostgreSQL ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS buildings (
      id            TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      name          TEXT NOT NULL,
      email         TEXT DEFAULT '',
      can_manage_ads BOOLEAN DEFAULT false,
      created_at    DATE DEFAULT CURRENT_DATE
    );
    CREATE TABLE IF NOT EXISTS businesses (
      id          BIGINT PRIMARY KEY,
      building_id TEXT REFERENCES buildings(id) ON DELETE CASCADE,
      name        TEXT NOT NULL DEFAULT '',
      office      TEXT DEFAULT '',
      floor       TEXT DEFAULT '',
      description TEXT DEFAULT '',
      sort_order  INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS ads (
      id          BIGINT PRIMARY KEY,
      building_id TEXT REFERENCES buildings(id) ON DELETE CASCADE,
      title       TEXT DEFAULT '',
      type        TEXT DEFAULT 'image',
      url         TEXT NOT NULL DEFAULT '',
      duration    INTEGER DEFAULT 6,
      active      BOOLEAN DEFAULT true
    );
    CREATE TABLE IF NOT EXISTS building_updates (
      id          BIGINT PRIMARY KEY,
      building_id TEXT REFERENCES buildings(id) ON DELETE CASCADE,
      text        TEXT NOT NULL DEFAULT '',
      image       TEXT DEFAULT '',
      sort_order  INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS building_settings (
      building_id   TEXT PRIMARY KEY REFERENCES buildings(id) ON DELETE CASCADE,
      building_name TEXT DEFAULT 'מרכז עסקים',
      theme         TEXT DEFAULT 'weather-news'
    );
    CREATE TABLE IF NOT EXISTS themes (
      id          TEXT PRIMARY KEY,
      name        TEXT NOT NULL,
      description TEXT DEFAULT '',
      sort_order  INTEGER DEFAULT 0
    );
  `);

  // Default themes
  await pool.query(`
    INSERT INTO themes (id, name, description, sort_order) VALUES
      ('weather-news', 'ערכת נושא כחול לבן - תחזית וחדשות',  'תחזית שבועית וחדשות ישראל היום בפאנל שמאל', 1),
      ('ads-focus',    'ערכת נושא כחול לבן - פרסומות מורחב', 'פרסומות רחבות ללא פאנל שמאל', 2),
      ('vibrant',      'ערכת נושא שחור לבן - תחזית וחדשות',  'עיצוב שחור לבן עם תחזית וחדשות במרכז', 3),
      ('vibrant-ads',  'ערכת נושא שחור לבן - פרסומות מורחב', 'עיצוב שחור לבן עם פרסומות רחבות ללא פאנל תחזית', 4),
      ('pink',         'ערכת נושא ורוד לבן',                  'עיצוב ורוד בייבי ולבן עם הדגשות שחור', 5),
      ('pink-ads',     'ערכת נושא ורוד לבן - פרסומות מורחב', 'עיצוב ורוד בייבי עם פרסומות רחבות ללא פאנל תחזית', 6)
    ON CONFLICT (id) DO NOTHING;
  `);

  console.log('DB מוכן');
}

// --- Cloudinary ---
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => ({
    folder: 'building-display/ads',
    resource_type: file.mimetype.startsWith('video') ? 'video' : 'image',
    allowed_formats: ['jpg', 'jpeg', 'png', 'gif', 'mp4', 'mov', 'webm'],
  }),
});
const upload = multer({ storage });

// --- Middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  store: new PgSession({ pool, createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'building-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 }
}));

// --- Auth ---
function requireSuper(req, res, next) {
  if (req.session.superAdmin) return next();
  res.status(401).json({ error: 'נדרשת כניסה כמנהל-על' });
}
function requireBuilding(req, res, next) {
  const bid = req.params.bid;
  if (req.session.superAdmin || req.session.buildingId === bid) return next();
  res.status(401).json({ error: 'אין הרשאה' });
}
async function requireAdsAuth(req, res, next) {
  const bid = req.params.bid;
  if (req.session.superAdmin) return next();
  if (req.session.buildingId !== bid) return res.status(401).json({ error: 'אין הרשאה' });
  const { rows } = await pool.query('SELECT can_manage_ads FROM buildings WHERE id=$1', [bid]);
  if (rows[0]?.can_manage_ads) return next();
  res.status(403).json({ error: 'ניהול פרסומות אינו מופעל לבניין זה' });
}

// --- Login ---
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (username === SUPER_USER && bcrypt.compareSync(password, SUPER_PASS_HASH)) {
    req.session.superAdmin = true; req.session.buildingId = null;
    return res.json({ ok: true, role: 'superadmin' });
  }
  const { rows } = await pool.query('SELECT * FROM buildings WHERE id=$1', [username]);
  const b = rows[0];
  if (b && bcrypt.compareSync(password, b.password_hash)) {
    req.session.buildingId = b.id; req.session.superAdmin = false;
    return res.json({ ok: true, role: 'building', buildingId: b.id });
  }
  res.status(401).json({ error: 'שם משתמש או סיסמה שגויים' });
});
app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ ok: true }); });
app.get('/api/me', (req, res) => {
  if (req.session.superAdmin) return res.json({ role: 'superadmin' });
  if (req.session.buildingId) return res.json({ role: 'building', buildingId: req.session.buildingId });
  res.json({ role: null });
});

// --- חדשות ישראל היום ---
let ilHayomCache = [], ilHayomCacheTime = 0;
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

async function fetchOgImage(url) {
  try {
    const r = await fetch(url, { headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(5000) });
    const html = await r.text();
    const m = html.match(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']/i)
           || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:image["']/i);
    return m ? m[1] : '';
  } catch(e) { return ''; }
}
async function fetchIsraelHayom() {
  try {
    const proxyUrl = 'https://api.rss2json.com/v1/api.json?rss_url=' + encodeURIComponent('https://www.israelhayom.co.il/rss.xml') + '&count=10';
    const r = await fetch(proxyUrl, { signal: AbortSignal.timeout(15000) });
    const data = await r.json();
    if (data.status !== 'ok' || !data.items?.length) throw new Error('rss2json returned: ' + data.status);
    const items = data.items.map(i => ({
      title: i.title || '',
      link: i.link || '',
      pubDate: i.pubDate || '',
      image: i.thumbnail || i.enclosure?.link || ''
    }));
    // Fill missing images from og:image
    const images = await Promise.all(items.map(i => (!i.image && i.link) ? fetchOgImage(i.link) : Promise.resolve(i.image)));
    items.forEach((item, idx) => { item.image = images[idx]; });
    ilHayomCache = items; ilHayomCacheTime = Date.now();
    console.log('ישראל היום: נטענו', items.length, 'כתבות');
  } catch(e) { console.error('שגיאה ישראל היום:', e.message); }
}
fetchIsraelHayom();
setInterval(fetchIsraelHayom, 10 * 60 * 1000);
app.get('/api/israelhayom', async (req, res) => {
  if (Date.now() - ilHayomCacheTime > 5 * 60 * 1000) await fetchIsraelHayom();
  res.json(ilHayomCache);
});

// --- חדשות ynet ---
let newsCache = [], newsCacheTime = 0;
async function fetchNews() {
  try {
    const r = await fetch('https://www.ynet.co.il/Integration/StoryRss2.xml', { headers: { 'User-Agent': 'Mozilla/5.0' } });
    const xml = await r.text();
    const result = await xml2js.parseStringPromise(xml);
    newsCache = result.rss.channel[0].item.slice(0, 15).map(i => ({ title: i.title[0], pubDate: i.pubDate?.[0] || '' }));
    newsCacheTime = Date.now();
  } catch(e) { console.log('שגיאה ynet:', e.message); }
}
fetchNews();
setInterval(fetchNews, 2 * 60 * 1000);
app.get('/api/news', async (req, res) => {
  if (Date.now() - newsCacheTime > 2 * 60 * 1000) await fetchNews();
  res.json(newsCache);
});

// --- ממשקי בניין ציבוריים ---
app.get('/api/:bid/businesses', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM businesses WHERE building_id=$1 ORDER BY sort_order, id', [req.params.bid]);
  res.json(rows.map(r => ({ id: r.id, name: r.name, office: r.office, floor: r.floor, description: r.description })));
});
app.get('/api/:bid/updates', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM building_updates WHERE building_id=$1 ORDER BY sort_order, id', [req.params.bid]);
  res.json(rows.map(r => ({ id: r.id, text: r.text, image: r.image })));
});
app.get('/api/:bid/settings', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM building_settings WHERE building_id=$1', [req.params.bid]);
  res.json(rows[0] ? { buildingName: rows[0].building_name } : { buildingName: 'מרכז עסקים' });
});
app.get('/api/:bid/theme', async (req, res) => {
  const { rows } = await pool.query('SELECT theme FROM building_settings WHERE building_id=$1', [req.params.bid]);
  res.json({ theme: rows[0]?.theme || 'weather-news' });
});
app.get('/api/:bid/ads', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM ads WHERE building_id=$1 AND active=true ORDER BY id', [req.params.bid]);
  res.json(rows.map(r => ({ id: r.id, title: r.title, type: r.type, url: r.url, duration: r.duration })));
});

// --- עסקים ---
app.post('/api/:bid/businesses', requireBuilding, async (req, res) => {
  const id = Date.now();
  const { name, office, floor, description } = req.body;
  const { rows } = await pool.query(
    'INSERT INTO businesses (id, building_id, name, office, floor, description) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
    [id, req.params.bid, name || '', office || '', floor || '', description || '']
  );
  res.json({ id: rows[0].id, name: rows[0].name, office: rows[0].office, floor: rows[0].floor, description: rows[0].description });
});
app.put('/api/:bid/businesses/:id', requireBuilding, async (req, res) => {
  const { name, office, floor, description } = req.body;
  await pool.query(
    'UPDATE businesses SET name=$1, office=$2, floor=$3, description=$4 WHERE id=$5 AND building_id=$6',
    [name, office, floor || '', description || '', req.params.id, req.params.bid]
  );
  res.json({ ok: true });
});
app.delete('/api/:bid/businesses/:id', requireBuilding, async (req, res) => {
  await pool.query('DELETE FROM businesses WHERE id=$1 AND building_id=$2', [req.params.id, req.params.bid]);
  res.json({ ok: true });
});

// --- עדכוני בניין ---
app.post('/api/:bid/updates', requireBuilding, async (req, res) => {
  const id = Date.now();
  const { rows } = await pool.query(
    'INSERT INTO building_updates (id, building_id, text, image) VALUES ($1,$2,$3,$4) RETURNING *',
    [id, req.params.bid, req.body.text || '', req.body.image || '']
  );
  res.json({ id: rows[0].id, text: rows[0].text, image: rows[0].image });
});
app.put('/api/:bid/updates/:id', requireBuilding, async (req, res) => {
  await pool.query(
    'UPDATE building_updates SET text=$1, image=$2 WHERE id=$3 AND building_id=$4',
    [req.body.text, req.body.image || '', req.params.id, req.params.bid]
  );
  res.json({ ok: true });
});
app.delete('/api/:bid/updates/:id', requireBuilding, async (req, res) => {
  await pool.query('DELETE FROM building_updates WHERE id=$1 AND building_id=$2', [req.params.id, req.params.bid]);
  res.json({ ok: true });
});
app.post('/api/:bid/updates/reorder', requireBuilding, async (req, res) => {
  const { id, direction } = req.body;
  const { rows } = await pool.query('SELECT * FROM building_updates WHERE building_id=$1 ORDER BY sort_order, id', [req.params.bid]);
  const idx = rows.findIndex(u => u.id == id);
  if (idx === -1) return res.json({ ok: false });
  const ni = direction === 'up' ? idx - 1 : idx + 1;
  if (ni < 0 || ni >= rows.length) return res.json({ ok: false });
  await pool.query('UPDATE building_updates SET sort_order=$1 WHERE id=$2', [ni, rows[idx].id]);
  await pool.query('UPDATE building_updates SET sort_order=$1 WHERE id=$2', [idx, rows[ni].id]);
  res.json({ ok: true });
});

// --- פרסומות ---
app.get('/api/:bid/ads/all', requireBuilding, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM ads WHERE building_id=$1 ORDER BY id', [req.params.bid]);
  res.json(rows.map(r => ({ id: r.id, title: r.title, type: r.type, url: r.url, duration: r.duration, active: r.active })));
});
app.post('/api/:bid/ads', requireAdsAuth, upload.single('file'), async (req, res) => {
  const id  = Date.now();
  const url = req.file ? (req.file.secure_url || req.file.path || '') : (req.body.url || '');
  const { rows } = await pool.query(
    'INSERT INTO ads (id, building_id, title, type, url, duration, active) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
    [id, req.params.bid, req.body.title || '', req.body.type || 'image', url, parseInt(req.body.duration) || 6, true]
  );
  res.json({ id: rows[0].id, title: rows[0].title, type: rows[0].type, url: rows[0].url, duration: rows[0].duration, active: rows[0].active });
});
app.put('/api/:bid/ads/:id', requireAdsAuth, async (req, res) => {
  await pool.query(
    'UPDATE ads SET active=$1 WHERE id=$2 AND building_id=$3',
    [req.body.active === 'true', req.params.id, req.params.bid]
  );
  res.json({ ok: true });
});
app.delete('/api/:bid/ads/:id', requireAdsAuth, async (req, res) => {
  await pool.query('DELETE FROM ads WHERE id=$1 AND building_id=$2', [req.params.id, req.params.bid]);
  res.json({ ok: true });
});

// --- הגדרות וערכת נושא ---
app.post('/api/:bid/settings', requireBuilding, async (req, res) => {
  await pool.query(
    'INSERT INTO building_settings (building_id, building_name) VALUES ($1,$2) ON CONFLICT (building_id) DO UPDATE SET building_name=$2',
    [req.params.bid, req.body.buildingName || 'מרכז עסקים']
  );
  res.json({ ok: true });
});
app.post('/api/:bid/theme', requireBuilding, async (req, res) => {
  await pool.query(
    'INSERT INTO building_settings (building_id, theme) VALUES ($1,$2) ON CONFLICT (building_id) DO UPDATE SET theme=$2',
    [req.params.bid, req.body.theme]
  );
  res.json({ ok: true });
});

// --- שינוי סיסמה ---
app.post('/api/:bid/change-password', requireBuilding, async (req, res) => {
  if (req.session.superAdmin) return res.status(403).json({ error: 'מנהל-על לא יכול לשנות סיסמת בניין מכאן' });
  const { oldPassword, newPassword } = req.body;
  const { rows } = await pool.query('SELECT * FROM buildings WHERE id=$1', [req.params.bid]);
  if (!rows[0]) return res.status(404).json({ error: 'בניין לא נמצא' });
  if (!bcrypt.compareSync(oldPassword, rows[0].password_hash))
    return res.status(401).json({ error: 'סיסמה ישנה שגויה' });
  await pool.query('UPDATE buildings SET password_hash=$1 WHERE id=$2', [bcrypt.hashSync(newPassword, 10), req.params.bid]);
  res.json({ ok: true });
});

// --- פרטי בניין ---
app.get('/api/:bid/building-info', requireBuilding, async (req, res) => {
  const { rows } = await pool.query('SELECT id, name, email, can_manage_ads, created_at FROM buildings WHERE id=$1', [req.params.bid]);
  if (!rows[0]) return res.status(404).json({ error: 'לא נמצא' });
  const b = rows[0];
  res.json({ id: b.id, name: b.name, email: b.email, canManageAds: b.can_manage_ads, createdAt: b.created_at });
});

// --- מנהל-על: ערכות נושא ---
app.get('/api/superadmin/themes', requireSuper, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM themes ORDER BY sort_order, id');
  res.json(rows.map(r => ({ id: r.id, name: r.name, description: r.description })));
});
app.put('/api/superadmin/themes', requireSuper, async (req, res) => {
  if (!Array.isArray(req.body)) return res.status(400).json({ error: 'נדרש מערך' });
  for (const t of req.body) {
    await pool.query(
      'INSERT INTO themes (id, name, description) VALUES ($1,$2,$3) ON CONFLICT (id) DO UPDATE SET name=$2, description=$3',
      [t.id, t.name, t.description || '']
    );
  }
  res.json({ ok: true });
});

// --- מנהל-על: ניהול בניינים ---
app.get('/api/superadmin/buildings', requireSuper, async (req, res) => {
  const { rows } = await pool.query('SELECT id, name, email, can_manage_ads, created_at FROM buildings ORDER BY created_at DESC');
  res.json(rows.map(r => ({ id: r.id, name: r.name, email: r.email, canManageAds: r.can_manage_ads, createdAt: r.created_at })));
});

app.post('/api/superadmin/buildings', requireSuper, async (req, res) => {
  const { id, password, name, email } = req.body;
  const { rows: existing } = await pool.query('SELECT id FROM buildings WHERE id=$1', [id]);
  if (existing.length) return res.status(400).json({ error: 'בניין עם ת"ז זו כבר קיים' });
  const passwordHash = bcrypt.hashSync(password, 10);
  await pool.query(
    'INSERT INTO buildings (id, password_hash, name, email) VALUES ($1,$2,$3,$4)',
    [id, passwordHash, name, email || '']
  );
  await pool.query(
    'INSERT INTO building_settings (building_id, building_name, theme) VALUES ($1,$2,$3)',
    [id, name, 'weather-news']
  );
  res.json({ id, name, email: email || '', canManageAds: false, createdAt: new Date().toISOString().split('T')[0] });
});

app.put('/api/superadmin/buildings/:id', requireSuper, async (req, res) => {
  const { name, email, password } = req.body;
  if (password) {
    await pool.query('UPDATE buildings SET name=$1, email=$2, password_hash=$3 WHERE id=$4',
      [name, email || '', bcrypt.hashSync(password, 10), req.params.id]);
  } else {
    await pool.query('UPDATE buildings SET name=$1, email=$2 WHERE id=$3', [name, email || '', req.params.id]);
  }
  res.json({ ok: true });
});

app.delete('/api/superadmin/buildings/:id', requireSuper, async (req, res) => {
  await pool.query('DELETE FROM buildings WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

// מנהל-על: toggle ריטיינר
app.post('/api/superadmin/buildings/:id/toggle-ads', requireSuper, async (req, res) => {
  await pool.query('UPDATE buildings SET can_manage_ads=$1 WHERE id=$2', [req.body.value, req.params.id]);
  res.json({ ok: true });
});

// מנהל-על: ניהול פרסומות
app.get('/api/superadmin/buildings/:id/ads', requireSuper, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM ads WHERE building_id=$1 ORDER BY id', [req.params.id]);
  res.json(rows.map(r => ({ id: r.id, title: r.title, type: r.type, url: r.url, duration: r.duration, active: r.active })));
});
app.post('/api/superadmin/buildings/:id/ads', requireSuper, upload.single('file'), async (req, res) => {
  const id  = Date.now();
  const url = req.file ? (req.file.secure_url || req.file.path || '') : (req.body.url || '');
  const { rows } = await pool.query(
    'INSERT INTO ads (id, building_id, title, type, url, duration, active) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
    [id, req.params.id, req.body.title || '', req.body.type || 'image', url, parseInt(req.body.duration) || 6, true]
  );
  res.json({ id: rows[0].id, title: rows[0].title, type: rows[0].type, url: rows[0].url, duration: rows[0].duration, active: rows[0].active });
});
app.put('/api/superadmin/buildings/:id/ads/:adId', requireSuper, async (req, res) => {
  await pool.query('UPDATE ads SET active=$1 WHERE id=$2 AND building_id=$3',
    [req.body.active === 'true', req.params.adId, req.params.id]);
  res.json({ ok: true });
});
app.delete('/api/superadmin/buildings/:id/ads/:adId', requireSuper, async (req, res) => {
  await pool.query('DELETE FROM ads WHERE id=$1 AND building_id=$2', [req.params.adId, req.params.id]);
  res.json({ ok: true });
});

// --- דפים ---
app.get('/login',       (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/screen/:bid', (req, res) => res.sendFile(path.join(__dirname, 'public', 'screen.html')));
app.get('/admin',       (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'super.html')));
app.get('/admin/:bid',  (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'index.html')));
app.get('/screen',      (req, res) => res.redirect('/screen/203991203'));

app.use(express.static('public'));

// --- Start ---
initDB().then(() => {
  app.listen(PORT, () => console.log(`שרת רץ על פורט ${PORT}`));
}).catch(err => {
  console.error('שגיאה בחיבור ל-DB:', err.message);
  process.exit(1);
});
