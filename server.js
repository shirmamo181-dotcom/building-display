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
    CREATE TABLE IF NOT EXISTS clients (
      id            TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      name          TEXT DEFAULT '',
      email         TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS themes (
      id          TEXT PRIMARY KEY,
      name        TEXT NOT NULL,
      description TEXT DEFAULT '',
      sort_order  INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS global_ads (
      id               BIGINT PRIMARY KEY,
      title            TEXT DEFAULT '',
      type             TEXT DEFAULT 'image',
      url              TEXT NOT NULL DEFAULT '',
      duration         INTEGER DEFAULT 6,
      active           BOOLEAN DEFAULT true,
      start_date       DATE,
      end_date         DATE,
      advertiser_name  TEXT DEFAULT '',
      advertiser_phone TEXT DEFAULT '',
      advertiser_email TEXT DEFAULT '',
      created_at       DATE DEFAULT CURRENT_DATE
    );
    CREATE TABLE IF NOT EXISTS global_ad_buildings (
      id           BIGINT PRIMARY KEY,
      global_ad_id BIGINT REFERENCES global_ads(id) ON DELETE CASCADE,
      building_id  TEXT REFERENCES buildings(id) ON DELETE CASCADE,
      sort_order   INTEGER DEFAULT 999,
      active       BOOLEAN DEFAULT true,
      UNIQUE(global_ad_id, building_id)
    );
  `);

  // Migrate buildings table
  try { await pool.query("ALTER TABLE buildings ADD COLUMN IF NOT EXISTS client_id TEXT REFERENCES clients(id) ON DELETE SET NULL"); } catch(e) {}

  // Migrate ads table
  const adsCols = ['sort_order INTEGER DEFAULT 999','start_date DATE','end_date DATE',
    "advertiser_name TEXT DEFAULT ''","advertiser_phone TEXT DEFAULT ''","advertiser_email TEXT DEFAULT ''"];
  for (const col of adsCols) {
    try { await pool.query(`ALTER TABLE ads ADD COLUMN IF NOT EXISTS ${col}`); } catch(e) {}
  }

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
async function requireBuilding(req, res, next) {
  const bid = req.params.bid;
  if (req.session.superAdmin || req.session.buildingId === bid) return next();
  if (req.session.clientId) {
    const { rows } = await pool.query('SELECT id FROM buildings WHERE id=$1 AND client_id=$2', [bid, req.session.clientId]);
    if (rows[0]) return next();
  }
  res.status(401).json({ error: 'אין הרשאה' });
}
async function requireAdsAuth(req, res, next) {
  const bid = req.params.bid;
  if (req.session.superAdmin) return next();
  const isBuilding = req.session.buildingId === bid;
  const isClient = req.session.clientId && !!(await pool.query('SELECT id FROM buildings WHERE id=$1 AND client_id=$2', [bid, req.session.clientId])).rows[0];
  if (!isBuilding && !isClient) return res.status(401).json({ error: 'אין הרשאה' });
  const { rows } = await pool.query('SELECT can_manage_ads FROM buildings WHERE id=$1', [bid]);
  if (rows[0]?.can_manage_ads) return next();
  res.status(403).json({ error: 'ניהול פרסומות אינו מופעל לבניין זה' });
}

// --- Login ---
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (username === SUPER_USER && bcrypt.compareSync(password, SUPER_PASS_HASH)) {
    req.session.superAdmin = true; req.session.buildingId = null; req.session.clientId = null;
    return res.json({ ok: true, role: 'superadmin' });
  }
  // Check client accounts
  const { rows: clientRows } = await pool.query('SELECT * FROM clients WHERE id=$1', [username]);
  if (clientRows[0] && bcrypt.compareSync(password, clientRows[0].password_hash)) {
    req.session.clientId = clientRows[0].id; req.session.superAdmin = false;
    const { rows: bldgs } = await pool.query('SELECT id, name FROM buildings WHERE client_id=$1 ORDER BY name', [clientRows[0].id]);
    req.session.buildingId = bldgs.length ? bldgs[0].id : null;
    return res.json({ ok: true, role: 'building', buildingId: req.session.buildingId });
  }
  // Check individual building accounts
  const { rows } = await pool.query('SELECT * FROM buildings WHERE id=$1', [username]);
  const b = rows[0];
  if (b && bcrypt.compareSync(password, b.password_hash)) {
    req.session.buildingId = b.id; req.session.superAdmin = false; req.session.clientId = null;
    return res.json({ ok: true, role: 'building', buildingId: b.id });
  }
  res.status(401).json({ error: 'שם משתמש או סיסמה שגויים' });
});
app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ ok: true }); });
app.get('/api/me', (req, res) => {
  if (req.session.superAdmin) return res.json({ role: 'superadmin' });
  if (req.session.buildingId) return res.json({ role: 'building', buildingId: req.session.buildingId, clientId: req.session.clientId || null });
  if (req.session.clientId) return res.json({ role: 'client', clientId: req.session.clientId });
  res.json({ role: null });
});

app.post('/api/client/switch-building', async (req, res) => {
  if (!req.session.clientId) return res.status(401).json({ error: 'אין הרשאה' });
  const { buildingId } = req.body;
  const { rows } = await pool.query('SELECT id FROM buildings WHERE id=$1 AND client_id=$2', [buildingId, req.session.clientId]);
  if (!rows[0]) return res.status(403).json({ error: 'בניין לא שייך ללקוח זה' });
  req.session.buildingId = buildingId;
  res.json({ ok: true });
});

app.get('/api/client/buildings', async (req, res) => {
  if (!req.session.clientId && !req.session.superAdmin) return res.status(401).json({ error: 'אין הרשאה' });
  const cid = req.session.clientId;
  if (!cid) return res.json([]);
  const { rows } = await pool.query('SELECT id, name FROM buildings WHERE client_id=$1 ORDER BY name', [cid]);
  res.json(rows);
});

// --- חדשות (Ynet RSS) ---
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

// Ynet RSS עובד מ-Railway (ישראל היום חוסמת)
let newsCache = [], newsCacheTime = 0;
async function fetchNews() {
  try {
    const r = await fetch('https://www.ynet.co.il/Integration/StoryRss2.xml', { headers: { 'User-Agent': UA } });
    const xml = await r.text();
    const result = await xml2js.parseStringPromise(xml);
    const items = result.rss.channel[0].item.slice(0, 10);
    newsCache = items.map(i => ({
      title: i.title[0],
      link: i.link?.[0] || '',
      pubDate: i.pubDate?.[0] || '',
      image: ''
    }));
    newsCacheTime = Date.now();
    // fetch og:images in background (don't block)
    Promise.all(newsCache.map((item, idx) =>
      item.link ? fetchOgImage(item.link).then(img => { newsCache[idx].image = img; }) : Promise.resolve()
    )).catch(() => {});
    console.log('חדשות ynet: נטענו', newsCache.length, 'כתבות');
  } catch(e) { console.log('שגיאה ynet:', e.message); }
}
fetchNews();
setInterval(fetchNews, 5 * 60 * 1000);

// שני endpoint-ים מגישים את אותו המידע
app.get('/api/israelhayom', async (req, res) => {
  if (Date.now() - newsCacheTime > 5 * 60 * 1000) await fetchNews();
  ilHayomCache = newsCache; ilHayomCacheTime = newsCacheTime;
  res.json(ilHayomCache);
});
app.get('/api/news', async (req, res) => {
  if (Date.now() - newsCacheTime > 5 * 60 * 1000) await fetchNews();
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
  const bid = req.params.bid;
  const today = new Date().toISOString().split('T')[0];
  const { rows: local } = await pool.query(
    `SELECT id, title, type, url, duration, sort_order FROM ads
     WHERE building_id=$1 AND active=true
     AND (start_date IS NULL OR start_date <= $2)
     AND (end_date IS NULL OR end_date >= $2)
     ORDER BY sort_order, id`, [bid, today]);
  const { rows: global } = await pool.query(
    `SELECT ga.id, ga.title, ga.type, ga.url, ga.duration, gab.sort_order
     FROM global_ads ga
     JOIN global_ad_buildings gab ON gab.global_ad_id=ga.id AND gab.building_id=$1
     WHERE ga.active=true AND gab.active=true
     AND (ga.start_date IS NULL OR ga.start_date <= $2)
     AND (ga.end_date IS NULL OR ga.end_date >= $2)
     ORDER BY gab.sort_order, ga.id`, [bid, today]);
  const merged = [...local, ...global].sort((a,b) => (a.sort_order||999)-(b.sort_order||999));
  res.json(merged.map(r => ({ id: r.id, title: r.title, type: r.type, url: r.url, duration: r.duration })));
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
  const bid = req.params.bid;
  const { rows: local } = await pool.query(
    'SELECT *, false AS is_global FROM ads WHERE building_id=$1 ORDER BY sort_order, id', [bid]);
  const { rows: global } = await pool.query(
    `SELECT ga.*, true AS is_global, gab.sort_order AS gab_sort, gab.active AS gab_active
     FROM global_ads ga
     JOIN global_ad_buildings gab ON gab.global_ad_id=ga.id AND gab.building_id=$1
     ORDER BY gab.sort_order, ga.id`, [bid]);
  const localMapped = local.map(r => ({
    id: r.id, title: r.title, type: r.type, url: r.url, duration: r.duration,
    active: r.active, sort_order: r.sort_order,
    start_date: r.start_date, end_date: r.end_date,
    advertiser_name: r.advertiser_name, advertiser_phone: r.advertiser_phone, advertiser_email: r.advertiser_email,
    is_global: false
  }));
  const globalMapped = global.map(r => ({
    id: r.id, title: r.title, type: r.type, url: r.url, duration: r.duration,
    active: r.gab_active, sort_order: r.gab_sort,
    start_date: r.start_date, end_date: r.end_date,
    advertiser_name: r.advertiser_name, advertiser_phone: r.advertiser_phone, advertiser_email: r.advertiser_email,
    is_global: true
  }));
  res.json([...localMapped, ...globalMapped].sort((a,b) => (a.sort_order||999)-(b.sort_order||999)));
});
app.post('/api/:bid/ads', requireAdsAuth, upload.single('file'), async (req, res) => {
  const id  = Date.now();
  const url = req.file ? (req.file.secure_url || req.file.path || '') : (req.body.url || '');
  const { rows } = await pool.query(
    `INSERT INTO ads (id, building_id, title, type, url, duration, active, start_date, end_date, advertiser_name, advertiser_phone, advertiser_email)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
    [id, req.params.bid, req.body.title || '', req.body.type || 'image', url, parseInt(req.body.duration) || 6, true,
     req.body.start_date || null, req.body.end_date || null,
     req.body.advertiser_name || '', req.body.advertiser_phone || '', req.body.advertiser_email || '']
  );
  const r = rows[0];
  res.json({ id: r.id, title: r.title, type: r.type, url: r.url, duration: r.duration, active: r.active });
});
app.put('/api/:bid/ads/:id', requireAdsAuth, async (req, res) => {
  const { active, title, duration, start_date, end_date, advertiser_name, advertiser_phone, advertiser_email } = req.body;
  if (title !== undefined) {
    await pool.query(
      `UPDATE ads SET title=$1, duration=$2, start_date=$3, end_date=$4,
       advertiser_name=$5, advertiser_phone=$6, advertiser_email=$7 WHERE id=$8 AND building_id=$9`,
      [title||'', parseInt(duration)||6, start_date||null, end_date||null,
       advertiser_name||'', advertiser_phone||'', advertiser_email||'', req.params.id, req.params.bid]
    );
  } else {
    await pool.query('UPDATE ads SET active=$1 WHERE id=$2 AND building_id=$3',
      [active === 'true' || active === true, req.params.id, req.params.bid]);
  }
  res.json({ ok: true });
});
app.delete('/api/:bid/ads/:id', requireAdsAuth, async (req, res) => {
  await pool.query('DELETE FROM ads WHERE id=$1 AND building_id=$2', [req.params.id, req.params.bid]);
  res.json({ ok: true });
});
app.post('/api/:bid/ads/reorder', requireAdsAuth, async (req, res) => {
  const { id, direction } = req.body;
  const { rows } = await pool.query('SELECT * FROM ads WHERE building_id=$1 ORDER BY sort_order, id', [req.params.bid]);
  const idx = rows.findIndex(a => a.id == id);
  if (idx === -1) return res.json({ ok: false });
  const ni = direction === 'up' ? idx - 1 : idx + 1;
  if (ni < 0 || ni >= rows.length) return res.json({ ok: false });
  await pool.query('UPDATE ads SET sort_order=$1 WHERE id=$2', [ni, rows[idx].id]);
  await pool.query('UPDATE ads SET sort_order=$1 WHERE id=$2', [idx, rows[ni].id]);
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

// מנהל-על: ניהול פרסומות בניין
app.get('/api/superadmin/buildings/:id/ads', requireSuper, async (req, res) => {
  const bid = req.params.id;
  const { rows: local } = await pool.query(
    'SELECT * FROM ads WHERE building_id=$1 ORDER BY sort_order, id', [bid]);
  const { rows: global } = await pool.query(
    `SELECT ga.*, gab.sort_order AS gab_sort, gab.active AS gab_active, gab.id AS gab_id
     FROM global_ads ga
     JOIN global_ad_buildings gab ON gab.global_ad_id=ga.id AND gab.building_id=$1
     ORDER BY gab.sort_order, ga.id`, [bid]);
  const localMapped = local.map(r => ({
    id: r.id, title: r.title, type: r.type, url: r.url, duration: r.duration, active: r.active,
    sort_order: r.sort_order, start_date: r.start_date, end_date: r.end_date,
    advertiser_name: r.advertiser_name, advertiser_phone: r.advertiser_phone, advertiser_email: r.advertiser_email,
    is_global: false
  }));
  const globalMapped = global.map(r => ({
    id: r.id, title: r.title, type: r.type, url: r.url, duration: r.duration, active: r.gab_active,
    sort_order: r.gab_sort, start_date: r.start_date, end_date: r.end_date,
    advertiser_name: r.advertiser_name, advertiser_phone: r.advertiser_phone, advertiser_email: r.advertiser_email,
    is_global: true, gab_id: r.gab_id
  }));
  res.json([...localMapped, ...globalMapped].sort((a,b) => (a.sort_order||999)-(b.sort_order||999)));
});
app.post('/api/superadmin/buildings/:id/ads', requireSuper, upload.single('file'), async (req, res) => {
  const id  = Date.now();
  const url = req.file ? (req.file.secure_url || req.file.path || '') : (req.body.url || '');
  const { rows } = await pool.query(
    `INSERT INTO ads (id, building_id, title, type, url, duration, active, start_date, end_date, advertiser_name, advertiser_phone, advertiser_email)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
    [id, req.params.id, req.body.title || '', req.body.type || 'image', url, parseInt(req.body.duration) || 6, true,
     req.body.start_date || null, req.body.end_date || null,
     req.body.advertiser_name || '', req.body.advertiser_phone || '', req.body.advertiser_email || '']
  );
  const r = rows[0];
  res.json({ id: r.id, title: r.title, type: r.type, url: r.url, duration: r.duration, active: r.active });
});
app.put('/api/superadmin/buildings/:id/ads/:adId', requireSuper, async (req, res) => {
  const { active, title, duration, start_date, end_date, advertiser_name, advertiser_phone, advertiser_email } = req.body;
  if (title !== undefined) {
    await pool.query(
      `UPDATE ads SET title=$1, duration=$2, start_date=$3, end_date=$4,
       advertiser_name=$5, advertiser_phone=$6, advertiser_email=$7 WHERE id=$8 AND building_id=$9`,
      [title||'', parseInt(duration)||6, start_date||null, end_date||null,
       advertiser_name||'', advertiser_phone||'', advertiser_email||'', req.params.adId, req.params.id]
    );
  } else {
    await pool.query('UPDATE ads SET active=$1 WHERE id=$2 AND building_id=$3',
      [active === 'true' || active === true, req.params.adId, req.params.id]);
  }
  res.json({ ok: true });
});
app.delete('/api/superadmin/buildings/:id/ads/:adId', requireSuper, async (req, res) => {
  await pool.query('DELETE FROM ads WHERE id=$1 AND building_id=$2', [req.params.adId, req.params.id]);
  res.json({ ok: true });
});
app.post('/api/superadmin/buildings/:id/ads/reorder', requireSuper, async (req, res) => {
  const { adId, direction } = req.body;
  const { rows } = await pool.query('SELECT * FROM ads WHERE building_id=$1 ORDER BY sort_order, id', [req.params.id]);
  const idx = rows.findIndex(a => a.id == adId);
  if (idx === -1) return res.json({ ok: false });
  const ni = direction === 'up' ? idx - 1 : idx + 1;
  if (ni < 0 || ni >= rows.length) return res.json({ ok: false });
  await pool.query('UPDATE ads SET sort_order=$1 WHERE id=$2', [ni, rows[idx].id]);
  await pool.query('UPDATE ads SET sort_order=$1 WHERE id=$2', [idx, rows[ni].id]);
  res.json({ ok: true });
});
// toggle global ad active state for a specific building
app.post('/api/superadmin/buildings/:id/global-ads/:gid/toggle', requireSuper, async (req, res) => {
  await pool.query('UPDATE global_ad_buildings SET active=$1 WHERE global_ad_id=$2 AND building_id=$3',
    [req.body.active, req.params.gid, req.params.id]);
  res.json({ ok: true });
});

// --- פרסומות גלובליות ---
app.get('/api/superadmin/global-ads', requireSuper, async (req, res) => {
  const { rows: ads } = await pool.query('SELECT * FROM global_ads ORDER BY created_at DESC, id DESC');
  const { rows: bldgs } = await pool.query(
    'SELECT global_ad_id, building_id, active FROM global_ad_buildings');
  const { rows: allBuildings } = await pool.query('SELECT id, name FROM buildings ORDER BY name');
  const bldgMap = {};
  bldgs.forEach(b => {
    if (!bldgMap[b.global_ad_id]) bldgMap[b.global_ad_id] = [];
    bldgMap[b.global_ad_id].push({ building_id: b.building_id, active: b.active });
  });
  res.json(ads.map(r => ({
    id: r.id, title: r.title, type: r.type, url: r.url, duration: r.duration, active: r.active,
    start_date: r.start_date, end_date: r.end_date,
    advertiser_name: r.advertiser_name, advertiser_phone: r.advertiser_phone, advertiser_email: r.advertiser_email,
    created_at: r.created_at,
    buildings: bldgMap[r.id] || []
  })));
});

app.post('/api/superadmin/global-ads', requireSuper, upload.single('file'), async (req, res) => {
  const id  = Date.now();
  const url = req.file ? (req.file.secure_url || req.file.path || '') : (req.body.url || '');
  const { rows } = await pool.query(
    `INSERT INTO global_ads (id, title, type, url, duration, active, start_date, end_date, advertiser_name, advertiser_phone, advertiser_email)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
    [id, req.body.title || '', req.body.type || 'image', url, parseInt(req.body.duration) || 6, true,
     req.body.start_date || null, req.body.end_date || null,
     req.body.advertiser_name || '', req.body.advertiser_phone || '', req.body.advertiser_email || '']
  );
  // assign to buildings
  const buildingIds = req.body.building_ids ? JSON.parse(req.body.building_ids) : [];
  for (let i = 0; i < buildingIds.length; i++) {
    await pool.query(
      'INSERT INTO global_ad_buildings (id, global_ad_id, building_id) VALUES ($1,$2,$3) ON CONFLICT (global_ad_id, building_id) DO NOTHING',
      [id + i + 1, id, buildingIds[i]]
    );
  }
  const r = rows[0];
  res.json({ id: r.id, title: r.title, type: r.type, url: r.url, duration: r.duration, active: r.active, buildings: buildingIds.map(b=>({building_id:b,active:true})) });
});

app.put('/api/superadmin/global-ads/:id', requireSuper, async (req, res) => {
  const { title, duration, start_date, end_date, advertiser_name, advertiser_phone, advertiser_email, active } = req.body;
  await pool.query(
    `UPDATE global_ads SET title=$1, duration=$2, start_date=$3, end_date=$4,
     advertiser_name=$5, advertiser_phone=$6, advertiser_email=$7, active=$8 WHERE id=$9`,
    [title||'', parseInt(duration)||6, start_date||null, end_date||null,
     advertiser_name||'', advertiser_phone||'', advertiser_email||'',
     active !== false && active !== 'false', req.params.id]
  );
  // update building assignments
  if (req.body.building_ids !== undefined) {
    const buildingIds = JSON.parse(req.body.building_ids);
    await pool.query('DELETE FROM global_ad_buildings WHERE global_ad_id=$1', [req.params.id]);
    for (const bid of buildingIds) {
      await pool.query(
        'INSERT INTO global_ad_buildings (id, global_ad_id, building_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING',
        [Date.now() + Math.random(), req.params.id, bid]
      );
    }
  }
  res.json({ ok: true });
});

app.delete('/api/superadmin/global-ads/:id', requireSuper, async (req, res) => {
  await pool.query('DELETE FROM global_ads WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

app.get('/api/superadmin/global-ads/:id/buildings', requireSuper, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT gab.building_id, gab.active, b.name
     FROM global_ad_buildings gab JOIN buildings b ON b.id=gab.building_id
     WHERE gab.global_ad_id=$1`, [req.params.id]);
  res.json(rows);
});

// כל הפרסומות לפי בניין (לתצוגה מאוחדת - מקומיות + גלובליות)
app.get('/api/superadmin/all-ads', requireSuper, async (req, res) => {
  const { rows: buildings } = await pool.query('SELECT id, name FROM buildings ORDER BY name');
  const { rows: localAds } = await pool.query('SELECT * FROM ads ORDER BY building_id, sort_order, id');
  const { rows: globalAds } = await pool.query(
    `SELECT ga.id, ga.title, ga.type, ga.url, ga.duration, ga.start_date, ga.end_date,
     ga.advertiser_name, ga.advertiser_phone, gab.building_id, gab.active AS gab_active, gab.sort_order AS gab_sort
     FROM global_ads ga
     JOIN global_ad_buildings gab ON gab.global_ad_id = ga.id
     ORDER BY gab.building_id, gab.sort_order, ga.id`
  );
  const byBuilding = {};
  buildings.forEach(b => { byBuilding[b.id] = { id: b.id, name: b.name, ads: [] }; });
  localAds.forEach(a => {
    if (byBuilding[a.building_id]) byBuilding[a.building_id].ads.push({
      id: a.id, title: a.title, type: a.type, url: a.url, duration: a.duration,
      active: a.active, start_date: a.start_date, end_date: a.end_date,
      advertiser_name: a.advertiser_name, advertiser_phone: a.advertiser_phone,
      sort_order: a.sort_order, is_global: false
    });
  });
  globalAds.forEach(a => {
    if (byBuilding[a.building_id]) byBuilding[a.building_id].ads.push({
      id: a.id, title: a.title, type: a.type, url: a.url, duration: a.duration,
      active: a.gab_active, start_date: a.start_date, end_date: a.end_date,
      advertiser_name: a.advertiser_name, advertiser_phone: a.advertiser_phone,
      sort_order: a.gab_sort, is_global: true
    });
  });
  // sort each building's ads by sort_order
  Object.values(byBuilding).forEach(b => {
    b.ads.sort((x,y) => (x.sort_order||999)-(y.sort_order||999));
  });
  res.json(Object.values(byBuilding).filter(b => b.ads.length > 0));
});

// מיון פרסומת גלובלית בתוך בניין
app.post('/api/superadmin/buildings/:id/global-ads/reorder', requireSuper, async (req, res) => {
  const { gid, direction } = req.body;
  const { rows } = await pool.query(
    'SELECT * FROM global_ad_buildings WHERE building_id=$1 ORDER BY sort_order, global_ad_id',
    [req.params.id]
  );
  const idx = rows.findIndex(r => r.global_ad_id == gid);
  if (idx === -1) return res.json({ ok: false });
  const ni = direction === 'up' ? idx - 1 : idx + 1;
  if (ni < 0 || ni >= rows.length) return res.json({ ok: false });
  await pool.query('UPDATE global_ad_buildings SET sort_order=$1 WHERE global_ad_id=$2 AND building_id=$3',
    [ni, rows[idx].global_ad_id, req.params.id]);
  await pool.query('UPDATE global_ad_buildings SET sort_order=$1 WHERE global_ad_id=$2 AND building_id=$3',
    [idx, rows[ni].global_ad_id, req.params.id]);
  res.json({ ok: true });
});

// --- לקוחות (מנהל-על) ---
app.get('/api/superadmin/clients', requireSuper, async (req, res) => {
  const { rows: clients } = await pool.query('SELECT id, name, email FROM clients ORDER BY name');
  const { rows: bldgs }   = await pool.query('SELECT id, name, client_id FROM buildings WHERE client_id IS NOT NULL');
  const map = {};
  bldgs.forEach(b => { if (!map[b.client_id]) map[b.client_id] = []; map[b.client_id].push({ id: b.id, name: b.name }); });
  res.json(clients.map(c => ({ ...c, buildings: map[c.id] || [] })));
});

app.post('/api/superadmin/clients', requireSuper, async (req, res) => {
  const { id, password, name, email } = req.body;
  if (!id || !password) return res.status(400).json({ error: 'נא למלא מזהה וסיסמה' });
  const { rows: ex } = await pool.query('SELECT id FROM clients WHERE id=$1', [id]);
  if (ex.length) return res.status(400).json({ error: 'מזהה לקוח כבר קיים' });
  await pool.query('INSERT INTO clients (id, password_hash, name, email) VALUES ($1,$2,$3,$4)',
    [id, bcrypt.hashSync(password, 10), name || '', email || '']);
  res.json({ ok: true, id });
});

app.put('/api/superadmin/clients/:id', requireSuper, async (req, res) => {
  const { name, email, password } = req.body;
  if (password) {
    await pool.query('UPDATE clients SET name=$1, email=$2, password_hash=$3 WHERE id=$4',
      [name||'', email||'', bcrypt.hashSync(password, 10), req.params.id]);
  } else {
    await pool.query('UPDATE clients SET name=$1, email=$2 WHERE id=$3', [name||'', email||'', req.params.id]);
  }
  res.json({ ok: true });
});

app.delete('/api/superadmin/clients/:id', requireSuper, async (req, res) => {
  await pool.query('UPDATE buildings SET client_id=NULL WHERE client_id=$1', [req.params.id]);
  await pool.query('DELETE FROM clients WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

// שיוך בניין ללקוח
app.post('/api/superadmin/clients/:id/assign-building', requireSuper, async (req, res) => {
  await pool.query('UPDATE buildings SET client_id=$1 WHERE id=$2', [req.params.id, req.body.buildingId]);
  res.json({ ok: true });
});
app.post('/api/superadmin/clients/:id/unassign-building', requireSuper, async (req, res) => {
  await pool.query('UPDATE buildings SET client_id=NULL WHERE id=$1 AND client_id=$2', [req.body.buildingId, req.params.id]);
  res.json({ ok: true });
});

// --- דפים ---
app.get('/login',             (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/select-building',   (req, res) => res.sendFile(path.join(__dirname, 'public', 'select-building.html')));
app.get('/screen/:bid',       (req, res) => res.sendFile(path.join(__dirname, 'public', 'screen.html')));
app.get('/admin',             (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'super.html')));
app.get('/admin/:bid',        (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'index.html')));
app.get('/screen',            (req, res) => res.redirect('/screen/203991203'));

app.use(express.static('public'));

// --- Start ---
initDB().then(() => {
  app.listen(PORT, () => console.log(`שרת רץ על פורט ${PORT}`));
}).catch(err => {
  console.error('שגיאה בחיבור ל-DB:', err.message);
  process.exit(1);
});
