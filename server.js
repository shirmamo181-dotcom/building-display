require('dotenv').config();
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const fetch = require('node-fetch');
const xml2js = require('xml2js');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

const SUPER_USER      = process.env.SUPER_ADMIN_USER     || 'superadmin';
const SUPER_PASS_HASH = bcrypt.hashSync(process.env.SUPER_ADMIN_PASSWORD || 'super123', 10);

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => ({
    folder: 'building-display',
    resource_type: file.mimetype.startsWith('video') ? 'video' : 'image',
    allowed_formats: ['jpg', 'jpeg', 'png', 'gif', 'mp4', 'mov', 'webm'],
  }),
});
const upload = multer({ storage });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'building-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// --- נתונים ---
const BUILDINGS_PATH = path.join(__dirname, 'data', 'buildings.json');
const bDir  = (bid)       => path.join(__dirname, 'data', 'buildings', bid);
const bFile = (bid, file) => path.join(bDir(bid), file);

const DEFAULT_DATA = {
  'businesses.json': [],
  'ads.json':        [],
  'updates.json':    [],
  'settings.json':   { buildingName: 'מרכז עסקים' },
  'theme.json':      { theme: 'wood' },
};

function readBuildings() {
  if (!fs.existsSync(BUILDINGS_PATH)) return [];
  return JSON.parse(fs.readFileSync(BUILDINGS_PATH, 'utf8'));
}
function writeBuildings(data) { fs.writeFileSync(BUILDINGS_PATH, JSON.stringify(data, null, 2)); }

function readBData(bid, file) {
  const p = bFile(bid, file);
  if (!fs.existsSync(p)) return DEFAULT_DATA[file] ?? null;
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}
function writeBData(bid, file, data) { fs.writeFileSync(bFile(bid, file), JSON.stringify(data, null, 2)); }

// הפעלה: hash סיסמאות, צור תיקיות חסרות
(function initBuildings() {
  if (!fs.existsSync(BUILDINGS_PATH)) { fs.writeFileSync(BUILDINGS_PATH, '[]'); return; }
  let buildings = readBuildings();
  let changed = false;
  buildings.forEach(b => {
    if (!fs.existsSync(bDir(b.id))) fs.mkdirSync(bDir(b.id), { recursive: true });
    if (b.password && !b.passwordHash) {
      b.passwordHash = bcrypt.hashSync(b.password, 10);
      delete b.password;
      changed = true;
    }
  });
  if (changed) writeBuildings(buildings);
  console.log(`נטענו ${buildings.length} בניינים`);
})();

// --- Auth middleware ---
function requireSuper(req, res, next) {
  if (req.session.superAdmin) return next();
  res.status(401).json({ error: 'נדרשת כניסה כמנהל-על' });
}

function requireBuilding(req, res, next) {
  const bid = req.params.bid;
  if (req.session.superAdmin || req.session.buildingId === bid) return next();
  res.status(401).json({ error: 'אין הרשאה' });
}

function requireAdsAuth(req, res, next) {
  const bid = req.params.bid;
  if (req.session.superAdmin) return next();
  if (req.session.buildingId !== bid) return res.status(401).json({ error: 'אין הרשאה' });
  const b = readBuildings().find(b => b.id === bid);
  if (b && b.canManageAds) return next();
  res.status(403).json({ error: 'ניהול פרסומות אינו מופעל לבניין זה' });
}

// --- Login / Auth ---
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (username === SUPER_USER && bcrypt.compareSync(password, SUPER_PASS_HASH)) {
    req.session.superAdmin = true;
    req.session.buildingId = null;
    return res.json({ ok: true, role: 'superadmin' });
  }
  const b = readBuildings().find(b => b.id === username);
  if (b && bcrypt.compareSync(password, b.passwordHash)) {
    req.session.buildingId = b.id;
    req.session.superAdmin = false;
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

async function fetchOgImage(url) {
  try {
    const r = await fetch(url, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
      signal: AbortSignal.timeout(5000)
    });
    const html = await r.text();
    const m = html.match(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']/i)
           || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:image["']/i);
    return m ? m[1] : '';
  } catch(e) { return ''; }
}

async function fetchIsraelHayom() {
  try {
    const r = await fetch('https://www.israelhayom.co.il/rss.xml', {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
    });
    const xml = await r.text();
    const result = await xml2js.parseStringPromise(xml);
    const items = result.rss.channel[0].item.slice(0, 10).map(i => ({
      title: i.title[0],
      link: i.link ? i.link[0] : '',
      pubDate: i.pubDate ? i.pubDate[0] : '',
      image: ''
    }));
    // חילוץ תמונות og:image במקביל מכל כתבה
    const images = await Promise.all(items.map(i => i.link ? fetchOgImage(i.link) : Promise.resolve('')));
    items.forEach((item, idx) => { item.image = images[idx]; });
    ilHayomCache = items;
    ilHayomCacheTime = Date.now();
    console.log('ישראל היום עודכן:', ilHayomCache.length, 'פריטים, תמונות:', images.filter(Boolean).length);
  } catch(e) { console.log('שגיאה ישראל היום:', e.message); }
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
    const r = await fetch('https://www.ynet.co.il/Integration/StoryRss2.xml', {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
    });
    const xml = await r.text();
    const result = await xml2js.parseStringPromise(xml);
    newsCache = result.rss.channel[0].item.slice(0, 15).map(i => ({
      title: i.title[0], pubDate: i.pubDate ? i.pubDate[0] : ''
    }));
    newsCacheTime = Date.now();
    console.log('ynet עודכן:', newsCache.length, 'פריטים');
  } catch (e) { console.log('שגיאה ynet:', e.message); }
}
fetchNews();
setInterval(fetchNews, 2 * 60 * 1000);

app.get('/api/news', async (req, res) => {
  if (Date.now() - newsCacheTime > 2 * 60 * 1000) await fetchNews();
  res.json(newsCache);
});

// --- ממשקי בניין ציבוריים ---
app.get('/api/:bid/businesses', (req, res) => res.json(readBData(req.params.bid, 'businesses.json') || []));
app.get('/api/:bid/updates',    (req, res) => res.json(readBData(req.params.bid, 'updates.json')    || []));
app.get('/api/:bid/settings',   (req, res) => res.json(readBData(req.params.bid, 'settings.json')   || {}));
app.get('/api/:bid/theme',      (req, res) => res.json(readBData(req.params.bid, 'theme.json')      || { theme: 'wood' }));
app.get('/api/:bid/ads',        (req, res) => res.json((readBData(req.params.bid, 'ads.json') || []).filter(a => a.active)));

// --- עסקים ---
app.post('/api/:bid/businesses', requireBuilding, (req, res) => {
  const list = readBData(req.params.bid, 'businesses.json') || [];
  const item = { id: Date.now(), name: req.body.name, office: req.body.office, floor: req.body.floor || '', description: req.body.description || '' };
  list.push(item);
  writeBData(req.params.bid, 'businesses.json', list);
  res.json(item);
});
app.put('/api/:bid/businesses/:id', requireBuilding, (req, res) => {
  let list = readBData(req.params.bid, 'businesses.json') || [];
  list = list.map(b => b.id == req.params.id ? { ...b, ...req.body } : b);
  writeBData(req.params.bid, 'businesses.json', list);
  res.json({ ok: true });
});
app.delete('/api/:bid/businesses/:id', requireBuilding, (req, res) => {
  const list = (readBData(req.params.bid, 'businesses.json') || []).filter(b => b.id != req.params.id);
  writeBData(req.params.bid, 'businesses.json', list);
  res.json({ ok: true });
});

// --- עדכוני בניין ---
app.post('/api/:bid/updates', requireBuilding, (req, res) => {
  const list = readBData(req.params.bid, 'updates.json') || [];
  const item = { id: Date.now(), text: req.body.text, image: req.body.image || '' };
  list.push(item);
  writeBData(req.params.bid, 'updates.json', list);
  res.json(item);
});
app.put('/api/:bid/updates/:id', requireBuilding, (req, res) => {
  let list = readBData(req.params.bid, 'updates.json') || [];
  list = list.map(u => u.id == req.params.id ? { ...u, ...req.body } : u);
  writeBData(req.params.bid, 'updates.json', list);
  res.json({ ok: true });
});
app.delete('/api/:bid/updates/:id', requireBuilding, (req, res) => {
  const list = (readBData(req.params.bid, 'updates.json') || []).filter(u => u.id != req.params.id);
  writeBData(req.params.bid, 'updates.json', list);
  res.json({ ok: true });
});
app.post('/api/:bid/updates/reorder', requireBuilding, (req, res) => {
  const { id, direction } = req.body;
  let list = readBData(req.params.bid, 'updates.json') || [];
  const idx = list.findIndex(u => u.id == id);
  if (idx === -1) return res.json({ ok: false });
  const ni = direction === 'up' ? idx - 1 : idx + 1;
  if (ni < 0 || ni >= list.length) return res.json({ ok: false });
  [list[idx], list[ni]] = [list[ni], list[idx]];
  writeBData(req.params.bid, 'updates.json', list);
  res.json({ ok: true });
});

// --- פרסומות ---
app.get('/api/:bid/ads/all', requireBuilding, (req, res) => res.json(readBData(req.params.bid, 'ads.json') || []));

app.post('/api/:bid/ads', requireAdsAuth, upload.single('file'), (req, res) => {
  const list = readBData(req.params.bid, 'ads.json') || [];
  const url  = req.file ? (req.file.secure_url || req.file.path || '') : (req.body.url || '');
  const item = { id: Date.now(), title: req.body.title, type: req.body.type, url, duration: parseInt(req.body.duration) || 6, active: req.body.active === 'true' };
  list.push(item);
  writeBData(req.params.bid, 'ads.json', list);
  res.json(item);
});
app.put('/api/:bid/ads/:id', requireAdsAuth, (req, res) => {
  let list = readBData(req.params.bid, 'ads.json') || [];
  list = list.map(a => a.id == req.params.id ? { ...a, ...req.body, active: req.body.active === 'true' } : a);
  writeBData(req.params.bid, 'ads.json', list);
  res.json({ ok: true });
});
app.delete('/api/:bid/ads/:id', requireAdsAuth, (req, res) => {
  const list = (readBData(req.params.bid, 'ads.json') || []).filter(a => a.id != req.params.id);
  writeBData(req.params.bid, 'ads.json', list);
  res.json({ ok: true });
});

// --- הגדרות וערכת נושא ---
app.post('/api/:bid/settings', requireBuilding, (req, res) => {
  const cur = readBData(req.params.bid, 'settings.json') || {};
  writeBData(req.params.bid, 'settings.json', { ...cur, ...req.body });
  res.json({ ok: true });
});
app.post('/api/:bid/theme', requireBuilding, (req, res) => {
  writeBData(req.params.bid, 'theme.json', { theme: req.body.theme });
  res.json({ ok: true });
});

// --- שינוי סיסמה ---
app.post('/api/:bid/change-password', requireBuilding, (req, res) => {
  if (req.session.superAdmin) return res.status(403).json({ error: 'מנהל-על לא יכול לשנות סיסמת בניין מכאן' });
  const { oldPassword, newPassword } = req.body;
  let buildings = readBuildings();
  const idx = buildings.findIndex(b => b.id === req.params.bid);
  if (idx === -1) return res.status(404).json({ error: 'בניין לא נמצא' });
  if (!bcrypt.compareSync(oldPassword, buildings[idx].passwordHash))
    return res.status(401).json({ error: 'סיסמה ישנה שגויה' });
  buildings[idx].passwordHash = bcrypt.hashSync(newPassword, 10);
  writeBuildings(buildings);
  res.json({ ok: true });
});

// --- פרטי בניין ---
app.get('/api/:bid/building-info', requireBuilding, (req, res) => {
  const b = readBuildings().find(b => b.id === req.params.bid);
  if (!b) return res.status(404).json({ error: 'לא נמצא' });
  res.json({ id: b.id, name: b.name, email: b.email, canManageAds: b.canManageAds, createdAt: b.createdAt });
});

// --- מנהל-על: ניהול בניינים ---
app.get('/api/superadmin/buildings', requireSuper, (req, res) => {
  res.json(readBuildings().map(({ passwordHash, ...safe }) => safe));
});

app.post('/api/superadmin/buildings', requireSuper, (req, res) => {
  const buildings = readBuildings();
  if (buildings.find(b => b.id === req.body.id))
    return res.status(400).json({ error: 'בניין עם ת"ז זו כבר קיים' });
  const building = {
    id: req.body.id,
    passwordHash: bcrypt.hashSync(req.body.password, 10),
    name: req.body.name,
    email: req.body.email || '',
    canManageAds: false,
    createdAt: new Date().toISOString().split('T')[0]
  };
  fs.mkdirSync(bDir(building.id), { recursive: true });
  writeBData(building.id, 'businesses.json', []);
  writeBData(building.id, 'ads.json', []);
  writeBData(building.id, 'updates.json', []);
  writeBData(building.id, 'settings.json', { buildingName: building.name });
  writeBData(building.id, 'theme.json', { theme: 'wood' });
  buildings.push(building);
  writeBuildings(buildings);
  const { passwordHash, ...safe } = building;
  res.json(safe);
});

app.put('/api/superadmin/buildings/:id', requireSuper, (req, res) => {
  let buildings = readBuildings();
  const idx = buildings.findIndex(b => b.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'לא נמצא' });
  const update = { ...req.body };
  if (update.password) { update.passwordHash = bcrypt.hashSync(update.password, 10); delete update.password; }
  buildings[idx] = { ...buildings[idx], ...update };
  writeBuildings(buildings);
  res.json({ ok: true });
});

app.delete('/api/superadmin/buildings/:id', requireSuper, (req, res) => {
  writeBuildings(readBuildings().filter(b => b.id !== req.params.id));
  res.json({ ok: true });
});

// מנהל-על: ניהול פרסומות לבניין
app.get('/api/superadmin/buildings/:id/ads', requireSuper, (req, res) => {
  res.json(readBData(req.params.id, 'ads.json') || []);
});
app.post('/api/superadmin/buildings/:id/ads', requireSuper, upload.single('file'), (req, res) => {
  const list = readBData(req.params.id, 'ads.json') || [];
  const url  = req.file ? (req.file.secure_url || req.file.path || '') : (req.body.url || '');
  const item = { id: Date.now(), title: req.body.title, type: req.body.type, url, duration: parseInt(req.body.duration) || 6, active: req.body.active === 'true' };
  list.push(item);
  writeBData(req.params.id, 'ads.json', list);
  res.json(item);
});
app.put('/api/superadmin/buildings/:id/ads/:adId', requireSuper, (req, res) => {
  let list = readBData(req.params.id, 'ads.json') || [];
  list = list.map(a => a.id == req.params.adId ? { ...a, ...req.body, active: req.body.active === 'true' } : a);
  writeBData(req.params.id, 'ads.json', list);
  res.json({ ok: true });
});
app.delete('/api/superadmin/buildings/:id/ads/:adId', requireSuper, (req, res) => {
  const list = (readBData(req.params.id, 'ads.json') || []).filter(a => a.id != req.params.adId);
  writeBData(req.params.id, 'ads.json', list);
  res.json({ ok: true });
});

// --- דפים (לפני static כדי שלא יתנגשו עם public/admin/index.html) ---
app.get('/login',       (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/screen/:bid', (req, res) => res.sendFile(path.join(__dirname, 'public', 'screen.html')));
app.get('/admin',       (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'super.html')));
app.get('/admin/:bid',  (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'index.html')));
app.get('/screen',      (req, res) => res.redirect('/screen/203991203'));

app.use(express.static('public'));

app.listen(PORT, () => console.log(`שרת רץ על פורט ${PORT}`));
