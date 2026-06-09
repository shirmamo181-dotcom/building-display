const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const fetch = require('node-fetch');
const xml2js = require('xml2js');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD_HASH = bcrypt.hashSync('admin123', 10); // שני תשנה את זה

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use(session({ secret: 'building-secret-key', resave: false, saveUninitialized: false }));

const upload = multer({ dest: 'uploads/' });

// --- נתונים ---
const dataPath = (file) => path.join(__dirname, 'data', file);
const readData = (file) => JSON.parse(fs.readFileSync(dataPath(file), 'utf8'));
const writeData = (file, data) => fs.writeFileSync(dataPath(file), JSON.stringify(data, null, 2));

// --- מבזקי ynet (מתעדכן כל 10 דקות) ---
let newsCache = [];
async function fetchNews() {
  try {
    const res = await fetch('https://www.ynet.co.il/Integration/StoryRss2.xml');
    const xml = await res.text();
    const result = await xml2js.parseStringPromise(xml);
    newsCache = result.rss.channel[0].item.slice(0, 15).map(i => i.title[0]);
  } catch (e) {
    console.log('שגיאה בשליפת ynet:', e.message);
  }
}
fetchNews();
setInterval(fetchNews, 10 * 60 * 1000);

// --- API ---
app.get('/api/businesses', (req, res) => res.json(readData('businesses.json')));
app.get('/api/updates', (req, res) => res.json(readData('updates.json')));
app.get('/api/ads', (req, res) => res.json(readData('ads.json').filter(a => a.active)));
app.get('/api/news', (req, res) => res.json(newsCache));

// --- Admin auth ---
function requireAuth(req, res, next) {
  if (req.session.admin) return next();
  res.status(401).json({ error: 'לא מחובר' });
}

app.post('/api/login', (req, res) => {
  if (bcrypt.compareSync(req.body.password, ADMIN_PASSWORD_HASH)) {
    req.session.admin = true;
    res.json({ ok: true });
  } else {
    res.status(401).json({ error: 'סיסמה שגויה' });
  }
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ ok: true }); });

// --- עסקים ---
app.post('/api/businesses', requireAuth, (req, res) => {
  const list = readData('businesses.json');
  const item = { id: Date.now(), name: req.body.name, office: req.body.office };
  list.push(item);
  writeData('businesses.json', list);
  res.json(item);
});

app.put('/api/businesses/:id', requireAuth, (req, res) => {
  let list = readData('businesses.json');
  list = list.map(b => b.id == req.params.id ? { ...b, ...req.body } : b);
  writeData('businesses.json', list);
  res.json({ ok: true });
});

app.delete('/api/businesses/:id', requireAuth, (req, res) => {
  let list = readData('businesses.json').filter(b => b.id != req.params.id);
  writeData('businesses.json', list);
  res.json({ ok: true });
});

// --- עדכוני בניין ---
app.post('/api/updates', requireAuth, (req, res) => {
  const list = readData('updates.json');
  const item = { id: Date.now(), text: req.body.text, image: req.body.image || '' };
  list.push(item);
  writeData('updates.json', list);
  res.json(item);
});

app.put('/api/updates/:id', requireAuth, (req, res) => {
  let list = readData('updates.json');
  list = list.map(u => u.id == req.params.id ? { ...u, ...req.body } : u);
  writeData('updates.json', list);
  res.json({ ok: true });
});

app.delete('/api/updates/:id', requireAuth, (req, res) => {
  let list = readData('updates.json').filter(u => u.id != req.params.id);
  writeData('updates.json', list);
  res.json({ ok: true });
});

// --- פרסומות ---
app.get('/api/ads/all', requireAuth, (req, res) => res.json(readData('ads.json')));

app.post('/api/ads', requireAuth, upload.single('file'), (req, res) => {
  const list = readData('ads.json');
  const item = {
    id: Date.now(),
    title: req.body.title,
    type: req.body.type,
    url: req.file ? '/uploads/' + req.file.filename : req.body.url,
    duration: parseInt(req.body.duration) || 6,
    active: req.body.active === 'true'
  };
  list.push(item);
  writeData('ads.json', list);
  res.json(item);
});

app.put('/api/ads/:id', requireAuth, (req, res) => {
  let list = readData('ads.json');
  list = list.map(a => a.id == req.params.id ? { ...a, ...req.body, active: req.body.active === 'true' } : a);
  writeData('ads.json', list);
  res.json({ ok: true });
});

app.delete('/api/ads/:id', requireAuth, (req, res) => {
  let list = readData('ads.json').filter(a => a.id != req.params.id);
  writeData('ads.json', list);
  res.json({ ok: true });
});

// --- דפי המסכים ---
app.get('/screen1', (req, res) => res.sendFile(path.join(__dirname, 'public', 'screen1.html')));
app.get('/screen2', (req, res) => res.sendFile(path.join(__dirname, 'public', 'screen2.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'index.html')));

app.listen(PORT, () => console.log(`המערכת רצה על http://localhost:${PORT}`));
