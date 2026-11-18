const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');

const SECRET = process.env.SECRET || 'jokernet-secret-2024';
const ADMIN_PASSWORD = 'ImJoker789a123b';
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'db.json');

// ========== JSON БД ==========
function loadDB() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return { users: [], tasks: [], messages: [], reports: [], nextId: 1 }; }
}
function saveDB(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
function nid(db) { return db.nextId++; }
function pub(u) {
  return { id: u.id, login: u.login, nickname: u.nickname, avatar: u.avatar, jkr: u.jkr, is_admin: u.is_admin };
}

// ========== EXPRESS ==========
const app = express();
app.set('trust proxy', 1); // Важно для Render
app.use(express.json({ limit: '8mb' }));

// Защита от спама
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  message: { error: 'Слишком много запросов, попробуй позже' }
});
app.use('/api', apiLimiter);

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' }, maxHttpBufferSize: 8e6 });

function auth(req, res, next) {
  const token = (req.headers.authorization || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Нет токена' });
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ error: 'Токен невалиден' }); }
}

// ========== AUTH ==========
app.post('/api/register', async (req, res) => {
  const { login, password } = req.body;
  if (!login || login.length < 3) return res.status(400).json({ error: 'Логин от 3 символов' });
  if (!password || password.length < 4) return res.status(400).json({ error: 'Пароль от 4 символов' });
  const db = loadDB();
  if (db.users.find(u => u.login === login)) return res.status(400).json({ error: 'Логин занят' });
  const hash = await bcrypt.hash(password, 10);
  const user = {
    id: nid(db), login, password: hash, nickname: login, avatar: '',
    jkr: 100, is_admin: false, created_at: Date.now(),
  };
  db.users.push(user);
  saveDB(db);
  const token = jwt.sign({ id: user.id }, SECRET);
  res.json({ token, user: pub(user) });
});

app.post('/api/login', async (req, res) => {
  const { login, password } = req.body;
  const db = loadDB();
  const user = db.users.find(u => u.login === login);
  if (!user) return res.status(400).json({ error: 'Неверный логин или пароль' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(400).json({ error: 'Неверный логин или пароль' });
  const token = jwt.sign({ id: user.id }, SECRET);
  res.json({ token, user: pub(user) });
});

app.get('/api/me', auth, (req, res) => {
  const db = loadDB();
  const u = db.users.find(x => x.id === req.user.id);
  if (!u) return res.status(404).json({ error: 'Не найден' });
  res.json(pub(u));
});

app.post('/api/profile', auth, (req, res) => {
  const { nickname, avatar } = req.body;
  const db = loadDB();
  const u = db.users.find(x => x.id === req.user.id);
  if (!u) return res.status(404).json({ error: 'Не найден' });
  if (nickname) u.nickname = nickname;
  if (avatar !== undefined) u.avatar = avatar;
  saveDB(db);
  res.json({ ok: true, user: pub(u) });
});

// ========== ADMIN ==========
app.post('/api/admin/check', auth, (req, res) => {
  if (req.body.password !== ADMIN_PASSWORD) return res.status(403).json({ error: 'Неверный пароль' });
  const db = loadDB();
  const u = db.users.find(x => x.id === req.user.id);
  u.is_admin = true;
  saveDB(db);
  res.json({ ok: true });
});

app.post('/api/admin/give', auth, (req, res) => {
  const db = loadDB();
  const u = db.users.find(x => x.id === req.user.id);
