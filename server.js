// ============================================================
//  server.js – Entry point
//  Passkey (WebAuthn) Auth Demo  |  Express + EJS + MongoDB
// ============================================================
'use strict';

require('dotenv').config();

const express      = require('express');
const session      = require('express-session');
const MongoStore   = require('connect-mongo');
const methodOverride = require('method-override');
const path         = require('path');

const connectDB    = require('./config/db');
const authRoutes   = require('./routes/auth');
const passkeyRoutes = require('./routes/passkeys');
const dashboardRoutes = require('./routes/dashboard');

const app = express();

// ── Database ─────────────────────────────────────────────────
connectDB();

// ── View engine ───────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ── Static assets ─────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ── Body parsers ──────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(methodOverride('_method'));

// ── Session ───────────────────────────────────────────────────
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev_secret',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: 'sessions',
    ttl: 60 * 60 * 24 * 7,   // 7 days
  }),
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 24 * 7,
  },
}));

// ── Make user available in all EJS templates ──────────────────
app.use((req, _res, next) => {
  // req.session.userId is set after login
  next();
});

// ── Routes ────────────────────────────────────────────────────
app.use('/',          authRoutes);
app.use('/passkeys',  passkeyRoutes);
app.use('/dashboard', dashboardRoutes);

// ── 404 handler ───────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).render('404');
});

// ── Error handler ─────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error(err.stack);
  res.status(500).render('error', { message: err.message });
});

// ── Start ─────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅  Server running → http://localhost:${PORT}`);
});
