const path = require('path');
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const { db, migrate } = require('./db');

migrate();

const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(
  session({
    store: new SQLiteStore({ db: 'sessions.db', dir: path.join(__dirname, 'data') }),
    secret: process.env.SESSION_SECRET || 'change-me-in-prod',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 1000 * 60 * 60 * 8,
    },
  })
);

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

function statusOptions() {
  return ['draft', 'submitted', 'approved', 'closed'];
}

app.get('/', requireAuth, (req, res) => {
  res.redirect('/permits');
});

app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/permits');
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).render('login', { error: 'Invalid username or password.' });
  }

  req.session.user = { id: user.id, username: user.username, role: user.role };
  res.redirect('/permits');
});

app.post('/logout', requireAuth, (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.get('/permits', requireAuth, (req, res) => {
  const { status = '', site = '', startDate = '', endDate = '' } = req.query;
  const clauses = [];
  const params = [];

  if (status) {
    clauses.push('p.status = ?');
    params.push(status);
  }
  if (site) {
    clauses.push('p.site LIKE ?');
    params.push(`%${site}%`);
  }
  if (startDate) {
    clauses.push('p.permit_date >= ?');
    params.push(startDate);
  }
  if (endDate) {
    clauses.push('p.permit_date <= ?');
    params.push(endDate);
  }

  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';

  const permits = db
    .prepare(
      `SELECT p.*, c.username AS created_by_name, u.username AS updated_by_name
       FROM permits p
       JOIN users c ON c.id = p.created_by
       JOIN users u ON u.id = p.updated_by
       ${where}
       ORDER BY p.updated_at DESC`
    )
    .all(...params);

  res.render('permits', {
    permits,
    filters: { status, site, startDate, endDate },
    statusOptions: statusOptions(),
  });
});

app.get('/permits/new', requireAuth, (req, res) => {
  res.render('permit-form', {
    permit: null,
    action: '/permits',
    statusOptions: statusOptions(),
    error: null,
  });
});

app.post('/permits', requireAuth, (req, res) => {
  const { title, description = '', site, status, permit_date } = req.body;
  if (!title || !site || !status || !permit_date) {
    return res.status(400).render('permit-form', {
      permit: req.body,
      action: '/permits',
      statusOptions: statusOptions(),
      error: 'Title, site, status, and permit date are required.',
    });
  }

  const insert = db.prepare(
    `INSERT INTO permits (title, description, site, status, permit_date, created_by, updated_by)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  );
  const result = insert.run(
    title,
    description,
    site,
    status,
    permit_date,
    req.session.user.id,
    req.session.user.id
  );

  db.prepare(
    `INSERT INTO permit_audit (permit_id, action, old_values, new_values, changed_by)
     VALUES (?, 'create', NULL, ?, ?)`
  ).run(
    result.lastInsertRowid,
    JSON.stringify({ title, description, site, status, permit_date }),
    req.session.user.id
  );

  res.redirect('/permits');
});

app.get('/permits/:id/edit', requireAuth, (req, res) => {
  const permit = db.prepare('SELECT * FROM permits WHERE id = ?').get(req.params.id);
  if (!permit) return res.status(404).send('Permit not found');

  res.render('permit-form', {
    permit,
    action: `/permits/${permit.id}`,
    statusOptions: statusOptions(),
    error: null,
  });
});

app.post('/permits/:id', requireAuth, (req, res) => {
  const permit = db.prepare('SELECT * FROM permits WHERE id = ?').get(req.params.id);
  if (!permit) return res.status(404).send('Permit not found');

  const { title, description = '', site, status, permit_date } = req.body;
  if (!title || !site || !status || !permit_date) {
    return res.status(400).render('permit-form', {
      permit: { ...req.body, id: req.params.id },
      action: `/permits/${req.params.id}`,
      statusOptions: statusOptions(),
      error: 'Title, site, status, and permit date are required.',
    });
  }

  db.prepare(
    `UPDATE permits
     SET title = ?, description = ?, site = ?, status = ?, permit_date = ?, updated_by = ?, updated_at = datetime('now')
     WHERE id = ?`
  ).run(title, description, site, status, permit_date, req.session.user.id, req.params.id);

  db.prepare(
    `INSERT INTO permit_audit (permit_id, action, old_values, new_values, changed_by)
     VALUES (?, 'update', ?, ?, ?)`
  ).run(
    req.params.id,
    JSON.stringify({
      title: permit.title,
      description: permit.description,
      site: permit.site,
      status: permit.status,
      permit_date: permit.permit_date,
    }),
    JSON.stringify({ title, description, site, status, permit_date }),
    req.session.user.id
  );

  res.redirect('/permits');
});

app.post('/permits/:id/delete', requireAuth, (req, res) => {
  const permit = db.prepare('SELECT * FROM permits WHERE id = ?').get(req.params.id);
  if (!permit) return res.status(404).send('Permit not found');

  db.prepare('DELETE FROM permits WHERE id = ?').run(req.params.id);
  db.prepare(
    `INSERT INTO permit_audit (permit_id, action, old_values, new_values, changed_by)
     VALUES (?, 'delete', ?, NULL, ?)`
  ).run(req.params.id, JSON.stringify(permit), req.session.user.id);

  res.redirect('/permits');
});

app.get('/permits/:id/audit', requireAuth, (req, res) => {
  const permit = db.prepare('SELECT * FROM permits WHERE id = ?').get(req.params.id);
  const auditRows = db
    .prepare(
      `SELECT a.*, u.username
       FROM permit_audit a
       JOIN users u ON u.id = a.changed_by
       WHERE a.permit_id = ?
       ORDER BY a.changed_at DESC`
    )
    .all(req.params.id);

  if (!permit && auditRows.length === 0) return res.status(404).send('Permit not found');

  res.render('audit', { permitId: req.params.id, auditRows });
});

app.get('/permits/export.csv', requireAuth, (req, res) => {
  const { status = '', site = '', startDate = '', endDate = '' } = req.query;
  const clauses = [];
  const params = [];

  if (status) {
    clauses.push('status = ?');
    params.push(status);
  }
  if (site) {
    clauses.push('site LIKE ?');
    params.push(`%${site}%`);
  }
  if (startDate) {
    clauses.push('permit_date >= ?');
    params.push(startDate);
  }
  if (endDate) {
    clauses.push('permit_date <= ?');
    params.push(endDate);
  }

  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  const rows = db
    .prepare(`SELECT id,title,description,site,status,permit_date,created_at,updated_at FROM permits ${where} ORDER BY updated_at DESC`)
    .all(...params);

  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const header = ['id', 'title', 'description', 'site', 'status', 'permit_date', 'created_at', 'updated_at'];
  const csv = [header.join(',')]
    .concat(rows.map((row) => header.map((h) => esc(row[h])).join(',')))
    .join('\n');

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="permits.csv"');
  res.send(csv);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Work permits app running on http://0.0.0.0:${PORT}`);
});
