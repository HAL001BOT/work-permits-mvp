const path = require('path');
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const PDFDocument = require('pdfkit');
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

function getFilterContext(query) {
  const { status = '', site = '', startDate = '', endDate = '' } = query;
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

  return {
    filters: { status, site, startDate, endDate },
    where: clauses.length ? `WHERE ${clauses.join(' AND ')}` : '',
    params,
  };
}

function formatStatusLabel(status) {
  if (!status) return '';
  return status[0].toUpperCase() + status.slice(1);
}

function generatePermitPdf(res, permit) {
  const doc = new PDFDocument({ margin: 50, size: 'A4' });
  const safeTitle = `permit-${permit.id}.pdf`;

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${safeTitle}"`);
  doc.pipe(res);

  doc.fontSize(20).text('Work Permit', { align: 'left' });
  doc.moveDown(0.5);
  doc.fontSize(12).fillColor('#4b5563').text(`Generated: ${new Date().toLocaleString()}`);

  doc.moveDown();
  doc.fillColor('black').fontSize(14).text(`Permit #${permit.id}: ${permit.title}`);
  doc.moveDown(0.7);

  const fields = [
    ['Site', permit.site],
    ['Status', formatStatusLabel(permit.status)],
    ['Permit Date', permit.permit_date],
    ['Created At', permit.created_at],
    ['Updated At', permit.updated_at],
    ['Created By', permit.created_by_name],
    ['Updated By', permit.updated_by_name],
  ];

  fields.forEach(([label, value]) => {
    doc.font('Helvetica-Bold').text(`${label}: `, { continued: true });
    doc.font('Helvetica').text(value || '-');
  });

  doc.moveDown();
  doc.font('Helvetica-Bold').text('Description');
  doc.font('Helvetica').text(permit.description || 'No description provided.', {
    lineGap: 3,
  });

  doc.end();
}

function generatePermitListPdf(res, permits, filters) {
  const doc = new PDFDocument({ margin: 45, size: 'A4' });
  const filename = 'permits-summary.pdf';

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  doc.pipe(res);

  doc.fontSize(20).text('Work Permits Summary');
  doc.moveDown(0.5);
  doc.fontSize(11).fillColor('#4b5563').text(`Generated: ${new Date().toLocaleString()}`);
  doc.fillColor('black');

  const activeFilterLines = [
    filters.status ? `Status: ${filters.status}` : null,
    filters.site ? `Site contains: ${filters.site}` : null,
    filters.startDate ? `From: ${filters.startDate}` : null,
    filters.endDate ? `To: ${filters.endDate}` : null,
  ].filter(Boolean);

  doc.moveDown(0.7);
  doc.font('Helvetica-Bold').text('Filters');
  doc.font('Helvetica').text(activeFilterLines.length ? activeFilterLines.join(' | ') : 'None');

  doc.moveDown(0.5);
  doc.font('Helvetica-Bold').text(`Total permits: ${permits.length}`);
  doc.moveDown();

  if (!permits.length) {
    doc.font('Helvetica').text('No permits matched the selected filters.');
    doc.end();
    return;
  }

  permits.forEach((permit, idx) => {
    if (idx > 0) doc.moveDown(0.5);

    const blockTop = doc.y;
    doc.rect(45, blockTop - 3, 505, 70).stroke('#e5e7eb');

    doc.font('Helvetica-Bold').fontSize(12).text(`#${permit.id} - ${permit.title}`, 52, blockTop + 6);
    doc.font('Helvetica').fontSize(10).text(
      `Site: ${permit.site}    Status: ${formatStatusLabel(permit.status)}    Permit Date: ${permit.permit_date}`,
      52,
      blockTop + 25
    );
    doc.text(`Updated: ${permit.updated_at} by ${permit.updated_by_name}`, 52, blockTop + 40);

    doc.y = blockTop + 76;
    if (doc.y > 740) doc.addPage();
  });

  doc.end();
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
  const { filters, where, params } = getFilterContext(req.query);

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

  const statusCounts = statusOptions().reduce((acc, status) => {
    acc[status] = permits.filter((p) => p.status === status).length;
    return acc;
  }, {});

  res.render('permits', {
    permits,
    filters,
    statusOptions: statusOptions(),
    stats: {
      total: permits.length,
      statusCounts,
    },
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

app.get('/permits/:id', requireAuth, (req, res) => {
  const permit = db
    .prepare(
      `SELECT p.*, c.username AS created_by_name, u.username AS updated_by_name
       FROM permits p
       JOIN users c ON c.id = p.created_by
       JOIN users u ON u.id = p.updated_by
       WHERE p.id = ?`
    )
    .get(req.params.id);

  if (!permit) return res.status(404).send('Permit not found');

  const recentAudit = db
    .prepare(
      `SELECT a.changed_at, a.action, u.username
       FROM permit_audit a
       JOIN users u ON u.id = a.changed_by
       WHERE a.permit_id = ?
       ORDER BY a.changed_at DESC
       LIMIT 5`
    )
    .all(req.params.id);

  res.render('permit-detail', {
    permit,
    recentAudit,
  });
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

app.get('/permits/:id/export.pdf', requireAuth, (req, res) => {
  const permit = db
    .prepare(
      `SELECT p.*, c.username AS created_by_name, u.username AS updated_by_name
       FROM permits p
       JOIN users c ON c.id = p.created_by
       JOIN users u ON u.id = p.updated_by
       WHERE p.id = ?`
    )
    .get(req.params.id);

  if (!permit) return res.status(404).send('Permit not found');
  generatePermitPdf(res, permit);
});

app.get('/permits/export.pdf', requireAuth, (req, res) => {
  const { filters, where, params } = getFilterContext(req.query);
  const whereNoAlias = where.replace(/p\./g, '');

  const permits = db
    .prepare(
      `SELECT p.id, p.title, p.site, p.status, p.permit_date, p.updated_at, u.username AS updated_by_name
       FROM permits p
       JOIN users u ON u.id = p.updated_by
       ${whereNoAlias}
       ORDER BY p.updated_at DESC`
    )
    .all(...params);

  generatePermitListPdf(res, permits, filters);
});

app.get('/permits/export.csv', requireAuth, (req, res) => {
  const { where, params } = getFilterContext(req.query);
  const whereNoAlias = where.replace(/p\./g, '');

  const rows = db
    .prepare(`SELECT id,title,description,site,status,permit_date,created_at,updated_at FROM permits ${whereNoAlias} ORDER BY updated_at DESC`)
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
