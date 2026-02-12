const path = require('path');
const fs = require('fs');
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

const BRAND = {
  primary: '#0f766e',
  primaryDark: '#115e59',
  accent: '#14b8a6',
  ink: '#0f172a',
  muted: '#475569',
  border: '#cbd5e1',
  bgSoft: '#f0fdfa',
};

const LOGO_CANDIDATES = [
  path.join(__dirname, 'public', 'img', 'sachem.gif'),
  path.join(__dirname, 'public', 'img', 'sachem.png'),
];

function resolveLogoPath() {
  for (const logoPath of LOGO_CANDIDATES) {
    if (fs.existsSync(logoPath)) return logoPath;
  }
  return null;
}

function formatDate(value) {
  if (!value) return '-';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString();
}

function drawFooter(doc, generatedAt) {
  const range = doc.bufferedPageRange();
  for (let i = 0; i < range.count; i += 1) {
    doc.switchToPage(range.start + i);
    const pageWidth = doc.page.width;
    const pageHeight = doc.page.height;

    doc
      .font('Helvetica')
      .fontSize(8)
      .fillColor(BRAND.muted)
      .text(`Generated ${generatedAt}`, 50, pageHeight - 32, {
        width: pageWidth - 100,
        align: 'left',
      })
      .text(`Page ${i + 1} of ${range.count}`, 50, pageHeight - 32, {
        width: pageWidth - 100,
        align: 'right',
      });
  }
}

function drawHeader(doc, subtitle) {
  const startY = 44;
  doc.save();
  doc.rect(0, 0, doc.page.width, 125).fill(BRAND.bgSoft);
  doc.rect(0, 118, doc.page.width, 7).fill(BRAND.primary);
  doc.restore();

  const logoPath = resolveLogoPath();
  if (logoPath) {
    try {
      doc.image(logoPath, 50, startY, { fit: [54, 54], align: 'left', valign: 'top' });
    } catch (_err) {
      // GIF support can vary by environment; continue without logo if unsupported.
    }
  }

  const textX = 120;
  doc.fillColor(BRAND.primaryDark).font('Helvetica-Bold').fontSize(20).text('Sachem Work Permits', textX, startY + 2);
  doc.fillColor(BRAND.ink).font('Helvetica-Bold').fontSize(14).text(subtitle, textX, startY + 30);
  doc.fillColor(BRAND.muted).font('Helvetica').fontSize(9).text('Permit & Safety Documentation', textX, startY + 50);

  doc.y = 145;
}

function drawSectionCard(doc, label, value, x, y, w) {
  const h = 54;
  doc.roundedRect(x, y, w, h, 6).fillAndStroke('#ffffff', BRAND.border);
  doc.font('Helvetica-Bold').fontSize(8).fillColor(BRAND.muted).text(label.toUpperCase(), x + 10, y + 10, { width: w - 20 });
  doc.font('Helvetica').fontSize(11).fillColor(BRAND.ink).text(value || '-', x + 10, y + 24, { width: w - 20 });
}

function generatePermitPdf(res, permit) {
  const doc = new PDFDocument({ margin: 50, size: 'A4', bufferPages: true });
  const safeTitle = `permit-${permit.id}.pdf`;
  const generatedAt = new Date().toLocaleString();

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${safeTitle}"`);
  doc.pipe(res);

  drawHeader(doc, `Permit #${permit.id}`);

  doc.roundedRect(50, doc.y, 495, 64, 8).fillAndStroke('#ffffff', BRAND.border);
  doc.fillColor(BRAND.primaryDark).font('Helvetica-Bold').fontSize(18).text(permit.title || 'Untitled permit', 64, doc.y + 14, {
    width: 465,
  });
  doc.fillColor(BRAND.muted).font('Helvetica').fontSize(10).text(`Status: ${formatStatusLabel(permit.status)} • Permit Date: ${permit.permit_date || '-'}`, 64, doc.y + 40);

  doc.y += 82;

  const cardWidth = 154;
  const gap = 16;
  const x0 = 50;
  let y = doc.y;
  drawSectionCard(doc, 'Site', permit.site, x0, y, cardWidth);
  drawSectionCard(doc, 'Created By', permit.created_by_name, x0 + cardWidth + gap, y, cardWidth);
  drawSectionCard(doc, 'Updated By', permit.updated_by_name, x0 + (cardWidth + gap) * 2, y, cardWidth);

  y += 68;
  drawSectionCard(doc, 'Created At', formatDate(permit.created_at), x0, y, 239);
  drawSectionCard(doc, 'Updated At', formatDate(permit.updated_at), x0 + 255, y, 239);

  doc.y = y + 74;

  doc.roundedRect(50, doc.y, 495, 250, 8).fillAndStroke('#ffffff', BRAND.border);
  doc.rect(50, doc.y, 495, 30).fill(BRAND.primary);
  doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(12).text('Description', 64, doc.y + 9);
  doc.fillColor(BRAND.ink).font('Helvetica').fontSize(11).text(permit.description || 'No description provided.', 64, doc.y + 42, {
    width: 467,
    height: 200,
    lineGap: 4,
    ellipsis: true,
  });

  drawFooter(doc, generatedAt);
  doc.end();
}

function drawTableHeader(doc, y) {
  doc.rect(50, y, 495, 24).fill(BRAND.primary);
  doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(9);
  doc.text('ID', 58, y + 7, { width: 34 });
  doc.text('Title', 95, y + 7, { width: 190 });
  doc.text('Site', 289, y + 7, { width: 90 });
  doc.text('Status', 380, y + 7, { width: 66 });
  doc.text('Permit Date', 448, y + 7, { width: 95 });
}

function generatePermitListPdf(res, permits, filters) {
  const doc = new PDFDocument({ margin: 50, size: 'A4', bufferPages: true });
  const filename = 'permits-summary.pdf';
  const generatedAt = new Date().toLocaleString();

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  doc.pipe(res);

  drawHeader(doc, 'Permit Summary Report');

  doc.roundedRect(50, doc.y, 495, 76, 8).fillAndStroke('#ffffff', BRAND.border);
  doc.fillColor(BRAND.primaryDark).font('Helvetica-Bold').fontSize(12).text(`Total permits: ${permits.length}`, 64, doc.y + 12);

  const activeFilterLines = [
    filters.status ? `Status: ${filters.status}` : null,
    filters.site ? `Site contains: ${filters.site}` : null,
    filters.startDate ? `From: ${filters.startDate}` : null,
    filters.endDate ? `To: ${filters.endDate}` : null,
  ].filter(Boolean);

  doc.fillColor(BRAND.muted).font('Helvetica-Bold').fontSize(9).text('Applied filters', 64, doc.y + 34);
  doc.font('Helvetica').fontSize(9).fillColor(BRAND.ink).text(activeFilterLines.length ? activeFilterLines.join(' | ') : 'None', 64, doc.y + 48, { width: 465 });

  doc.y += 92;

  if (!permits.length) {
    doc.roundedRect(50, doc.y, 495, 64, 8).fillAndStroke('#ffffff', BRAND.border);
    doc.fillColor(BRAND.ink).font('Helvetica').fontSize(11).text('No permits matched the selected filters.', 64, doc.y + 24);
    drawFooter(doc, generatedAt);
    doc.end();
    return;
  }

  let y = doc.y;
  drawTableHeader(doc, y);
  y += 24;

  permits.forEach((permit, idx) => {
    if (y > 740) {
      doc.addPage();
      drawHeader(doc, 'Permit Summary Report');
      y = doc.y;
      drawTableHeader(doc, y);
      y += 24;
    }

    const rowHeight = 28;
    const isEven = idx % 2 === 0;
    doc.rect(50, y, 495, rowHeight).fillAndStroke(isEven ? '#ffffff' : '#f8fafc', BRAND.border);

    doc.fillColor(BRAND.ink).font('Helvetica').fontSize(9);
    doc.text(String(permit.id), 58, y + 9, { width: 34 });
    doc.text(permit.title || '-', 95, y + 9, { width: 190, ellipsis: true });
    doc.text(permit.site || '-', 289, y + 9, { width: 90, ellipsis: true });
    doc.text(formatStatusLabel(permit.status), 380, y + 9, { width: 66 });
    doc.text(permit.permit_date || '-', 448, y + 9, { width: 95 });

    y += rowHeight;
  });

  drawFooter(doc, generatedAt);
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

app.get('/permits/:id(\\d+)/edit', requireAuth, (req, res) => {
  const permit = db.prepare('SELECT * FROM permits WHERE id = ?').get(req.params.id);
  if (!permit) return res.status(404).send('Permit not found');

  res.render('permit-form', {
    permit,
    action: `/permits/${permit.id}`,
    statusOptions: statusOptions(),
    error: null,
  });
});

app.post('/permits/:id(\\d+)', requireAuth, (req, res) => {
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

app.post('/permits/:id(\\d+)/delete', requireAuth, (req, res) => {
  const permit = db.prepare('SELECT * FROM permits WHERE id = ?').get(req.params.id);
  if (!permit) return res.status(404).send('Permit not found');

  db.prepare('DELETE FROM permits WHERE id = ?').run(req.params.id);
  db.prepare(
    `INSERT INTO permit_audit (permit_id, action, old_values, new_values, changed_by)
     VALUES (?, 'delete', ?, NULL, ?)`
  ).run(req.params.id, JSON.stringify(permit), req.session.user.id);

  res.redirect('/permits');
});

app.get('/permits/:id(\\d+)', requireAuth, (req, res) => {
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

app.get('/permits/:id(\\d+)/audit', requireAuth, (req, res) => {
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

app.get('/permits/:id(\\d+)/export.pdf', requireAuth, (req, res) => {
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
