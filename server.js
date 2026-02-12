const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const multer = require('multer');
const PDFDocument = require('pdfkit');
const { db, migrate } = require('./db');

migrate();

const app = express();
const PORT = process.env.PORT || 3000;

const ROLES = {
  ADMIN: 'admin',
  SUPERVISOR: 'supervisor',
  REQUESTER: 'requester',
  VIEWER: 'viewer',
};

const PERMIT_TYPES = {
  GENERAL_WORK_SAFE: 'general_work_safe',
  HOT_WORK: 'hot_work',
  CONFINED_SPACE: 'confined_space',
  LOTO: 'loto',
  EXCAVATION: 'excavation',
  LINE_BREAK: 'line_break',
  WORKING_HEIGHTS: 'working_heights',
};

const SUPPLEMENTAL_PERMIT_TYPES = [
  PERMIT_TYPES.HOT_WORK,
  PERMIT_TYPES.CONFINED_SPACE,
  PERMIT_TYPES.LOTO,
  PERMIT_TYPES.EXCAVATION,
  PERMIT_TYPES.LINE_BREAK,
  PERMIT_TYPES.WORKING_HEIGHTS,
];

const PERMIT_TYPE_LABELS = {
  [PERMIT_TYPES.GENERAL_WORK_SAFE]: 'General Work Safe',
  [PERMIT_TYPES.HOT_WORK]: 'Hot Work Permit',
  [PERMIT_TYPES.CONFINED_SPACE]: 'Confined Space Permit',
  [PERMIT_TYPES.LOTO]: 'LOTO / Energy Isolation Permit',
  [PERMIT_TYPES.EXCAVATION]: 'Excavation Permit',
  [PERMIT_TYPES.LINE_BREAK]: 'Line Break Permit',
  [PERMIT_TYPES.WORKING_HEIGHTS]: 'Working at Heights Permit',
};

const FIELD_EDITABLE_STATUSES = new Set(['draft', 'submitted']);
const ALLOWED_UPLOAD_MIME = new Set([
  'application/pdf',
  'image/jpeg',
  'image/png',
  'image/gif',
  'text/plain',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/msword',
]);

const uploadsDir = path.join(__dirname, 'data', 'uploads');
fs.mkdirSync(uploadsDir, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, uploadsDir),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname || '').slice(0, 10).replace(/[^a-zA-Z0-9.]/g, '');
      cb(null, `${Date.now()}-${crypto.randomUUID()}${ext ? `.${ext.replace(/^\./, '')}` : ''}`);
    },
  }),
  limits: { fileSize: 10 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    if (!ALLOWED_UPLOAD_MIME.has(file.mimetype)) return cb(new Error('File type not allowed'));
    cb(null, true);
  },
});

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
  if (!req.session.user) return res.redirect('/login');
  next();
}

function hasAnyRole(user, roles) {
  return user && roles.includes(user.role);
}

function canCreatePermit(user) {
  return hasAnyRole(user, [ROLES.ADMIN, ROLES.SUPERVISOR, ROLES.REQUESTER]);
}

function permitTypeLabel(type) {
  return PERMIT_TYPE_LABELS[type] || type;
}

function parseRequiredPermitsJson(value) {
  if (!value) return [];
  try {
    const arr = JSON.parse(value);
    if (!Array.isArray(arr)) return [];
    return arr.filter((x) => SUPPLEMENTAL_PERMIT_TYPES.includes(x));
  } catch {
    return [];
  }
}

function normalizeRequiredPermits(input) {
  const raw = Array.isArray(input) ? input : input ? [input] : [];
  return Array.from(new Set(raw.filter((x) => SUPPLEMENTAL_PERMIT_TYPES.includes(x))));
}

function isGeneralPermit(permit) {
  return (permit.permit_type || PERMIT_TYPES.GENERAL_WORK_SAFE) === PERMIT_TYPES.GENERAL_WORK_SAFE;
}

function canEditFields(user, permit) {
  if (!user || permit.is_locked) return false;
  if (!FIELD_EDITABLE_STATUSES.has(permit.status)) return false;
  if (hasAnyRole(user, [ROLES.ADMIN, ROLES.SUPERVISOR])) return true;
  return user.role === ROLES.REQUESTER && permit.created_by === user.id;
}

function canDeletePermit(user) {
  return hasAnyRole(user, [ROLES.ADMIN]);
}

function transitionActions(user, permit) {
  const actions = [];
  const isOwnerRequester = user.role === ROLES.REQUESTER && permit.created_by === user.id;
  if (permit.status === 'draft' && (isOwnerRequester || hasAnyRole(user, [ROLES.ADMIN, ROLES.SUPERVISOR]))) actions.push('submit');
  if (permit.status === 'submitted' && hasAnyRole(user, [ROLES.ADMIN, ROLES.SUPERVISOR])) actions.push('approve');
  if (permit.status === 'approved' && hasAnyRole(user, [ROLES.ADMIN, ROLES.SUPERVISOR])) actions.push('close', 'reopen');
  if (permit.status === 'closed' && hasAnyRole(user, [ROLES.ADMIN, ROLES.SUPERVISOR])) actions.push('reopen');
  return actions;
}

function canDeleteAttachment(user) {
  return hasAnyRole(user, [ROLES.ADMIN, ROLES.SUPERVISOR]);
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

const AUDIT_FIELD_LABELS = {
  title: 'Title',
  site: 'Site',
  permit_date: 'Permit Date',
  status: 'Status',
  description: 'Description',
  approved_at: 'Approved At',
  approver_name: 'Approver Name',
  signature_text: 'Digital Signature',
  is_locked: 'Locked',
  revision: 'Revision',
  id: 'ID',
};

function safeParseJson(value) {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

function formatDate(value) {
  if (!value) return '-';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString();
}

function toDisplayValue(field, value) {
  if (value === null || value === undefined || value === '') return '—';
  if (field === 'status') return formatStatusLabel(String(value));
  if (field === 'is_locked') return Number(value) ? 'Yes' : 'No';
  if (String(field).includes('date') || String(field).endsWith('_at')) return formatDate(value);
  return String(value);
}

function toFriendlyChanges(oldValues, newValues) {
  const oldObj = safeParseJson(oldValues) || {};
  const newObj = safeParseJson(newValues) || {};
  const keys = Array.from(new Set([...Object.keys(oldObj), ...Object.keys(newObj)]));

  return keys
    .filter((k) => String(oldObj[k] ?? '') !== String(newObj[k] ?? ''))
    .map((field) => ({
      field,
      label: AUDIT_FIELD_LABELS[field] || field.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()),
      oldValue: toDisplayValue(field, oldObj[field]),
      newValue: toDisplayValue(field, newObj[field]),
    }));
}

function logAudit(permitId, action, oldValues, newValues, changedBy) {
  db.prepare(
    `INSERT INTO permit_audit (permit_id, action, old_values, new_values, changed_by)
     VALUES (?, ?, ?, ?, ?)`
  ).run(permitId, action, oldValues ? JSON.stringify(oldValues) : null, newValues ? JSON.stringify(newValues) : null, changedBy);
}

function pickSnapshot(permit) {
  return {
    title: permit.title,
    description: permit.description,
    site: permit.site,
    status: permit.status,
    permit_date: permit.permit_date,
    permit_type: permit.permit_type,
    parent_permit_id: permit.parent_permit_id,
    required_permits: parseRequiredPermitsJson(permit.required_permits_json),
    approved_at: permit.approved_at,
    approver_name: permit.approver_name,
    signature_text: permit.signature_text,
    is_locked: permit.is_locked,
    revision: permit.revision,
  };
}

function getPermitById(id) {
  return db
    .prepare(
      `SELECT p.*, c.username AS created_by_name, u.username AS updated_by_name
       FROM permits p
       JOIN users c ON c.id = p.created_by
       JOIN users u ON u.id = p.updated_by
       WHERE p.id = ?`
    )
    .get(id);
}

function getChildPermits(parentPermitId) {
  return db
    .prepare(
      `SELECT p.*, c.username AS created_by_name, u.username AS updated_by_name
       FROM permits p
       JOIN users c ON c.id = p.created_by
       JOIN users u ON u.id = p.updated_by
       WHERE p.parent_permit_id = ?
       ORDER BY p.id ASC`
    )
    .all(parentPermitId);
}

function syncRequiredChildPermits(parentPermit, requiredTypes, userId) {
  if (!isGeneralPermit(parentPermit)) return;
  const existing = getChildPermits(parentPermit.id);
  const existingByType = new Map(existing.map((p) => [p.permit_type, p]));

  for (const type of requiredTypes) {
    if (existingByType.has(type)) continue;
    const title = `${permitTypeLabel(type)} - for Permit #${parentPermit.id}`;
    db.prepare(
      `INSERT INTO permits (title, description, site, status, permit_date, created_by, updated_by, permit_type, parent_permit_id, required_permits_json)
       VALUES (?, ?, ?, 'draft', ?, ?, ?, ?, ?, '[]')`
    ).run(title, '', parentPermit.site, parentPermit.permit_date, userId, userId, type, parentPermit.id);
  }
}

function validateGeneralTransitionRequirements(permit, action) {
  if (!isGeneralPermit(permit)) return null;
  const requiredTypes = parseRequiredPermitsJson(permit.required_permits_json);
  if (!requiredTypes.length) return null;

  const childrenByType = new Map(getChildPermits(permit.id).map((p) => [p.permit_type, p]));
  const missing = requiredTypes.filter((t) => !childrenByType.has(t));
  if (missing.length) return `Missing required permits: ${missing.map((t) => permitTypeLabel(t)).join(', ')}`;

  if (action === 'submit') {
    const notSubmitted = requiredTypes.filter((t) => {
      const status = childrenByType.get(t)?.status;
      return !['submitted', 'approved', 'closed'].includes(status);
    });
    if (notSubmitted.length) return `Submit required permits first: ${notSubmitted.map((t) => permitTypeLabel(t)).join(', ')}`;
  }

  if (action === 'approve') {
    const notApproved = requiredTypes.filter((t) => {
      const status = childrenByType.get(t)?.status;
      return !['approved', 'closed'].includes(status);
    });
    if (notApproved.length) return `Approve required permits first: ${notApproved.map((t) => permitTypeLabel(t)).join(', ')}`;
  }

  return null;
}

const BRAND = {
  primary: '#0f766e',
  primaryDark: '#115e59',
  muted: '#475569',
  border: '#cbd5e1',
  bgSoft: '#f0fdfa',
};

const LOGO_CANDIDATES = [path.join(__dirname, 'public', 'img', 'sachem.gif'), path.join(__dirname, 'public', 'img', 'sachem.png')];

function resolveLogoPath() {
  for (const logoPath of LOGO_CANDIDATES) if (fs.existsSync(logoPath)) return logoPath;
  return null;
}

function drawFooter(doc, generatedAt) {
  const range = doc.bufferedPageRange();
  for (let i = 0; i < range.count; i += 1) {
    doc.switchToPage(range.start + i);
    const pageWidth = doc.page.width;
    const pageHeight = doc.page.height;
    doc.font('Helvetica').fontSize(8).fillColor(BRAND.muted).text(`Generated ${generatedAt}`, 50, pageHeight - 32, { width: pageWidth - 100, align: 'left' }).text(`Page ${i + 1} of ${range.count}`, 50, pageHeight - 32, { width: pageWidth - 100, align: 'right' });
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
    try { doc.image(logoPath, 50, startY, { fit: [54, 54] }); } catch (_err) { }
  }

  const textX = 120;
  doc.fillColor(BRAND.primaryDark).font('Helvetica-Bold').fontSize(20).text('Sachem Work Permits', textX, startY + 2);
  doc.fillColor('#0f172a').font('Helvetica-Bold').fontSize(14).text(subtitle, textX, startY + 30);
  doc.fillColor(BRAND.muted).font('Helvetica').fontSize(9).text('Permit & Safety Documentation', textX, startY + 50);
  doc.y = 145;
}

function generatePermitPdf(res, permit) {
  const doc = new PDFDocument({ margin: 50, size: 'A4', bufferPages: true });
  const generatedAt = new Date().toLocaleString();
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="permit-${permit.id}.pdf"`);
  doc.pipe(res);

  drawHeader(doc, `Permit #${permit.id}`);
  doc.roundedRect(50, doc.y, 495, 64, 8).fillAndStroke('#ffffff', BRAND.border);
  doc.fillColor(BRAND.primaryDark).font('Helvetica-Bold').fontSize(18).text(permit.title || 'Untitled permit', 64, doc.y + 14, { width: 465 });
  doc.fillColor(BRAND.muted).font('Helvetica').fontSize(10).text(`Status: ${formatStatusLabel(permit.status)} • Revision: ${permit.revision}`, 64, doc.y + 40);
  doc.y += 82;
  doc.font('Helvetica').fontSize(11).fillColor('#0f172a');
  doc.text(`Site: ${permit.site || '-'}`);
  doc.text(`Permit Date: ${permit.permit_date || '-'}`);
  doc.text(`Created By: ${permit.created_by_name}`);
  doc.text(`Updated By: ${permit.updated_by_name}`);
  doc.text(`Locked: ${permit.is_locked ? 'Yes' : 'No'}`);
  if (permit.approver_name) doc.text(`Approved By: ${permit.approver_name} (${formatDate(permit.approved_at)})`);
  if (permit.signature_text) doc.text(`Signature: ${permit.signature_text}`);
  doc.moveDown();
  doc.font('Helvetica-Bold').text('Description');
  doc.font('Helvetica').text(permit.description || 'No description provided.');
  drawFooter(doc, generatedAt);
  doc.end();
}

app.get('/', requireAuth, (_req, res) => res.redirect('/permits'));

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

app.post('/logout', requireAuth, (req, res) => req.session.destroy(() => res.redirect('/login')));

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
    .all(...params)
    .map((p) => ({
      ...p,
      actions: {
        canEdit: canEditFields(req.session.user, p),
        canDelete: canDeletePermit(req.session.user),
        canTransition: transitionActions(req.session.user, p),
      },
    }));

  const statusCounts = statusOptions().reduce((acc, status) => ({ ...acc, [status]: permits.filter((p) => p.status === status).length }), {});

  res.render('permits', {
    permits,
    filters,
    statusOptions: statusOptions(),
    permissions: {
      canCreate: canCreatePermit(req.session.user),
    },
    stats: { total: permits.length, statusCounts },
  });
});

app.get('/permits/new', requireAuth, (req, res) => {
  if (!canCreatePermit(req.session.user)) return res.status(403).send('Forbidden');
  res.render('permit-form', {
    permit: null,
    action: '/permits',
    error: null,
    supplementalPermitTypes: SUPPLEMENTAL_PERMIT_TYPES,
    permitTypeLabels: PERMIT_TYPE_LABELS,
  });
});

app.post('/permits', requireAuth, (req, res) => {
  if (!canCreatePermit(req.session.user)) return res.status(403).send('Forbidden');
  const { title, description = '', site, permit_date } = req.body;
  const requiredPermits = normalizeRequiredPermits(req.body.required_permits);
  if (!title || !site || !permit_date) {
    return res.status(400).render('permit-form', {
      permit: { ...req.body, permit_type: PERMIT_TYPES.GENERAL_WORK_SAFE, required_permits_json: JSON.stringify(requiredPermits) },
      action: '/permits',
      error: 'Title, site, and permit date are required.',
      supplementalPermitTypes: SUPPLEMENTAL_PERMIT_TYPES,
      permitTypeLabels: PERMIT_TYPE_LABELS,
    });
  }

  const result = db
    .prepare(
      `INSERT INTO permits (title, description, site, status, permit_date, created_by, updated_by, permit_type, required_permits_json)
       VALUES (?, ?, ?, 'draft', ?, ?, ?, ?, ?)`
    )
    .run(title, description, site, permit_date, req.session.user.id, req.session.user.id, PERMIT_TYPES.GENERAL_WORK_SAFE, JSON.stringify(requiredPermits));

  const parent = getPermitById(result.lastInsertRowid);
  syncRequiredChildPermits(parent, requiredPermits, req.session.user.id);

  logAudit(result.lastInsertRowid, 'create', null, { title, description, site, status: 'draft', permit_date, permit_type: PERMIT_TYPES.GENERAL_WORK_SAFE, required_permits: requiredPermits, revision: 1 }, req.session.user.id);
  res.redirect(`/permits/${result.lastInsertRowid}`);
});

app.get('/permits/:id(\\d+)/edit', requireAuth, (req, res) => {
  const permit = getPermitById(req.params.id);
  if (!permit) return res.status(404).send('Permit not found');
  if (!canEditFields(req.session.user, permit)) return res.status(403).send('Forbidden');
  res.render('permit-form', {
    permit,
    action: `/permits/${permit.id}`,
    error: null,
    supplementalPermitTypes: SUPPLEMENTAL_PERMIT_TYPES,
    permitTypeLabels: PERMIT_TYPE_LABELS,
  });
});

app.post('/permits/:id(\\d+)', requireAuth, (req, res) => {
  const permit = getPermitById(req.params.id);
  if (!permit) return res.status(404).send('Permit not found');
  if (!canEditFields(req.session.user, permit)) return res.status(403).send('Forbidden');

  const { title, description = '', site, permit_date } = req.body;
  const requiredPermits = isGeneralPermit(permit) ? normalizeRequiredPermits(req.body.required_permits) : [];

  if (!title || !site || !permit_date) {
    return res.status(400).render('permit-form', {
      permit: { ...permit, ...req.body, required_permits_json: JSON.stringify(requiredPermits) },
      action: `/permits/${req.params.id}`,
      error: 'Title, site, and permit date are required.',
      supplementalPermitTypes: SUPPLEMENTAL_PERMIT_TYPES,
      permitTypeLabels: PERMIT_TYPE_LABELS,
    });
  }

  db.prepare(
    `UPDATE permits
     SET title = ?, description = ?, site = ?, permit_date = ?, required_permits_json = ?, updated_by = ?, updated_at = datetime('now')
     WHERE id = ?`
  ).run(title, description, site, permit_date, JSON.stringify(requiredPermits), req.session.user.id, req.params.id);

  const updated = getPermitById(req.params.id);
  syncRequiredChildPermits(updated, requiredPermits, req.session.user.id);

  logAudit(req.params.id, 'update', pickSnapshot(permit), pickSnapshot(updated), req.session.user.id);
  res.redirect(`/permits/${req.params.id}`);
});

app.post('/permits/:id(\\d+)/transition', requireAuth, (req, res) => {
  const permit = getPermitById(req.params.id);
  if (!permit) return res.status(404).send('Permit not found');

  const action = (req.body.action || '').trim();
  const allowed = transitionActions(req.session.user, permit);
  if (!allowed.includes(action)) return res.status(403).send('Transition not allowed');

  const transitionRequirementError = validateGeneralTransitionRequirements(permit, action);
  if (transitionRequirementError) return res.status(400).send(transitionRequirementError);

  const tx = db.transaction(() => {
    if (action === 'submit') {
      db.prepare(`UPDATE permits SET status = 'submitted', updated_by = ?, updated_at = datetime('now') WHERE id = ?`).run(req.session.user.id, permit.id);
    } else if (action === 'approve') {
      const signature = (req.body.signature_text || '').trim();
      if (!signature) throw new Error('Signature is required to approve');
      const approverName = req.session.user.username;
      db.prepare(
        `UPDATE permits
         SET status = 'approved', approved_by = ?, approved_at = datetime('now'), approver_name = ?, signature_text = ?, is_locked = 1,
             updated_by = ?, updated_at = datetime('now')
         WHERE id = ?`
      ).run(req.session.user.id, approverName, signature, req.session.user.id, permit.id);
    } else if (action === 'close') {
      db.prepare(`UPDATE permits SET status = 'closed', is_locked = 1, updated_by = ?, updated_at = datetime('now') WHERE id = ?`).run(req.session.user.id, permit.id);
    } else if (action === 'reopen') {
      db.prepare(
        `UPDATE permits
         SET status = 'draft', is_locked = 0, revision = revision + 1,
             approved_by = NULL, approved_at = NULL, approver_name = NULL, signature_text = NULL,
             updated_by = ?, updated_at = datetime('now')
         WHERE id = ?`
      ).run(req.session.user.id, permit.id);
    }

    const updated = getPermitById(permit.id);
    logAudit(permit.id, `transition_${action}`, pickSnapshot(permit), pickSnapshot(updated), req.session.user.id);
  });

  try {
    tx();
    res.redirect(`/permits/${permit.id}`);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.post('/permits/:id(\\d+)/delete', requireAuth, (req, res) => {
  if (!canDeletePermit(req.session.user)) return res.status(403).send('Forbidden');
  const permit = getPermitById(req.params.id);
  if (!permit) return res.status(404).send('Permit not found');

  const attachmentRows = db.prepare('SELECT * FROM permit_attachments WHERE permit_id = ?').all(permit.id);
  for (const a of attachmentRows) {
    const fullPath = path.join(uploadsDir, a.stored_name);
    if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
  }
  db.prepare('DELETE FROM permit_attachments WHERE permit_id = ?').run(permit.id);
  db.prepare('DELETE FROM permits WHERE id = ?').run(permit.id);
  logAudit(permit.id, 'delete', pickSnapshot(permit), null, req.session.user.id);
  res.redirect('/permits');
});

app.get('/permits/:id(\\d+)', requireAuth, (req, res) => {
  const permit = getPermitById(req.params.id);
  if (!permit) return res.status(404).send('Permit not found');

  const recentAudit = db
    .prepare(
      `SELECT a.changed_at, a.action, u.username FROM permit_audit a JOIN users u ON u.id = a.changed_by WHERE a.permit_id = ? ORDER BY a.changed_at DESC LIMIT 7`
    )
    .all(req.params.id);

  const attachments = db
    .prepare(
      `SELECT pa.*, u.username AS uploaded_by_name FROM permit_attachments pa JOIN users u ON u.id = pa.uploaded_by WHERE pa.permit_id = ? ORDER BY pa.created_at DESC`
    )
    .all(req.params.id);

  const requiredPermitTypes = parseRequiredPermitsJson(permit.required_permits_json);
  const childPermits = getChildPermits(permit.id);

  res.render('permit-detail', {
    permit,
    recentAudit,
    attachments,
    permitTypeLabels: PERMIT_TYPE_LABELS,
    requiredPermitTypes,
    childPermits,
    permissions: {
      canEdit: canEditFields(req.session.user, permit),
      canDeletePermit: canDeletePermit(req.session.user),
      canUpload: canEditFields(req.session.user, permit) || hasAnyRole(req.session.user, [ROLES.ADMIN, ROLES.SUPERVISOR]),
      canDeleteAttachment: canDeleteAttachment(req.session.user),
      transitions: transitionActions(req.session.user, permit),
    },
  });
});

app.post('/permits/:id(\\d+)/attachments', requireAuth, upload.single('attachment'), (req, res) => {
  const permit = getPermitById(req.params.id);
  if (!permit) return res.status(404).send('Permit not found');
  const canUpload = canEditFields(req.session.user, permit) || hasAnyRole(req.session.user, [ROLES.ADMIN, ROLES.SUPERVISOR]);
  if (!canUpload) return res.status(403).send('Forbidden');
  if (!req.file) return res.status(400).send('No file uploaded');

  const originalName = path.basename(req.file.originalname).replace(/[^a-zA-Z0-9._ -]/g, '_').slice(0, 140);
  db.prepare(
    `INSERT INTO permit_attachments (permit_id, original_name, stored_name, mime_type, size_bytes, uploaded_by)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).run(permit.id, originalName, req.file.filename, req.file.mimetype, req.file.size, req.session.user.id);

  db.prepare(`UPDATE permits SET updated_by = ?, updated_at = datetime('now') WHERE id = ?`).run(req.session.user.id, permit.id);
  logAudit(permit.id, 'attachment_upload', null, { original_name: originalName, size_bytes: req.file.size, mime_type: req.file.mimetype }, req.session.user.id);
  res.redirect(`/permits/${permit.id}`);
});

app.get('/permits/:id(\\d+)/attachments/:attachmentId(\\d+)', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM permit_attachments WHERE id = ? AND permit_id = ?').get(req.params.attachmentId, req.params.id);
  if (!row) return res.status(404).send('Attachment not found');
  const fullPath = path.join(uploadsDir, row.stored_name);
  if (!fs.existsSync(fullPath)) return res.status(404).send('File missing on server');
  res.download(fullPath, row.original_name);
});

app.post('/permits/:id(\\d+)/attachments/:attachmentId(\\d+)/delete', requireAuth, (req, res) => {
  if (!canDeleteAttachment(req.session.user)) return res.status(403).send('Forbidden');
  const row = db.prepare('SELECT * FROM permit_attachments WHERE id = ? AND permit_id = ?').get(req.params.attachmentId, req.params.id);
  if (!row) return res.status(404).send('Attachment not found');

  db.prepare('DELETE FROM permit_attachments WHERE id = ?').run(row.id);
  const fullPath = path.join(uploadsDir, row.stored_name);
  if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);

  db.prepare(`UPDATE permits SET updated_by = ?, updated_at = datetime('now') WHERE id = ?`).run(req.session.user.id, req.params.id);
  logAudit(req.params.id, 'attachment_delete', { original_name: row.original_name, size_bytes: row.size_bytes }, null, req.session.user.id);
  res.redirect(`/permits/${req.params.id}`);
});

app.get('/permits/:id(\\d+)/audit', requireAuth, (req, res) => {
  const permit = db.prepare('SELECT id FROM permits WHERE id = ?').get(req.params.id);
  const auditRows = db
    .prepare(`SELECT a.*, u.username FROM permit_audit a JOIN users u ON u.id = a.changed_by WHERE a.permit_id = ? ORDER BY a.changed_at DESC`)
    .all(req.params.id)
    .map((row) => ({
      ...row,
      changedAtPretty: formatDate(row.changed_at),
      actionLabel: formatStatusLabel(row.action),
      changes: toFriendlyChanges(row.old_values, row.new_values),
      oldRaw: row.old_values,
      newRaw: row.new_values,
    }));

  if (!permit && auditRows.length === 0) return res.status(404).send('Permit not found');
  res.render('audit', { permitId: req.params.id, auditRows });
});

app.get('/permits/:id(\\d+)/export.pdf', requireAuth, (req, res) => {
  const permit = getPermitById(req.params.id);
  if (!permit) return res.status(404).send('Permit not found');
  generatePermitPdf(res, permit);
});

app.get('/permits/export.csv', requireAuth, (req, res) => {
  const { where, params } = getFilterContext(req.query);
  const whereNoAlias = where.replace(/p\./g, '');
  const rows = db
    .prepare(`SELECT id,title,description,site,status,permit_type,parent_permit_id,required_permits_json,permit_date,revision,is_locked,approver_name,approved_at,created_at,updated_at FROM permits ${whereNoAlias} ORDER BY updated_at DESC`)
    .all(...params);

  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const header = ['id', 'title', 'description', 'site', 'status', 'permit_type', 'parent_permit_id', 'required_permits_json', 'permit_date', 'revision', 'is_locked', 'approver_name', 'approved_at', 'created_at', 'updated_at'];
  const csv = [header.join(',')].concat(rows.map((row) => header.map((h) => esc(row[h])).join(','))).join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="permits.csv"');
  res.send(csv);
});

app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError || err.message === 'File type not allowed') {
    return res.status(400).send(`Upload failed: ${err.message}`);
  }
  return res.status(500).send('Unexpected server error');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Work permits app running on http://0.0.0.0:${PORT}`);
});
