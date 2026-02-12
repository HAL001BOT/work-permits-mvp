const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'app.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

function hasMigration(version) {
  return !!db.prepare('SELECT 1 FROM schema_migrations WHERE version = ?').get(version);
}

function applyMigration(version, fn) {
  if (hasMigration(version)) return;
  const tx = db.transaction(() => {
    fn();
    db.prepare('INSERT INTO schema_migrations (version) VALUES (?)').run(version);
  });
  tx();
}

function migrate() {
  applyMigration('001_base', () => {
    db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'requester',
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS permits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        site TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('draft', 'submitted', 'approved', 'closed')) DEFAULT 'draft',
        permit_date TEXT NOT NULL,
        created_by INTEGER NOT NULL,
        updated_by INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY(created_by) REFERENCES users(id),
        FOREIGN KEY(updated_by) REFERENCES users(id)
      );

      CREATE TABLE IF NOT EXISTS permit_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        permit_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        old_values TEXT,
        new_values TEXT,
        changed_by INTEGER NOT NULL,
        changed_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY(permit_id) REFERENCES permits(id),
        FOREIGN KEY(changed_by) REFERENCES users(id)
      );

      CREATE INDEX IF NOT EXISTS idx_permits_status ON permits(status);
      CREATE INDEX IF NOT EXISTS idx_permits_site ON permits(site);
      CREATE INDEX IF NOT EXISTS idx_permits_date ON permits(permit_date);
      CREATE INDEX IF NOT EXISTS idx_audit_permit_id ON permit_audit(permit_id);
    `);
  });

  applyMigration('002_rbac_roles', () => {
    db.exec(`
      UPDATE users
      SET role = 'requester'
      WHERE role NOT IN ('admin', 'supervisor', 'requester', 'viewer');
    `);
  });

  applyMigration('003_workflow_signatures', () => {
    db.exec(`
      ALTER TABLE permits ADD COLUMN approved_by INTEGER;
      ALTER TABLE permits ADD COLUMN approved_at TEXT;
      ALTER TABLE permits ADD COLUMN approver_name TEXT;
      ALTER TABLE permits ADD COLUMN signature_text TEXT;
      ALTER TABLE permits ADD COLUMN is_locked INTEGER NOT NULL DEFAULT 0;
      ALTER TABLE permits ADD COLUMN revision INTEGER NOT NULL DEFAULT 1;
    `);
  });

  applyMigration('004_attachments', () => {
    db.exec(`
      CREATE TABLE IF NOT EXISTS permit_attachments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        permit_id INTEGER NOT NULL,
        original_name TEXT NOT NULL,
        stored_name TEXT NOT NULL,
        mime_type TEXT,
        size_bytes INTEGER NOT NULL,
        uploaded_by INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY(permit_id) REFERENCES permits(id),
        FOREIGN KEY(uploaded_by) REFERENCES users(id)
      );

      CREATE INDEX IF NOT EXISTS idx_attachments_permit ON permit_attachments(permit_id);
    `);
  });
}

module.exports = {
  db,
  migrate,
};
