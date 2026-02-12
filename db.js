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

function migrate() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
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
}

module.exports = {
  db,
  migrate,
};
