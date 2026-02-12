const bcrypt = require('bcryptjs');
const { db, migrate } = require('../db');

migrate();

const defaultPassword = process.env.SEED_DEFAULT_PASS || 'permit123!';
const usersToSeed = [
  { username: process.env.SEED_ADMIN_USER || 'admin', role: 'admin', password: process.env.SEED_ADMIN_PASS || defaultPassword },
  { username: process.env.SEED_SUPERVISOR_USER || 'supervisor', role: 'supervisor', password: process.env.SEED_SUPERVISOR_PASS || defaultPassword },
  { username: process.env.SEED_REQUESTER_USER || 'requester', role: 'requester', password: process.env.SEED_REQUESTER_PASS || defaultPassword },
  { username: process.env.SEED_VIEWER_USER || 'viewer', role: 'viewer', password: process.env.SEED_VIEWER_PASS || defaultPassword },
];

for (const u of usersToSeed) {
  const existing = db.prepare('SELECT id, role FROM users WHERE username = ?').get(u.username);
  if (existing) {
    if (existing.role !== u.role) {
      db.prepare('UPDATE users SET role = ? WHERE id = ?').run(u.role, existing.id);
      console.log(`Updated role for '${u.username}' to ${u.role}.`);
    } else {
      console.log(`User '${u.username}' already exists.`);
    }
    continue;
  }

  const hash = bcrypt.hashSync(u.password, 12);
  db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)').run(u.username, hash, u.role);
  console.log(`Seeded ${u.role} user '${u.username}'.`);
}

console.log('Default seed password (unless overridden by env vars):', defaultPassword);
