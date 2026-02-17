const bcrypt = require('bcryptjs');
const { db, migrate } = require('../db');

migrate();

const defaultPassword = process.env.SEED_DEFAULT_PASS || 'permit123!';
const usersToSeed = [
  { username: process.env.SEED_ADMIN_USER || 'admin', role: 'admin', password: process.env.SEED_ADMIN_PASS || defaultPassword, group_name: '' },
  { username: process.env.SEED_SUPERVISOR_USER || 'supervisor', role: 'supervisor', password: process.env.SEED_SUPERVISOR_PASS || defaultPassword, group_name: 'supervisors' },
  { username: process.env.SEED_REQUESTER_USER || 'requester', role: 'requester', password: process.env.SEED_REQUESTER_PASS || defaultPassword, group_name: '' },
  { username: process.env.SEED_VIEWER_USER || 'viewer', role: 'viewer', password: process.env.SEED_VIEWER_PASS || defaultPassword, group_name: '' },
];

const staffSeeds = [
  { username: 'supervisor1', role: 'supervisor', password: defaultPassword, group_name: 'supervisors' },
  { username: 'supervisor2', role: 'supervisor', password: defaultPassword, group_name: 'supervisors' },
  { username: 'supervisor3', role: 'supervisor', password: defaultPassword, group_name: 'supervisors' },
  { username: 'operator1', role: 'requester', password: defaultPassword, group_name: 'operators' },
  { username: 'operator2', role: 'requester', password: defaultPassword, group_name: 'operators' },
  { username: 'operator3', role: 'requester', password: defaultPassword, group_name: 'operators' },
  { username: 'operator4', role: 'requester', password: defaultPassword, group_name: 'operators' },
  { username: 'operator5', role: 'requester', password: defaultPassword, group_name: 'operators' },
];

for (const u of [...usersToSeed, ...staffSeeds]) {
  const existing = db.prepare('SELECT id, role, group_name FROM users WHERE username = ?').get(u.username);
  if (existing) {
    const updates = [];
    const values = [];
    if (existing.role !== u.role) {
      updates.push('role = ?');
      values.push(u.role);
    }
    if (u.group_name && existing.group_name !== u.group_name) {
      updates.push('group_name = ?');
      values.push(u.group_name);
    }
    if (updates.length) {
      db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...values, existing.id);
      console.log(`Updated user '${u.username}': ${updates.join(', ')}.`);
    } else {
      console.log(`User '${u.username}' already exists.`);
    }
    continue;
  }

  const hash = bcrypt.hashSync(u.password, 12);
  const columns = ['username', 'password_hash', 'role'];
  const params = [u.username, hash, u.role];
  if (u.group_name) {
    columns.push('group_name');
    params.push(u.group_name);
  }
  const placeholders = columns.map(() => '?').join(', ');
  db.prepare(`INSERT INTO users (${columns.join(', ')}) VALUES (${placeholders})`).run(...params);
  console.log(`Seeded ${u.role} user '${u.username}' with group '${u.group_name || 'none'}'.`);
}

console.log('Default seed password (unless overridden by env vars):', defaultPassword);
