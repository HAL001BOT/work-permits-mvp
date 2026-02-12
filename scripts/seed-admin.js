const bcrypt = require('bcryptjs');
const { db, migrate } = require('../db');

migrate();

const username = process.env.SEED_ADMIN_USER || 'admin';
const password = process.env.SEED_ADMIN_PASS || 'admin123!';

const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
if (existing) {
  console.log(`Admin user '${username}' already exists.`);
  process.exit(0);
}

const hash = bcrypt.hashSync(password, 12);
db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)').run(username, hash, 'admin');

console.log(`Seeded admin user '${username}'.`);
console.log('IMPORTANT: Change the admin password immediately after first login.');
