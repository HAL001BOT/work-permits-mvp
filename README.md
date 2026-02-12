# Work Permits MVP (Node.js + Express + SQLite)

A lightweight multi-user work permits app for local LAN demos.

## Features

- Multi-user login with hashed passwords (`bcryptjs`)
- Session-based authentication (`express-session` + SQLite session store)
- Permit CRUD
- Persistent storage with SQLite (`better-sqlite3`)
- Filtering by status, site, and date range
- Audit trail for create/update/delete (who + when + old/new values)
- CSV export for permit records

## Tech Stack

- Node.js + Express
- EJS server-rendered views
- SQLite database

## Quick Start

```bash
cd work-permits-mvp
bash scripts/setup.sh
npm start
```

Then open:

- `http://<your-lan-ip>:3000` (LAN)
- `http://localhost:3000` (local)

## Seed Admin User

Default seeded admin credentials:

- Username: `admin`
- Password: `admin123!`

⚠️ Change password quickly for real demos.

You can override seed credentials during setup:

```bash
SEED_ADMIN_USER=supervisor SEED_ADMIN_PASS='StrongPass123!' bash scripts/setup.sh
```

## Manual Setup (without script)

```bash
npm install
node scripts/seed-admin.js
npm start
```

## Environment Variables

- `PORT` (default `3000`)
- `SESSION_SECRET` (strong random value recommended)
- `NODE_ENV=production` (enables secure cookies)
- `SEED_ADMIN_USER` (only for seeding script)
- `SEED_ADMIN_PASS` (only for seeding script)

## Notes for Local LAN Demo Safety

- Passwords are hashed with bcrypt
- Sessions are HttpOnly and SameSite=Lax
- Basic security headers via `helmet`

## Project Structure

- `server.js` - Express app and routes
- `db.js` - SQLite connection + migrations
- `scripts/setup.sh` - install + seed helper
- `scripts/seed-admin.js` - creates default admin if missing
- `views/` - EJS templates
- `public/css/` - basic styling
