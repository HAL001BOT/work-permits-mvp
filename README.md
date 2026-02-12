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
- Branded PDF exports for single permits and filtered summaries (`pdfkit`) with logo/header cards, themed tables, and footer metadata
- Improved dashboard, forms, table view, and permit detail page for easier visualization

## Tech Stack

- Node.js + Express
- EJS server-rendered views
- SQLite database
- PDF generation with `pdfkit`

## Quick Start

```bash
cd work-permits-mvp
bash scripts/setup.sh
npm start
```

Then open:

- `http://<your-lan-ip>:3000` (LAN)
- `http://localhost:3000` (local)

## Using Exports and Views

- **Dashboard:** `/permits` includes filter controls, status summary cards, and action links.
- **Permit detail:** click **View** on any permit row to open a readable detail page.
- **Single permit PDF:** click **PDF** in a permit row (or open `/permits/:id/export.pdf`) for a branded permit sheet with section cards and detailed metadata.
- **Filtered summary PDF:** use dashboard filters then click **Export PDF Summary** (or open `/permits/export.pdf` with the same query string) for a themed report table with totals and filters.
- **CSV export:** still available via **Export CSV** with the active filters.

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
