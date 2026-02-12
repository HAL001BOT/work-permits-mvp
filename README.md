# Work Permits MVP (Node.js + Express + SQLite)

A lightweight multi-user work permits app for local LAN demos.

## Features

- Multi-user login with hashed passwords (`bcryptjs`)
- Session-based authentication (`express-session` + SQLite session store)
- **RBAC roles:** `admin`, `supervisor`, `requester`, `viewer`
- **Server-side permission enforcement** for create/edit/delete/transition/upload actions
- **Approval workflow** with explicit transitions:
  - `draft -> submitted` (requester owner, supervisor, admin)
  - `submitted -> approved` (supervisor/admin only, signature required)
  - `approved -> closed` (supervisor/admin only)
  - `approved|closed -> draft` via reopen (supervisor/admin only, revision increments)
- **Digital signatures:** approval captures signature text + approver name + timestamp
- **Record locking:** permits lock after approve/close; key fields become non-editable until reopened
- **Attachments/evidence:** upload to local storage with safe naming + size/type checks, list/download, optional delete (supervisor/admin)
- Comprehensive audit trail for create/update/delete, transitions, signatures, and attachment operations
- CSV export for permit records
- Branded single-permit PDF export (`pdfkit`)

## Tech Stack

- Node.js + Express
- EJS server-rendered views
- SQLite database (`better-sqlite3`)
- Multer for file uploads
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

## Default Seeded Users

By default, setup seeds one user for each role:

- `admin` / `permit123!`
- `supervisor` / `permit123!`
- `requester` / `permit123!`
- `viewer` / `permit123!`

⚠️ Change all passwords for real environments.

You can override usernames/passwords with env vars before running setup:

- `SEED_DEFAULT_PASS`
- `SEED_ADMIN_USER`, `SEED_ADMIN_PASS`
- `SEED_SUPERVISOR_USER`, `SEED_SUPERVISOR_PASS`
- `SEED_REQUESTER_USER`, `SEED_REQUESTER_PASS`
- `SEED_VIEWER_USER`, `SEED_VIEWER_PASS`

## Workflow Usage

1. Requester creates permit (starts in `draft`).
2. Requester submits permit when ready.
3. Supervisor/admin approves permit and enters signature text.
4. Supervisor/admin closes permit when work is complete.
5. If changes are needed after approval/closure, supervisor/admin reopens permit (new revision, unlocked).

## Attachments

- Upload evidence files on permit detail page.
- File constraints:
  - max size: 10 MB
  - allowed MIME: PDF, JPG/PNG/GIF, TXT, DOC/DOCX
- Files are stored locally in `data/uploads` with randomized stored names.
- Download is available from permit detail page.
- Delete attachment is available to supervisor/admin.

## Manual Setup (without script)

```bash
npm install
node scripts/seed-users.js
npm start
```

## Environment Variables

- `PORT` (default `3000`)
- `SESSION_SECRET` (strong random value recommended)
- `NODE_ENV=production` (enables secure cookies)

## DB / Migration Notes

`db.js` includes migration steps for:

- base schema
- RBAC role normalization
- workflow/signature/locking/revision columns
- attachments table + index

## Project Structure

- `server.js` - Express app and routes
- `db.js` - SQLite connection + migrations
- `scripts/setup.sh` - install + seed helper
- `scripts/seed-users.js` - seeds role users
- `views/` - EJS templates
- `public/css/` - styles
