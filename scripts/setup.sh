#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "Installing dependencies..."
npm install

echo "Running DB migrations + seed users..."
node scripts/seed-users.js

echo "Setup complete."
echo "Run: npm start"
