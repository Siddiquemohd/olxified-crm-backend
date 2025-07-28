#!/bin/sh
set -e

echo "🏗 Running TypeScript build..."
# Not needed in production; already built
# npm run build

echo "🧩 Syncing database..."
node dist/database/sync.js || {
  echo "❌ Failed to sync database"
  exit 1
}

echo "🚀 Starting backend server..."
node dist/index.js
