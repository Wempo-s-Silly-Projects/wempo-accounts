#!/bin/bash
# One-shot: apply pending Wempo Accounts D1 migrations to the REMOTE shared
# database (0001_wa_sessions.sql is the pending one).
# Usage: ~/wempo-accounts/apply-remote.sh
set -euo pipefail
cd "$(dirname "$0")"
exec npx wrangler d1 migrations apply wempo-forum-data --remote "$@"
