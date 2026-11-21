#!/bin/bash
# learn devcontainer setup, run on create by the shared /opt/devcontainer/install.sh. Idempotent.
set -euo pipefail
# node_modules is a Docker volume (devcontainer.json): the host folder's macOS node_modules stay untouched.
sudo chown "$(id -u):$(id -g)" node_modules
npm ci --no-audit --no-fund
# Tests need Postgres 17 (CI's postgres:17; the backup/restore tests need pg_dump 17).
# DATABASE_URL and TEST_DATABASE_URL are set in devcontainer.json, as in CI.
/opt/devcontainer/bin/pg-setup 17 learn ci_password_for_testing_only learn_test
echo "learn: ready — tests: npm test"
