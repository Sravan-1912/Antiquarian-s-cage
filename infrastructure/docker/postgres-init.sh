#!/bin/sh
# Creates the least-privilege application role. The schema owner (cage_owner) runs migrations;
# the API connects as cage_app, which cannot alter schema, and can only INSERT/SELECT audit_logs.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE ROLE cage_app LOGIN PASSWORD '${APP_DB_PASSWORD}';
GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO cage_app;
GRANT USAGE ON SCHEMA public TO cage_app;
ALTER DEFAULT PRIVILEGES FOR ROLE ${POSTGRES_USER} IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO cage_app;
ALTER DEFAULT PRIVILEGES FOR ROLE ${POSTGRES_USER} IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO cage_app;
SQL
# Tightening for audit_logs (applied after migrations): see infrastructure/scripts/harden_db.sql
