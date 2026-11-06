-- Run as the schema owner after `alembic upgrade head`.
-- The application role may append to and read the audit log, never change or remove entries.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM cage_app;
GRANT SELECT, INSERT ON audit_logs TO cage_app;
-- The app never needs to alter role/permission definitions outside of startup sync; keep write access
-- (sync_rbac runs at startup) but deny TRUNCATE everywhere.
REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM cage_app;
-- Audit anchors (Phase 7) are append-only too.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_anchors FROM cage_app;
GRANT SELECT, INSERT ON audit_anchors TO cage_app;
