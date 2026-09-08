-- supportlab schema. Portable across SQLite (in-process lane) and PostgreSQL (container lane).
-- Generated from src/purpleloop/fixture/supportlab/schema.py; a test guards that they match.
-- Identifiers are application-assigned and seed-derived; no SERIAL, IDENTITY, now(), random(),
-- or gen_random_uuid() appears anywhere, so nothing here can reach scored output.
CREATE TABLE orgs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    seq INTEGER NOT NULL
);
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs (id),
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    display_name TEXT NOT NULL,
    credit_limit INTEGER NOT NULL,
    seq INTEGER NOT NULL
);
CREATE TABLE tickets (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs (id),
    author_id TEXT NOT NULL REFERENCES users (id),
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    status TEXT NOT NULL,
    priority TEXT NOT NULL,
    assignee_id TEXT,
    seq INTEGER NOT NULL
);
CREATE TABLE documents (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs (id),
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    classification TEXT NOT NULL,
    seq INTEGER NOT NULL
);
CREATE TABLE approvals (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs (id),
    kind TEXT NOT NULL,
    amount INTEGER NOT NULL,
    approver_id TEXT NOT NULL REFERENCES users (id),
    seq INTEGER NOT NULL
);
CREATE TABLE refunds (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs (id),
    ticket_id TEXT NOT NULL REFERENCES tickets (id),
    amount INTEGER NOT NULL,
    approval_id TEXT,
    is_approved INTEGER NOT NULL,
    status TEXT NOT NULL,
    seq INTEGER NOT NULL
);
CREATE TABLE exports (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs (id),
    requester_id TEXT NOT NULL REFERENCES users (id),
    destination TEXT NOT NULL,
    approval_id TEXT,
    is_approved INTEGER NOT NULL,
    canary_exposed INTEGER NOT NULL,
    seq INTEGER NOT NULL
);
CREATE TABLE canaries (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs (id),
    value TEXT NOT NULL,
    seq INTEGER NOT NULL
);
CREATE TABLE audit (
    tick INTEGER PRIMARY KEY,
    operation TEXT NOT NULL,
    rule_id TEXT,
    actor_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    is_unauthorized INTEGER NOT NULL,
    is_write INTEGER NOT NULL,
    is_blocked INTEGER NOT NULL
);
CREATE TABLE meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE idempotency (
    key TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    response TEXT NOT NULL
);
