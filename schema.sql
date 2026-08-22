PRAGMA foreign_keys = ON;

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE capsules (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  unlock_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'DRAFT' CHECK(status IN ('DRAFT','LOCKED','OPEN')),
  visibility TEXT NOT NULL DEFAULT 'PRIVATE' CHECK(visibility IN ('PRIVATE','FAMILY','PUBLIC')),
  locked_at TEXT,
  opened_at TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE entries (
  id TEXT PRIMARY KEY,
  capsule_id TEXT NOT NULL,
  year INTEGER NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('NOTE','LETTER','PHOTO','AUDIO','VIDEO','DOCUMENT','ART','FAMILY')),
  title TEXT,
  content TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(capsule_id) REFERENCES capsules(id)
);

CREATE TABLE media (
  id TEXT PRIMARY KEY,
  capsule_id TEXT NOT NULL,
  entry_id TEXT,
  type TEXT NOT NULL,
  file_key TEXT NOT NULL,
  sha256 TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(capsule_id) REFERENCES capsules(id),
  FOREIGN KEY(entry_id) REFERENCES entries(id)
);

CREATE TABLE family_members (
  id TEXT PRIMARY KEY,
  capsule_id TEXT NOT NULL,
  name TEXT NOT NULL,
  surname TEXT,
  relation TEXT,
  birth_date TEXT,
  biography TEXT,
  photo_key TEXT,
  FOREIGN KEY(capsule_id) REFERENCES capsules(id)
);

CREATE TABLE participants (
  id TEXT PRIMARY KEY,
  capsule_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('OWNER','EDITOR','VIEWER')),
  FOREIGN KEY(capsule_id) REFERENCES capsules(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE security_layers (
  id TEXT PRIMARY KEY,
  capsule_id TEXT NOT NULL,
  layer_type TEXT NOT NULL,
  config_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(capsule_id) REFERENCES capsules(id)
);

CREATE TABLE audit_logs (
  id TEXT PRIMARY KEY,
  capsule_id TEXT NOT NULL,
  action TEXT NOT NULL,
  previous_hash TEXT,
  record_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(capsule_id) REFERENCES capsules(id)
);

CREATE INDEX idx_capsules_unlock ON capsules(unlock_at, status);
CREATE INDEX idx_entries_capsule_year ON entries(capsule_id, year);
CREATE INDEX idx_public_open ON capsules(visibility, status, unlock_at);
