-- 0001: the document index (spec, Normalization). Times are RFC 3339 UTC text,
-- NULL when unknown. provider_id is NULL for documents without a supplier id,
-- so they never collide on the unique key (SQLite treats NULLs as distinct).
CREATE TABLE IF NOT EXISTS documents (
	id           INTEGER PRIMARY KEY,
	provider     TEXT    NOT NULL CHECK (provider <> ''),
	provider_id  TEXT             CHECK (provider_id IS NULL OR provider_id <> ''),
	kind         TEXT    NOT NULL,
	issued_at    TEXT,
	period_start TEXT,
	period_end   TEXT,
	amount_cents INTEGER,
	currency     TEXT    NOT NULL,
	sha256       BLOB    NOT NULL CHECK (length(sha256) = 32),
	local_path   TEXT    NOT NULL,
	drive_id     TEXT    NOT NULL,
	collected_at TEXT    NOT NULL,
	version      INTEGER NOT NULL CHECK (version >= 1),
	UNIQUE (provider, provider_id, version)
) STRICT;

CREATE INDEX IF NOT EXISTS documents_sha256 ON documents (sha256);
