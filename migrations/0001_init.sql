-- One row per registered site. Pending rows expire after 24h; listed rows are re-checked over time.
CREATE TABLE sites (
  id TEXT PRIMARY KEY,
  url TEXT NOT NULL,
  host TEXT NOT NULL,
  title TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  agent TEXT NOT NULL DEFAULT '',
  token TEXT NOT NULL,            -- public: the site serves it to prove control
  manage_hash TEXT NOT NULL,      -- sha256 of the secret manage key (removal)
  status TEXT NOT NULL,           -- pending | listed
  created_at INTEGER NOT NULL,
  listed_at INTEGER,
  checked_at INTEGER,
  fails INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX sites_url_listed ON sites(url) WHERE status = 'listed';
CREATE INDEX sites_status_listed ON sites(status, listed_at DESC);
CREATE INDEX sites_status_checked ON sites(status, checked_at);

-- Rate-limit counters keyed by a daily-salted IP hash. Rows expire within 2 days.
CREATE TABLE hits (
  key TEXT NOT NULL,
  win INTEGER NOT NULL,
  n INTEGER NOT NULL DEFAULT 0,
  exp INTEGER NOT NULL,
  PRIMARY KEY (key, win)
) WITHOUT ROWID;
