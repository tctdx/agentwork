-- How the site proved control (file | meta) and the security headers seen at the last check.
ALTER TABLE sites ADD COLUMN method TEXT NOT NULL DEFAULT '';
ALTER TABLE sites ADD COLUMN security TEXT NOT NULL DEFAULT '';

-- Public, append-only, hash-chained log of everything that happens to listings.
-- hash = sha256(prev \n seq \n ts \n type \n site_id \n url_hash \n detail). The chain covers the
-- URL's hash, not the URL, so a URL can be redacted on request without breaking the chain.
CREATE TABLE log (
  seq INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  type TEXT NOT NULL,          -- listed | checked | check_failed | delisted | removed
  site_id TEXT NOT NULL,
  url TEXT,                    -- NULL when redacted
  url_hash TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  prev TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX log_site ON log(site_id, seq);

-- Listings made before this migration proved control with the file; re-check them on the next run.
UPDATE sites SET method = 'file', checked_at = 0 WHERE status = 'listed';
