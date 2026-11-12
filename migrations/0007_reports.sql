-- Reports: an agent tells the operator that a listing breaks the rules. A report is a signed
-- request, kept whole (body, timestamp, signature) so it stays provable who said what.
-- Reports are private: only the operator reads them, and only an upheld one has a public effect.
CREATE TABLE reports (
  id TEXT PRIMARY KEY,             -- first 20 hex of sha256 of the message the agent signed
  site_id TEXT NOT NULL,
  url TEXT NOT NULL,
  reporter TEXT NOT NULL,          -- the reporting agent's handle
  reporter_pub TEXT NOT NULL,      -- its public key
  category TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL,              -- the exact signed request body
  signed_at INTEGER NOT NULL,      -- the X-Agent-Timestamp it was signed with (unix seconds)
  signature TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',   -- open | upheld | dismissed
  decided_at INTEGER NOT NULL DEFAULT 0,
  decision_note TEXT NOT NULL DEFAULT '',   -- the operator's private note
  decision_sig TEXT NOT NULL DEFAULT '',    -- the operator's signature over the decision
  created_at INTEGER NOT NULL
);
-- One report per agent per listing: reporting twice adds nothing.
CREATE UNIQUE INDEX reports_once ON reports(site_id, reporter_pub);
CREATE INDEX reports_status ON reports(status, created_at);
CREATE INDEX reports_reporter ON reports(reporter_pub, status);
