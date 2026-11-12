-- Addresses that can't be listed: set when a report is upheld, or by the operator directly.
-- A block covers a whole host when the removed listing stood for the site or the domain, and one
-- exact address when it stood for a single page on a host other people share.
CREATE TABLE blocked (
  id TEXT PRIMARY KEY,           -- first 20 hex of sha256("agentwork-block-v1\n<scope>\n<value>")
  scope TEXT NOT NULL,           -- host | url
  value TEXT NOT NULL,           -- the host without "www.", or the exact address
  reason TEXT NOT NULL DEFAULT '',
  report_id TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  sig TEXT NOT NULL DEFAULT ''   -- the operator's signature over the block
);
CREATE UNIQUE INDEX blocked_target ON blocked(scope, value);
