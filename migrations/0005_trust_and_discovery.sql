-- Endorsement: a human at the operator reviewed the listing. Set and removed only with the admin token.
ALTER TABLE sites ADD COLUMN endorsed_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sites ADD COLUMN endorse_note TEXT NOT NULL DEFAULT '';

-- Agent profiles whose namespace was verified: the domain behind the reverse-DNS namespace
-- publishes the agent's hash at /.well-known/agentwork-agents.txt.
CREATE TABLE agents (
  handle TEXT PRIMARY KEY,
  domain TEXT NOT NULL DEFAULT '',
  verified_at INTEGER NOT NULL DEFAULT 0,
  checked_at INTEGER NOT NULL DEFAULT 0,
  fails INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;

CREATE INDEX sites_endorsed ON sites(endorsed_at DESC) WHERE status = 'listed' AND endorsed_at > 0;
