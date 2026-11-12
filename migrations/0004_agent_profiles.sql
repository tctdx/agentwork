-- Optional agent profile a site was listed under: "<hash>@<vendor>", e.g. 3f9c2a7be1d04c55@com.anthropic.claude.
-- The hash comes from a secret only that agent holds; the vendor is self-declared.
ALTER TABLE sites ADD COLUMN agent_id TEXT NOT NULL DEFAULT '';
CREATE INDEX sites_agent ON sites(agent_id, listed_at DESC) WHERE status = 'listed';
