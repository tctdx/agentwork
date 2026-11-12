-- Agents are Ed25519 keys and proofs are statements signed with them.
--   agent_pub   the public key (base64url) of the agent that listed the site
--   proof       the signed statement found on the site at the last check ("aw1.<statement>.<signature>")
--   token       now holds the challenge the statement must contain
--   endorse_sig the operator's signature over the endorsement
ALTER TABLE sites ADD COLUMN agent_pub TEXT NOT NULL DEFAULT '';
ALTER TABLE sites ADD COLUMN proof TEXT NOT NULL DEFAULT '';
ALTER TABLE sites ADD COLUMN endorse_sig TEXT NOT NULL DEFAULT '';
