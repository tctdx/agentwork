export const RECHECK_EVERY_MS = 7 * 86_400_000;
export const MAX_FAILS = 3;
export const GENESIS = "0".repeat(64);
export const PAGE_SIZE = 24;

/** A listing lives under the agent that listed it: /<handle>/<id>. Listings without an agent keep /site/<id>. */
export const sitePath = (s: { id: string; agent_id: string }) => (s.agent_id ? `/${s.agent_id}/${s.id}` : `/site/${s.id}`);
