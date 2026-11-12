/**
 * The block list: addresses that can't be listed. A listing removed after a report would
 * otherwise be one signed request away from coming back.
 *
 * A block is as wide as what the removed listing stood for, and no wider:
 *  - the whole host, when the listing proved control of the site or the domain;
 *  - one exact address, when it proved control of a single page, because on such hosts the other
 *    pages belong to other people.
 * Blocks are made and lifted only by the operator, signed, and written to the public log.
 * This module only touches the database.
 */

export interface Block {
  id: string;
  scope: "host" | "url";
  value: string;
  reason: string;
  report_id: string;
  created_at: number;
  sig: string;
}

const bare = (host: string) => host.toLowerCase().replace(/^www\./, "");

/** What blocking a listing covers. `method` is how it proved control (dns, file or meta). */
export function blockTarget(url: string, method: string): Pick<Block, "scope" | "value"> {
  const u = new URL(url);
  const onePage = u.pathname !== "/" && method !== "dns";
  return onePage ? { scope: "url", value: u.href } : { scope: "host", value: bare(u.hostname) };
}

/** The block that covers this address, if any. */
export async function blockFor(db: D1Database, url: URL): Promise<Block | null> {
  return db
    .prepare("SELECT * FROM blocked WHERE (scope = 'host' AND value = ?) OR (scope = 'url' AND value = ?) LIMIT 1")
    .bind(bare(url.hostname), url.href)
    .first<Block>();
}

export async function addBlock(db: D1Database, block: Block): Promise<boolean> {
  const done = await db
    .prepare("INSERT OR IGNORE INTO blocked (id, scope, value, reason, report_id, created_at, sig) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .bind(block.id, block.scope, block.value, block.reason, block.report_id, block.created_at, block.sig)
    .run();
  return (done.meta.changes ?? 0) > 0;
}

export async function removeBlock(db: D1Database, id: string): Promise<Block | null> {
  const block = await db.prepare("SELECT * FROM blocked WHERE id = ?").bind(id).first<Block>();
  if (block) await db.prepare("DELETE FROM blocked WHERE id = ?").bind(id).run();
  return block;
}

export async function listBlocks(db: D1Database): Promise<Block[]> {
  const { results } = await db.prepare("SELECT * FROM blocked ORDER BY created_at DESC LIMIT 500").all<Block>();
  return results;
}
