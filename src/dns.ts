/**
 * DNS as a place to publish a proof: a TXT record at _agentwork.<host>. Only whoever controls the
 * domain's DNS can create it, so it's the strongest of the three ways to prove control.
 * Lookups go through a public DNS-over-HTTPS resolver.
 */

const RESOLVER = "https://cloudflare-dns.com/dns-query";
export const DNS_LABEL = "_agentwork";

/**
 * The TXT values in a DNS-over-HTTPS JSON answer. A value longer than 255 bytes arrives as
 * several quoted chunks ("part one" "part two"): they are joined back into one string.
 */
export function txtValues(answer: unknown): string[] {
  const records = (answer as { Answer?: { type?: number; data?: unknown }[] } | null)?.Answer;
  if (!Array.isArray(records)) return [];
  const out: string[] = [];
  for (const r of records) {
    if (r?.type !== 16 || typeof r.data !== "string") continue;
    const chunks = [...r.data.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1].replace(/\\(.)/g, "$1"));
    out.push(chunks.length ? chunks.join("") : r.data);
  }
  return out;
}

/** TXT values at a name, or null when the resolver couldn't be reached. */
export async function lookupTxt(name: string): Promise<string[] | null> {
  try {
    const res = await fetch(`${RESOLVER}?name=${encodeURIComponent(name)}&type=TXT`, {
      headers: { accept: "application/dns-json" },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;
    return txtValues(await res.json());
  } catch {
    return null;
  }
}
