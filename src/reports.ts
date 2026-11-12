/**
 * Reports: agents telling the operator that a listing breaks the rules.
 *
 * What a report can and can't do, on purpose:
 *  - It is a signed request, so there is always an accountable key behind it.
 *  - Only an agent that has a verified listing of its own can report. Keys are free; controlling
 *    a real site is not, and that's what keeps one person from filing fifty reports.
 *  - It never removes or hides anything. It goes to a private queue, and a person decides.
 *  - It stays private. An accusation is not published; only an upheld report has a public
 *    effect (the listing is removed, with the category, in the transparency log).
 *  - It gives the reporter nothing: no score, no rank, no weight on later reports.
 *
 * This module only touches the database. The Worker's router does the signature check, the rate
 * limit and the admin check, then calls in here.
 */

/** Why a listing can be reported. The ids are the API; the wording is shown to agents and people. */
export const REPORT_CATEGORIES = {
  illegal: { label: "Illegal content", what: "Content that is against the law where the directory operates, or links to it." },
  malware: { label: "Malware or phishing", what: "The site tries to install something harmful or to steal credentials or payment details." },
  scam: { label: "Scam or fraud", what: "The site takes money or data under false pretences: fake shops, fake investments, fake giveaways." },
  impersonation: { label: "Impersonation", what: "The site pretends to be a person, brand or organisation it isn't." },
  abuse: { label: "Hate or harassment", what: "The site attacks people for who they are, or targets a person for harassment." },
  adult: { label: "Sexual content", what: "The site shows sexually explicit material." },
  spam: { label: "Spam", what: "The site exists only to push links or ads: generated filler, doorway pages, link farms." },
  misleading: { label: "Misleading listing", what: "The title or description shown on the directory doesn't match what the site is." },
  other: { label: "Something else", what: "It breaks the terms in a way the categories above don't cover. Explain in the note." },
} as const;

export type ReportCategory = keyof typeof REPORT_CATEGORIES;
export const isReportCategory = (s: unknown): s is ReportCategory => typeof s === "string" && Object.hasOwn(REPORT_CATEGORIES, s);

export const MAX_REPORT_NOTE = 500;

export interface Report {
  id: string;
  site_id: string;
  url: string;
  reporter: string;
  reporter_pub: string;
  category: ReportCategory;
  note: string;
  body: string;
  signed_at: number;
  signature: string;
  status: "open" | "upheld" | "dismissed";
  decided_at: number;
  decision_note: string;
  decision_sig: string;
  created_at: number;
}

export type Filed =
  | { ok: true; report: Report; duplicate: boolean }
  | { ok: false; status: number; error: string; message: string };

/** Records a report whose signature the caller has already verified. */
export async function fileReport(
  db: D1Database,
  input: {
    id: string;
    siteId: string;
    reporter: string;
    reporterPub: string;
    category: unknown;
    note: unknown;
    body: string;
    signedAt: number;
    signature: string;
  },
): Promise<Filed> {
  if (!isReportCategory(input.category)) {
    return { ok: false, status: 400, error: "bad_category", message: `category must be one of: ${Object.keys(REPORT_CATEGORIES).join(", ")}.` };
  }
  const note = typeof input.note === "string" ? input.note.replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, " ").trim().slice(0, MAX_REPORT_NOTE) : "";
  if (input.category === "other" && note.length < 10) {
    return { ok: false, status: 400, error: "note_required", message: 'The "other" category needs a note saying what is wrong.' };
  }

  const site = await db.prepare("SELECT url, agent_pub FROM sites WHERE id = ? AND status = 'listed'").bind(input.siteId).first<{ url: string; agent_pub: string }>();
  if (!site) return { ok: false, status: 404, error: "not_found", message: "No listed site with this id." };
  if (site.agent_pub && site.agent_pub === input.reporterPub) {
    return { ok: false, status: 400, error: "own_listing", message: "This is your own listing. Remove it instead of reporting it." };
  }

  // Standing: the reporter must have proven control of a site of its own.
  const standing = await db.prepare("SELECT 1 AS ok FROM sites WHERE agent_pub = ? AND status = 'listed' LIMIT 1").bind(input.reporterPub).first();
  if (!standing) {
    return { ok: false, status: 403, error: "no_standing", message: "Only agents with at least one verified listing of their own can report. Anyone can still write to the contact address." };
  }

  const existing = await db.prepare("SELECT * FROM reports WHERE site_id = ? AND reporter_pub = ?").bind(input.siteId, input.reporterPub).first<Report>();
  if (existing) return { ok: true, report: existing, duplicate: true };

  const report: Report = {
    id: input.id,
    site_id: input.siteId,
    url: site.url,
    reporter: input.reporter,
    reporter_pub: input.reporterPub,
    category: input.category,
    note,
    body: input.body,
    signed_at: input.signedAt,
    signature: input.signature,
    status: "open",
    decided_at: 0,
    decision_note: "",
    decision_sig: "",
    created_at: Date.now(),
  };
  try {
    await db
      .prepare(
        "INSERT INTO reports (id, site_id, url, reporter, reporter_pub, category, note, body, signed_at, signature, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)",
      )
      .bind(report.id, report.site_id, report.url, report.reporter, report.reporter_pub, report.category, report.note, report.body, report.signed_at, report.signature, report.created_at)
      .run();
  } catch {
    // Two identical requests raced: the unique index kept one.
    const kept = await db.prepare("SELECT * FROM reports WHERE site_id = ? AND reporter_pub = ?").bind(input.siteId, input.reporterPub).first<Report>();
    if (kept) return { ok: true, report: kept, duplicate: true };
    throw new Error("Could not store the report");
  }
  return { ok: true, report, duplicate: false };
}

/** What a reporter is told about its own report: the outcome, never the operator's private note. */
export const reportForReporter = (r: Report) => ({
  id: r.id,
  site_id: r.site_id,
  url: r.url,
  category: r.category,
  note: r.note,
  status: r.status,
  filed_at: r.created_at,
  ...(r.decided_at ? { decided_at: r.decided_at, decision_signature: r.decision_sig } : {}),
});

export async function getReport(db: D1Database, id: string): Promise<Report | null> {
  return db.prepare("SELECT * FROM reports WHERE id = ?").bind(id).first<Report>();
}

export interface QueueEntry extends Report {
  /** How this reporter's earlier reports ended, so the operator can spot a careless or hostile one. */
  reporter_upheld: number;
  reporter_dismissed: number;
  /** Other open reports on the same listing. */
  open_on_site: number;
}

/** The operator's queue, oldest first. */
export async function reportQueue(db: D1Database, status: Report["status"], limit = 100): Promise<QueueEntry[]> {
  const { results } = await db
    .prepare(
      `SELECT r.*,
         (SELECT COUNT(*) FROM reports x WHERE x.reporter_pub = r.reporter_pub AND x.status = 'upheld') AS reporter_upheld,
         (SELECT COUNT(*) FROM reports x WHERE x.reporter_pub = r.reporter_pub AND x.status = 'dismissed') AS reporter_dismissed,
         (SELECT COUNT(*) FROM reports x WHERE x.site_id = r.site_id AND x.status = 'open') AS open_on_site
       FROM reports r WHERE r.status = ? ORDER BY r.created_at LIMIT ?`,
    )
    .bind(status, limit)
    .all<QueueEntry>();
  return results;
}

export type Decided =
  | { ok: true; report: Report; alsoClosed: number }
  | { ok: false; status: number; error: string; message: string };

/**
 * Marks a report upheld or dismissed. Upholding one closes every open report on that listing in
 * the same category; removing the listing itself is the caller's job, so it goes through the same
 * path, and the same log entry, as any other removal.
 */
export async function decideReport(
  db: D1Database,
  id: string,
  decision: "upheld" | "dismissed",
  note: string,
  sign: (report: Report, ts: number) => Promise<string>,
): Promise<Decided> {
  const report = await getReport(db, id);
  if (!report) return { ok: false, status: 404, error: "not_found", message: "No report with this id." };
  if (report.status !== "open") return { ok: false, status: 409, error: "already_decided", message: `This report was already ${report.status}.` };
  const now = Date.now();
  const clean = note.replace(/\s+/g, " ").trim().slice(0, 300);
  const signature = await sign(report, now);
  await db.prepare("UPDATE reports SET status = ?, decided_at = ?, decision_note = ?, decision_sig = ? WHERE id = ?").bind(decision, now, clean, signature, id).run();
  let alsoClosed = 0;
  if (decision === "upheld") {
    const others = await db
      .prepare("UPDATE reports SET status = 'upheld', decided_at = ?, decision_note = ? WHERE site_id = ? AND category = ? AND status = 'open'")
      .bind(now, `same as ${id}`, report.site_id, report.category)
      .run();
    alsoClosed = others.meta.changes ?? 0;
  }
  return { ok: true, report: { ...report, status: decision, decided_at: now, decision_note: clean, decision_sig: signature }, alsoClosed };
}

/** Public numbers only: how many reports there were and how they ended. Never who or what. */
export async function reportTotals(db: D1Database): Promise<{ open: number; upheld: number; dismissed: number }> {
  const { results } = await db.prepare("SELECT status, COUNT(*) AS n FROM reports GROUP BY status").all<{ status: Report["status"]; n: number }>();
  const totals = { open: 0, upheld: 0, dismissed: 0 };
  for (const row of results) totals[row.status] = row.n;
  return totals;
}
