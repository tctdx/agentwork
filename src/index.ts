/**
 * agentwork: a directory of sites people built, listed by their agents.
 *
 * An agent lists a site in three calls:
 *   1. POST /api/sites {url}          → a public token + a secret manage key
 *   2. the site serves the token      → /.well-known/agentwork.txt or <meta name="agentwork-verify">
 *   3. POST /api/sites/:id/verify     → we fetch the site, check the token, read its own title
 * Nothing is listed without proof that whoever asked controls the site, and listed sites are
 * re-checked over time: if the site goes away or drops the token, it leaves the directory.
 *
 * Transparency: every listing, check, failure and removal goes into a public, hash-chained log
 * (/log, /api/log) that anyone can verify, and each listing has a page showing how it proved
 * control and which security headers the site sent at its last check.
 *
 * Screenshots: a headless browser (Browser Rendering) captures each listed page at its final
 * size and stores it in the R2 bucket served at IMG_BASE. No image transforms.
 *
 * Signatures (see crypto.ts): an agent is an Ed25519 key. It signs its requests, and the proof a
 * site publishes is a statement signed with that key, so anyone can check a listing without
 * trusting this server. The operator has its own key and signs receipts, endorsements and the
 * head of the log. An agent's profile, /<hash>@<namespace>, is a fingerprint of its public key;
 * the namespace is self-declared until the domain behind it publishes that fingerprint.
 *
 * A trusted process holding REVERIFY_TOKEN can re-verify any listing on demand
 * (POST /api/sites/:id/reverify): same check as the weekly one, plus a fresh screenshot.
 */
import puppeteer from "@cloudflare/puppeteer";
import clientScript from "./client.mjs.txt";
import {
  agentHandle,
  endorseMessage,
  HANDLE_HASH_LENGTH,
  isPublicKey,
  logHeadMessage,
  operator,
  PROOF_PREFIX,
  proofToSign,
  readProof,
  receiptMessage,
  requestMessage,
  sha256Hex,
  verifySignature,
  type Statement,
} from "./crypto";
import { GENESIS, MAX_FAILS, PAGE_SIZE, RECHECK_EVERY_MS, sitePath } from "./constants";
import { DNS_LABEL, lookupTxt } from "./dns";
import { agentPage, agentsIndexPage, agentsMd, homePage, logPage, notFoundPage, privacyPage, sitePage, styles, trustPage } from "./pages";

export interface Env {
  DB: D1Database;
  IMG: R2Bucket;
  BROWSER: Fetcher;
  /** Public address of this directory, e.g. https://agentwork.example.com */
  SITE_URL: string;
  /** Public address of the screenshot bucket, e.g. https://img.example.com */
  IMG_BASE: string;
  CONTACT_EMAIL: string;
  /** Shown in the header ("by …") and in the privacy page. */
  OPERATOR_NAME: string;
  OPERATOR_URL: string;
  /** Who runs it, for the privacy page, e.g. "Jane Doe, a private individual in France". */
  OPERATOR_LEGAL: string;
  HASH_SALT: string;
  /** The operator's Ed25519 private key, PKCS#8 in base64. Its public half is published. */
  OPERATOR_SIGNING_KEY: string;
  ADMIN_TOKEN: string;
  REVERIFY_TOKEN: string;
}

/** Everything specific to one deployment, read from the Worker's vars. */
export interface Config {
  site: string;
  host: string;
  imgBase: string;
  imgOrigin: string;
  contact: string;
  operatorName: string;
  operatorUrl: string;
  operatorLegal: string;
}

function config(env: Env): Config {
  const site = env.SITE_URL.replace(/\/+$/, "");
  const imgBase = env.IMG_BASE.replace(/\/+$/, "");
  return {
    site,
    host: new URL(site).host,
    imgBase,
    imgOrigin: new URL(imgBase).origin,
    contact: env.CONTACT_EMAIL,
    operatorName: env.OPERATOR_NAME,
    operatorUrl: env.OPERATOR_URL,
    operatorLegal: env.OPERATOR_LEGAL,
  };
}

export interface Security {
  hsts: boolean;
  csp: boolean;
  frame: boolean;
  nosniff: boolean;
  referrer: boolean;
}

export interface Listing {
  id: string;
  url: string;
  host: string;
  title: string;
  description: string;
  agent: string;
  agent_id: string;
  /** The agent's Ed25519 public key. Empty on listings made before signatures. */
  agent_pub: string;
  /** The signed statement found on the site at the last check. */
  proof: string;
  challenge: string;
  method: string;
  security: Security | null;
  listed_at: number;
  checked_at: number;
  /** Failed checks in a row since the last good one. */
  fails: number;
  shot_url: string | null;
  shot_at: number;
  /** Set when a human at the operator reviewed the listing. */
  endorsed_at: number;
  endorse_note: string;
  endorse_sig: string;
  /** Domain that vouches for the agent's namespace, when verified. */
  agent_domain: string | null;
  /** The listing's page on the directory. */
  page: string;
}

export interface Query {
  q: string;
  filter: "all" | "endorsed";
  sort: "new" | "checked";
  page: number;
}

export interface AgentSummary {
  handle: string;
  name: string | null;
  sites: number;
  since: number;
  domain: string | null;
}

export interface LogEvent {
  seq: number;
  ts: number;
  type:
    | "listed"
    | "checked"
    | "check_failed"
    | "delisted"
    | "removed"
    | "endorsed"
    | "unendorsed"
    | "claimed"
    | "agent_verified"
    | "agent_unverified";
  site_id: string;
  url: string | null;
  url_hash: string;
  detail: string;
  prev: string;
  hash: string;
}

const PENDING_TTL_MS = 24 * 3600_000;
const MAX_PENDING = 2000;
const MAX_BODY = 4096;
const MAX_PAGE_BYTES = 512 * 1024;
const FETCH_TIMEOUT_MS = 8000;
const RECHECK_PER_RUN = 10;
const SHOTS_PER_RUN = 3; // browser time is limited: the cron only fills in missing or old screenshots
const SHOT_MAX_AGE_MS = 30 * 86_400_000;
const SHOT_VIEWPORT = { width: 1280, height: 800, deviceScaleFactor: 1 };
const SHOT_TIMEOUT_MS = 20_000; // page load
const SHOT_BUDGET_MS = 40_000; // whole capture, browser launch included
const LIMITS = {
  register: { n: 10, windowSec: 3600 },
  verify: { n: 30, windowSec: 3600 },
} as const;
const userAgent = (env: Env) => `agentwork-verifier/1.0 (+${config(env).site}/agents.md)`;
const LISTING_COLUMNS =
  "id, url, host, title, description, agent, agent_id, agent_pub, proof, token AS challenge, method, security, listed_at, checked_at, fails, shot, shot_at, endorsed_at, endorse_note, endorse_sig, " +
  "(SELECT domain FROM agents a WHERE a.handle = sites.agent_id AND a.verified_at > 0) AS agent_domain";
const AGENT_RECHECK_PER_RUN = 5;
const AGENTS_FILE = "/.well-known/agentwork-agents.txt";
const SIGNATURE_WINDOW_S = 300;

const enc = new TextEncoder();

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const c = config(env);
    try {
      if (path.startsWith("/api/")) return withCors(await api(request, env, ctx, path, url));
      if (request.method !== "GET" && request.method !== "HEAD") return text("Method not allowed", 405);
      // A listing's address names its agent: /<handle>/<id>. The older /site/<id> redirects there.
      const nested = path.startsWith("/site/") ? null : /^\/([^/]+)\/([0-9a-f]{20})$/.exec(path);
      if (nested || path.startsWith("/site/")) {
        const site = await listing(env, nested ? nested[2] : path.slice(6));
        if (!site) return html(c, notFoundPage(c), 404);
        if (path !== sitePath(site)) {
          if (nested) return html(c, notFoundPage(c), 404);
          return new Response(null, { status: 308, headers: { location: sitePath(site) } });
        }
        return html(c, sitePage(c, site, await siteEvents(env, site.id), await receiptFor(env, site)));
      }
      const handle = parseHandle(safeDecode(path.slice(1)));
      if (handle) {
        const sites = await listedBy(env, handle.id);
        if (!sites.length) return html(c, notFoundPage(c), 404);
        return html(c, agentPage(c, handle, sites, await siteEvents(env, handle.id)));
      }
      switch (path) {
        case "/": {
          const query = parseQuery(url);
          const found = await searchListed(env, query, PAGE_SIZE);
          return html(c, homePage(c, query, found.sites, found.total, await countListed(env), await countEndorsed(env)));
        }
        case "/agents":
          return html(c, agentsIndexPage(c, await agentSummaries(env)));
        case "/trust":
          return html(c, trustPage(c, (await operatorOrNull(env))?.publicKey ?? ""));
        case "/agentwork.mjs":
          return text(clientScript.replace("__SITE__", c.site), 200, "text/javascript; charset=utf-8");
        case "/.well-known/agentwork-operator.json":
          return json({ alg: "Ed25519", key: (await operator(env.OPERATOR_SIGNING_KEY)).publicKey, signs: ["log head", "listing receipts", "endorsements"], formats: `${c.site}/agents.md` });
        case "/random": {
          const pick = await env.DB.prepare("SELECT id, agent_id FROM sites WHERE status = 'listed' ORDER BY RANDOM() LIMIT 1").first<{ id: string; agent_id: string }>();
          return new Response(null, { status: 302, headers: { location: pick ? sitePath(pick) : "/", "cache-control": "no-store" } });
        }
        case "/log":
          return html(c, logPage(c, await recentEvents(env, 100), await signedHead(env)));
        case "/agents.md":
        case "/llms.txt":
          return text(agentsMd(c), 200, "text/markdown; charset=utf-8");
        case "/privacy":
          return html(c, privacyPage(c));
        case "/style.css":
          return text(styles, 200, "text/css; charset=utf-8", "public, max-age=3600");
        case "/robots.txt":
          return text("User-agent: *\nAllow: /\n", 200);
        default:
          return html(c, notFoundPage(c), 404);
      }
    } catch (err) {
      console.error(err);
      return path.startsWith("/api/") ? withCors(apiError(500, "internal", "Something broke on our side.")) : text("Server error", 500);
    }
  },

  async scheduled(_event, env): Promise<void> {
    const now = Date.now();
    await env.DB.batch([
      env.DB.prepare("DELETE FROM sites WHERE status = 'pending' AND created_at < ?").bind(now - PENDING_TTL_MS),
      env.DB.prepare("DELETE FROM hits WHERE exp < ?").bind(now),
    ]);
    // Re-check the listings that were checked longest ago.
    const { results } = await env.DB.prepare(
      `SELECT ${CHECK_COLUMNS} FROM sites WHERE status = 'listed' AND checked_at < ? ORDER BY checked_at LIMIT ?`,
    )
      .bind(now - RECHECK_EVERY_MS, RECHECK_PER_RUN)
      .all<CheckRow>();
    const agents = await env.DB.prepare("SELECT handle FROM agents WHERE verified_at > 0 AND checked_at < ? ORDER BY checked_at LIMIT ?")
      .bind(now - RECHECK_EVERY_MS, AGENT_RECHECK_PER_RUN)
      .all<{ handle: string }>();
    for (const a of agents.results) {
      const handle = parseHandle(a.handle);
      if (handle) await verifyNamespace(env, handle);
    }
    let shots = 0;
    for (const row of results) {
      const outcome = await recheck(env, row, "schedule");
      if (outcome.result === "checked" && shots < SHOTS_PER_RUN && (!row.shot || row.shot_at < now - SHOT_MAX_AGE_MS)) {
        shots++;
        await captureShot(env, row);
      }
    }
  },
} satisfies ExportedHandler<Env>;

// ---------- API ----------

async function api(request: Request, env: Env, ctx: ExecutionContext, path: string, url: URL): Promise<Response> {
  if (request.method === "OPTIONS") return new Response(null, { status: 204 });
  const parts = path.split("/").slice(2); // ["sites", id?, "verify"?] or ["log"]

  if (parts[0] === "log" && parts.length === 1 && request.method === "GET") {
    const after = Math.max(0, Number.parseInt(url.searchParams.get("after") ?? "0", 10) || 0);
    const limit = Math.min(1000, Math.max(1, Number.parseInt(url.searchParams.get("limit") ?? "500", 10) || 500));
    const { results } = await env.DB.prepare("SELECT * FROM log WHERE seq > ? ORDER BY seq LIMIT ?").bind(after, limit).all<LogEvent>();
    return json({
      head: await signedHead(env),
      hash_rule: "sha256(prev + '\\n' + seq + '\\n' + ts + '\\n' + type + '\\n' + site_id + '\\n' + url_hash + '\\n' + detail), url_hash = sha256(url), first prev = 64 zeros",
      events: results,
      next: results.length === limit ? `/api/log?after=${results[results.length - 1].seq}&limit=${limit}` : null,
    });
  }

  if (parts[0] === "log" && parts[1] === "head" && parts.length === 2 && request.method === "GET") return json(await signedHead(env));
  if (parts[0] === "agents" && parts.length === 1 && request.method === "GET") return json({ agents: await agentSummaries(env) });
  if (parts[0] === "agents" && parts[1] === "whoami" && parts.length === 2 && request.method === "POST") return whoami(request, env);
  if (parts[0] === "agents" && parts.length === 3 && parts[2] === "verify" && request.method === "POST") {
    if (await limited(request, env, "verify")) return apiError(429, "rate_limited", "Too many verification attempts from here. Try again in an hour.");
    const handle = parseHandle(safeDecode(parts[1]));
    if (!handle || !(await listedBy(env, handle.id)).length) return apiError(404, "not_found", "No agent profile with this handle. A profile exists once it has a listed site.");
    const result = await verifyNamespace(env, handle);
    if (result.verified) return json({ agent: handle.id, namespace_verified: true, domain: result.domain, profile: `${config(env).site}/${handle.id}` });
    return apiError(
      422,
      result.reason === "unreachable" ? "unreachable" : "hash_missing",
      `To verify the namespace ${handle.vendor}, serve a text file containing ${handle.hash} at one of: ${vendorHosts(handle.vendor).map((h) => `https://${h}${AGENTS_FILE}`).join(" , ")}`,
    );
  }
  if (parts[0] === "agents" && parts.length === 2 && request.method === "GET") {
    const handle = parseHandle(safeDecode(parts[1]));
    const sites = handle ? await listedBy(env, handle.id) : [];
    if (!handle || !sites.length) return apiError(404, "not_found", "No agent profile with this handle.");
    const domain = sites[0].agent_domain;
    return json({
      agent: handle.id,
      hash: handle.hash,
      namespace: handle.vendor,
      key: sites[0].agent_pub,
      namespace_verified: !!domain,
      ...(domain ? { namespace_domain: domain } : {}),
      profile: `${config(env).site}/${handle.id}`,
      sites,
      events: await siteEvents(env, handle.id),
    });
  }

  if (parts[0] !== "sites") return apiError(404, "not_found", `Unknown endpoint. See ${config(env).site}/agents.md`);
  const id = parts[1];

  if (!id && request.method === "GET") {
    if (![...url.searchParams.keys()].length) return json({ sites: await listed(env, 500) });
    const query = parseQuery(url);
    const found = await searchListed(env, query, 100);
    return json({ ...found, page: query.page, page_size: 100 });
  }
  if (!id && request.method === "POST") return register(request, env);
  if (id && parts[2] === "verify" && request.method === "POST") return verify(request, env, ctx, id);
  if (id && parts[2] === "reverify" && request.method === "POST") return reverify(request, env, id);
  if (id && parts[2] === "endorse" && (request.method === "POST" || request.method === "DELETE")) return endorse(request, env, id);
  if (id && !parts[2] && request.method === "GET") return status(env, id);
  if (id && !parts[2] && request.method === "DELETE") return remove(request, env, id);
  return apiError(405, "method_not_allowed", `Wrong method for this endpoint. See ${config(env).site}/agents.md`);
}

/** Who signed this request. The signature covers the method, the path, a timestamp and the body. */
interface Signer {
  key: string;
  namespace: string;
  handle: string;
}

async function signer(request: Request, env: Env, raw: string): Promise<Signer | Response> {
  const h = request.headers;
  const key = h.get("x-agent-key") ?? "";
  const namespace = cleanVendor(h.get("x-agent-namespace"));
  const timestamp = h.get("x-agent-timestamp") ?? "";
  const signature = h.get("x-agent-signature") ?? "";
  const how = "Sign requests with your Ed25519 key: see the agents.md instructions.";
  if (!key && !signature) return apiError(401, "unsigned", `This request must be signed. ${how}`);
  if (!isPublicKey(key)) return apiError(400, "bad_key", `X-Agent-Key must be a 32-byte Ed25519 public key in base64url. ${how}`);
  if (!namespace) return apiError(400, "bad_namespace", "X-Agent-Namespace must be a reverse-DNS id like com.example.agents.");
  if (!/^\d{9,11}$/.test(timestamp) || Math.abs(Date.now() / 1000 - Number(timestamp)) > SIGNATURE_WINDOW_S) {
    return apiError(401, "bad_timestamp", `X-Agent-Timestamp must be the current time in unix seconds (within ${SIGNATURE_WINDOW_S} s).`);
  }
  const message = requestMessage(config(env).host, namespace, request.method, new URL(request.url).pathname, timestamp, await sha256Hex(raw));
  if (!(await verifySignature(key, signature, message))) {
    return apiError(401, "bad_signature", `The signature doesn't match. Sign exactly: agentwork-request-v2\\n${config(env).host}\\nyour-namespace\\nMETHOD\\n/path\\ntimestamp\\nsha256-hex-of-body`);
  }
  return { key, namespace, handle: await agentHandle(namespace, key) };
}

async function register(request: Request, env: Env): Promise<Response> {
  if (await limited(request, env, "register")) return apiError(429, "rate_limited", "Too many registrations from here. Try again in an hour.");

  const raw = await request.text();
  const who = await signer(request, env, raw);
  if (who instanceof Response) return who;
  const body = parseJson(raw);
  if (!body) return apiError(400, "bad_json", 'Send a JSON body like {"url": "https://example.com/"}.');
  const target = normalizeUrl(body.url);
  if (!target) return apiError(400, "bad_url", "url must be a public https:// address (no IPs, ports or localhost).");
  const agent = cleanAgent(body.agent);

  const pending = await env.DB.prepare("SELECT COUNT(*) AS n FROM sites WHERE status = 'pending'").first<{ n: number }>();
  if ((pending?.n ?? 0) >= MAX_PENDING) return apiError(503, "busy", "Too many pending registrations right now. Try again later.");
  const existing = await env.DB.prepare("SELECT agent_id FROM sites WHERE url = ? AND status = 'listed'").bind(target.href).first<{ agent_id: string }>();

  // A listing's id is the fingerprint of the statement its site will publish: anyone holding the
  // proof can recompute it. The random challenge inside makes every registration's id unique.
  const c = config(env);
  const challenge = randomHex(16);
  const statement: Statement = { aud: c.host, url: target.href, challenge, agent: who.handle, key: who.key };
  const id = (await sha256Hex(proofToSign(statement))).slice(0, HANDLE_HASH_LENGTH);
  await env.DB.prepare(
    "INSERT INTO sites (id, url, host, agent, agent_id, agent_pub, token, manage_hash, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, '', 'pending', ?)",
  )
    .bind(id, target.href, target.hostname, agent, who.handle, who.key, challenge, Date.now())
    .run();

  const atRoot = target.pathname === "/";
  return json(
    {
      id,
      url: target.href,
      status: "pending",
      agent: { handle: who.handle, profile: `${c.site}/${who.handle}` },
      statement,
      to_sign: proofToSign(statement),
      proof_token: "to_sign + '.' + base64url(Ed25519 signature of to_sign, made with your key)",
      publish: {
        dns: { type: "TXT", name: `${DNS_LABEL}.${target.hostname}`, value: "PROOF_TOKEN", note: "Strongest: proves control of the domain itself." },
        ...(atRoot ? { file: `${target.origin}/.well-known/agentwork.txt` } : {}),
        meta: '<meta name="agentwork-verify" content="PROOF_TOKEN">  (inside <head>)',
        note: atRoot
          ? "Publish the proof token one of these ways, then call verify. Keep it in place: listings are re-checked."
          : "Publish the proof token in DNS, or in a meta tag in the <head> of this exact page, then call verify. Keep it in place: listings are re-checked.",
      },
      verify: { method: "POST", url: `${c.site}/api/sites/${id}/verify` },
      expires_in_hours: 24,
      ...(existing ? { replaces: `This address is already listed${existing.agent_id ? ` by ${existing.agent_id}` : ""}. If the site publishes your proof, your listing replaces it: the site decides.` } : {}),
    },
    201,
  );
}

async function verify(request: Request, env: Env, ctx: ExecutionContext, id: string): Promise<Response> {
  if (await limited(request, env, "verify")) return apiError(429, "rate_limited", "Too many verification attempts from here. Try again in an hour.");
  const c = config(env);
  const row = await env.DB.prepare(`SELECT ${CHECK_COLUMNS}, status FROM sites WHERE id = ?`).bind(id).first<CheckRow & { status: string }>();
  if (!row) return apiError(404, "not_found", "No registration with this id. Pending ones expire after 24 hours.");
  if (row.status === "listed") return json({ id, status: "listed", url: row.url, page: c.site + sitePath({ id, agent_id: row.agent_id }) });

  const check = await checkSite(env, new URL(row.url), row);
  if (!check.ok) return apiError(422, check.reason, check.message);

  // The site now vouches for this key. A listing of the same address by another key gives way.
  const old = await env.DB.prepare("SELECT id, shot FROM sites WHERE url = ? AND status = 'listed' AND id != ?").bind(row.url, id).first<{ id: string; shot: string }>();
  if (old) {
    await env.DB.prepare("DELETE FROM sites WHERE id = ?").bind(old.id).run();
    await dropShot(env, old.shot);
    await appendLog(env, "removed", old.id, row.url, `superseded; agent=${row.agent_id}`);
  }
  const now = Date.now();
  try {
    await env.DB.prepare(
      "UPDATE sites SET status = 'listed', title = ?, description = ?, method = ?, proof = ?, security = ?, listed_at = ?, checked_at = ?, fails = 0 WHERE id = ?",
    )
      .bind(check.title, check.description, check.method, check.proof, JSON.stringify(check.security), now, now, id)
      .run();
  } catch {
    return apiError(409, "already_listed", "This URL was listed by another registration in the meantime.");
  }
  await env.DB.prepare("DELETE FROM sites WHERE url = ? AND status = 'pending'").bind(row.url).run();
  await appendLog(env, "listed", id, row.url, `proof=${check.method}; agent=${row.agent_id}`);
  // The screenshot takes a few seconds: don't make the agent wait for it.
  ctx.waitUntil(captureShot(env, { id, url: row.url, shot: "" }));
  const op = await operatorOrNull(env);
  return json({
    id,
    status: "listed",
    url: row.url,
    title: check.title,
    description: check.description,
    proof: check.method,
    agent: { handle: row.agent_id, profile: `${c.site}/${row.agent_id}` },
    security: check.security,
    page: c.site + sitePath({ id, agent_id: row.agent_id }),
    ...(op
      ? {
          receipt: {
            statement: receiptMessage(id, row.url, row.agent_id, now),
            signature: await op.sign(receiptMessage(id, row.url, row.agent_id, now)),
            operator_key: op.publicKey,
            note: "Signed by the directory. Keep it: it proves this listing was accepted, whatever happens to the server.",
          },
        }
      : {}),
    screenshot: "A screenshot of the page is being taken and will show on the listing shortly.",
  });
}

/** For a trusted process (holds REVERIFY_TOKEN): re-verify a listing now and refresh its screenshot. */
async function reverify(request: Request, env: Env, id: string): Promise<Response> {
  const key = (request.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!env.REVERIFY_TOKEN || !key || !safeEqual(key, env.REVERIFY_TOKEN)) {
    return apiError(401, "unauthorized", "This endpoint is for the trusted re-verification process.");
  }
  const row = await env.DB.prepare(`SELECT ${CHECK_COLUMNS} FROM sites WHERE id = ? AND status = 'listed'`)
    .bind(id)
    .first<CheckRow>();
  if (!row) return apiError(404, "not_found", "No listed site with this id.");

  const outcome = await recheck(env, row, "trusted");
  const shot = outcome.result === "checked" ? await captureShot(env, row) : null;
  return json({
    id,
    url: row.url,
    result: outcome.result,
    detail: outcome.detail,
    ...(outcome.result === "checked" ? { security: outcome.security, screenshot: shot ? `${config(env).imgBase}/${shot}` : null } : {}),
  });
}

const CHECK_COLUMNS = "id, url, token, agent_id, agent_pub, fails, shot, shot_at";
type CheckRow = { id: string; url: string; token: string; agent_id: string; agent_pub: string; fails: number; shot: string; shot_at: number };
type Outcome =
  | { result: "checked"; detail: string; security: Security }
  | { result: "check_failed" | "delisted"; detail: string };

/** One re-check of a listed site, shared by the weekly schedule and the trusted process. Always logged. */
async function recheck(env: Env, row: CheckRow, by: "schedule" | "trusted"): Promise<Outcome> {
  const now = Date.now();
  const tag = by === "trusted" ? "; by=trusted" : "";
  const check = await checkSite(env, new URL(row.url), row);
  if (check.ok) {
    await env.DB.prepare("UPDATE sites SET title = ?, description = ?, method = ?, proof = ?, security = ?, checked_at = ?, fails = 0 WHERE id = ?")
      .bind(check.title, check.description, check.method, check.proof, JSON.stringify(check.security), now, row.id)
      .run();
    const detail = `proof=${check.method}${tag}`;
    await appendLog(env, "checked", row.id, row.url, detail);
    return { result: "checked", detail, security: check.security };
  }
  if (check.reason === "token_missing" || row.fails + 1 >= MAX_FAILS) {
    await env.DB.prepare("DELETE FROM sites WHERE id = ?").bind(row.id).run();
    await dropShot(env, row.shot);
    const detail = (check.reason === "token_missing" ? "token_missing" : `${check.reason} (${MAX_FAILS} checks in a row)`) + tag;
    await appendLog(env, "delisted", row.id, row.url, detail);
    return { result: "delisted", detail };
  }
  await env.DB.prepare("UPDATE sites SET fails = fails + 1, checked_at = ? WHERE id = ?").bind(now, row.id).run();
  const detail = `${check.reason} (${row.fails + 1}/${MAX_FAILS})${tag}`;
  await appendLog(env, "check_failed", row.id, row.url, detail);
  return { result: "check_failed", detail };
}

// ---------- Endorsements ----------

/** Only the operator (ADMIN_TOKEN) can endorse: it means a human looked at the site. Always logged. */
async function endorse(request: Request, env: Env, id: string): Promise<Response> {
  const key = (request.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!env.ADMIN_TOKEN || !key || !safeEqual(key, env.ADMIN_TOKEN)) return apiError(401, "unauthorized", "Only the operator can endorse a site.");
  const row = await env.DB.prepare("SELECT url, endorsed_at FROM sites WHERE id = ? AND status = 'listed'").bind(id).first<{ url: string; endorsed_at: number }>();
  if (!row) return apiError(404, "not_found", "No listed site with this id.");

  if (request.method === "DELETE") {
    if (!row.endorsed_at) return json({ id, endorsed: false });
    await env.DB.prepare("UPDATE sites SET endorsed_at = 0, endorse_note = '', endorse_sig = '' WHERE id = ?").bind(id).run();
    await appendLog(env, "unendorsed", id, row.url);
    return json({ id, endorsed: false });
  }
  const body = (await readJson(request)) ?? {};
  const note = typeof body.note === "string" ? clip(body.note, 160) : "";
  const ts = Date.now();
  const op = await operator(env.OPERATOR_SIGNING_KEY);
  const signature = await op.sign(endorseMessage(row.url, ts, note));
  await env.DB.prepare("UPDATE sites SET endorsed_at = ?, endorse_note = ?, endorse_sig = ? WHERE id = ?").bind(ts, note, signature, id).run();
  await appendLog(env, "endorsed", id, row.url, note);
  return json({ id, endorsed: true, note, statement: endorseMessage(row.url, ts, note), signature, operator_key: op.publicKey });
}

// ---------- Agent identity ----------

/** Lets an agent confirm that its key, namespace and signature produce the handle it expects. */
async function whoami(request: Request, env: Env): Promise<Response> {
  if (await limited(request, env, "verify")) return apiError(429, "rate_limited", "Too many attempts from here. Try again in an hour.");
  const who = await signer(request, env, await request.text());
  if (who instanceof Response) return who;
  const sites = await listedBy(env, who.handle);
  return json({
    agent: who.handle,
    key: who.key,
    namespace: who.namespace,
    signature: "valid",
    profile: `${config(env).site}/${who.handle}`,
    sites_listed: sites.length,
    namespace_verified: !!sites[0]?.agent_domain,
  });
}

/** com.example.agents → agents.example.com, then example.com: any of them can vouch for the namespace. */
function vendorHosts(vendor: string): string[] {
  const labels = vendor.split(".").reverse();
  const hosts: string[] = [];
  for (let i = 0; i <= labels.length - 2; i++) hosts.push(labels.slice(i).join("."));
  return hosts;
}

type NamespaceResult = { verified: true; domain: string } | { verified: false; reason: "missing" | "unreachable" };

/**
 * A namespace is verified when the domain behind it publishes the agent's hash. Updates the
 * agents table and logs every change of state.
 */
async function verifyNamespace(env: Env, handle: Handle): Promise<NamespaceResult> {
  const now = Date.now();
  let domain = "";
  let reachable = false;
  for (const host of vendorHosts(handle.vendor)) {
    const file = await fetchCapped(env, new URL(`https://${host}${AGENTS_FILE}`), 16_384);
    // A 404 still means the domain answered: the file just isn't there.
    if (!file.ok) {
      if (file.reason === "http_error") reachable = true;
      continue;
    }
    reachable = true;
    if (file.body.split(/\s+/).some((line) => line === handle.hash || line === handle.id)) {
      domain = host;
      break;
    }
  }
  const before = await env.DB.prepare("SELECT verified_at, fails FROM agents WHERE handle = ?").bind(handle.id).first<{ verified_at: number; fails: number }>();
  const logUrl = `agent:${handle.id}`;

  if (domain) {
    await env.DB.prepare(
      "INSERT INTO agents (handle, domain, verified_at, checked_at, fails) VALUES (?, ?, ?, ?, 0) ON CONFLICT(handle) DO UPDATE SET domain = excluded.domain, verified_at = CASE WHEN agents.verified_at > 0 THEN agents.verified_at ELSE excluded.verified_at END, checked_at = excluded.checked_at, fails = 0",
    )
      .bind(handle.id, domain, now, now)
      .run();
    if (!before?.verified_at) await appendLog(env, "agent_verified", handle.id, logUrl, `domain=${domain}`);
    return { verified: true, domain };
  }
  if (before?.verified_at) {
    // The file is there without the hash: unverify now. Unreachable: give it a few tries first.
    const fails = before.fails + 1;
    if (reachable || fails >= MAX_FAILS) {
      await env.DB.prepare("UPDATE agents SET verified_at = 0, checked_at = ?, fails = 0 WHERE handle = ?").bind(now, handle.id).run();
      await appendLog(env, "agent_unverified", handle.id, logUrl, reachable ? "hash_missing" : `unreachable (${MAX_FAILS} checks in a row)`);
    } else {
      await env.DB.prepare("UPDATE agents SET checked_at = ?, fails = ? WHERE handle = ?").bind(now, fails, handle.id).run();
    }
  }
  return { verified: false, reason: reachable ? "missing" : "unreachable" };
}

async function agentSummaries(env: Env): Promise<AgentSummary[]> {
  const { results } = await env.DB.prepare(
    `SELECT agent_id AS handle, COUNT(*) AS sites, MIN(listed_at) AS since,
       (SELECT agent FROM sites s2 WHERE s2.agent_id = sites.agent_id AND s2.status = 'listed' AND s2.agent != '' GROUP BY agent ORDER BY COUNT(*) DESC, MAX(listed_at) DESC LIMIT 1) AS name,
       (SELECT domain FROM agents a WHERE a.handle = sites.agent_id AND a.verified_at > 0) AS domain
     FROM sites WHERE status = 'listed' AND agent_id != '' GROUP BY agent_id ORDER BY sites DESC, since LIMIT 200`,
  ).all<AgentSummary>();
  return results;
}

// ---------- Search ----------

function parseQuery(url: URL): Query {
  const p = url.searchParams;
  return {
    q: (p.get("q") ?? "").replace(/\s+/g, " ").trim().slice(0, 60),
    filter: p.get("filter") === "endorsed" ? "endorsed" : "all",
    sort: p.get("sort") === "checked" ? "checked" : "new",
    page: Math.min(500, Math.max(1, Number.parseInt(p.get("page") ?? "1", 10) || 1)),
  };
}

async function searchListed(env: Env, query: Query, pageSize: number): Promise<{ sites: Listing[]; total: number }> {
  const where = ["status = 'listed'"];
  const binds: (string | number)[] = [];
  if (query.q) {
    const like = `%${query.q.replace(/[\\%_]/g, "\\$&")}%`;
    where.push("(title LIKE ? ESCAPE '\\' OR host LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' OR agent LIKE ? ESCAPE '\\')");
    binds.push(like, like, like, like);
  }
  if (query.filter === "endorsed") where.push("endorsed_at > 0");
  const clause = where.join(" AND ");
  const order = query.sort === "checked" ? "checked_at DESC" : "listed_at DESC";
  const total = await env.DB.prepare(`SELECT COUNT(*) AS n FROM sites WHERE ${clause}`).bind(...binds).first<{ n: number }>();
  const { results } = await env.DB.prepare(`SELECT ${LISTING_COLUMNS} FROM sites WHERE ${clause} ORDER BY ${order} LIMIT ? OFFSET ?`)
    .bind(...binds, pageSize, (query.page - 1) * pageSize)
    .all<ListingRow>();
  return { sites: results.map((r) => toListing(env, r)), total: total?.n ?? 0 };
}

async function countEndorsed(env: Env): Promise<number> {
  const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM sites WHERE status = 'listed' AND endorsed_at > 0").first<{ n: number }>();
  return row?.n ?? 0;
}

// ---------- Screenshots ----------

/**
 * Captures the page in a headless browser at its final size and stores it in R2 under a
 * content-addressed key (so it can be cached forever). Returns the key, or null if it failed:
 * a missing screenshot never blocks a listing.
 */
async function captureShot(env: Env, site: { id: string; url: string; shot: string }): Promise<string | null> {
  let browser: Awaited<ReturnType<typeof puppeteer.launch>> | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const giveUp = new Promise<null>((resolve) => {
    timer = setTimeout(() => resolve(null), SHOT_BUDGET_MS);
  });
  try {
    // A browser that hangs must never hang the request or the cron with it.
    return await Promise.race([capture(), giveUp]);
  } catch (err) {
    console.error("screenshot failed", site.url, err);
    return null;
  } finally {
    clearTimeout(timer);
    await Promise.race([browser?.close().catch(() => {}), new Promise((r) => setTimeout(r, 3000))]);
  }

  async function capture(): Promise<string | null> {
    browser = await puppeteer.launch(env.BROWSER);
    const page = await browser.newPage();
    await page.setViewport(SHOT_VIEWPORT);
    // A slow page still gets a screenshot of whatever loaded in time.
    await page.goto(site.url, { waitUntil: "networkidle2", timeout: SHOT_TIMEOUT_MS }).catch(() => {});
    const landed = new URL(page.url());
    if (landed.protocol !== "https:" || bare(landed.hostname) !== bare(new URL(site.url).hostname)) return null;

    const image = (await page.screenshot({ type: "webp", quality: 72 })) as Uint8Array;
    const digest = await crypto.subtle.digest("SHA-256", image);
    const name = [...new Uint8Array(digest).subarray(0, 8)].map((b) => b.toString(16).padStart(2, "0")).join("");
    const key = `agentwork/${site.id}/${name}.webp`;
    await env.IMG.put(key, image, {
      httpMetadata: { contentType: "image/webp", cacheControl: "public, max-age=31536000, immutable" },
    });
    const updated = await env.DB.prepare("UPDATE sites SET shot = ?, shot_at = ? WHERE id = ? AND status = 'listed'")
      .bind(key, Date.now(), site.id)
      .run();
    if (!updated.meta.changes) {
      await env.IMG.delete(key); // the listing went away while we were capturing
      return null;
    }
    if (site.shot && site.shot !== key) await dropShot(env, site.shot);
    return key;
  }
}

async function dropShot(env: Env, key: string): Promise<void> {
  if (key) await env.IMG.delete(key).catch(() => {});
}

/** The operator's key, or null when it isn't configured: pages must still render without it. */
async function operatorOrNull(env: Env) {
  try {
    return await operator(env.OPERATOR_SIGNING_KEY);
  } catch (err) {
    console.error("operator key unavailable", err);
    return null;
  }
}

async function receiptFor(env: Env, site: Listing): Promise<Receipt | null> {
  if (!site.agent_pub) return null;
  const op = await operatorOrNull(env);
  if (!op) return null;
  const statement = receiptMessage(site.id, site.url, site.agent_id, site.listed_at);
  return { statement, signature: await op.sign(statement), operator_key: op.publicKey };
}

export interface Receipt {
  statement: string;
  signature: string;
  operator_key: string;
}

async function status(env: Env, id: string): Promise<Response> {
  const site = await listing(env, id);
  if (site) return json({ ...site, status: "listed", receipt: await receiptFor(env, site), events: await siteEvents(env, id) });
  const pending = await env.DB.prepare("SELECT id, url, status FROM sites WHERE id = ?").bind(id).first();
  if (pending) return json(pending);
  const events = await siteEvents(env, id);
  if (events.length) return json({ id, status: "gone", events });
  return apiError(404, "not_found", "No site with this id.");
}

/** A listing is removed by the key that listed it (a signed request), or by the moderator. */
async function remove(request: Request, env: Env, id: string): Promise<Response> {
  const row = await env.DB.prepare("SELECT url, status, agent_pub, shot FROM sites WHERE id = ?")
    .bind(id)
    .first<{ url: string; status: string; agent_pub: string; shot: string }>();
  if (!row) return apiError(404, "not_found", "No site with this id.");

  const bearer = (request.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, "");
  const byAdmin = !!bearer && !!env.ADMIN_TOKEN && safeEqual(bearer, env.ADMIN_TOKEN);
  if (!byAdmin) {
    const who = await signer(request, env, await request.text());
    if (who instanceof Response) return who;
    if (!row.agent_pub || who.key !== row.agent_pub) return apiError(403, "forbidden", "Only the key that listed this site can remove it.");
  }
  await env.DB.prepare("DELETE FROM sites WHERE id = ?").bind(id).run();
  await dropShot(env, row.shot);
  if (row.status === "listed") await appendLog(env, "removed", id, row.url, byAdmin ? "by_admin" : "by_owner");
  return json({ id, status: "removed" });
}

/** The head of the log, signed by the operator: a statement it can't take back later. */
async function signedHead(env: Env): Promise<SignedHead> {
  const head = (await env.DB.prepare("SELECT seq, hash FROM log ORDER BY seq DESC LIMIT 1").first<{ seq: number; hash: string }>()) ?? { seq: 0, hash: GENESIS };
  const op = await operatorOrNull(env);
  const ts = Date.now();
  return { ...head, ts, signature: op ? await op.sign(logHeadMessage(head.seq, head.hash, ts)) : "", operator_key: op?.publicKey ?? "" };
}

export interface SignedHead {
  seq: number;
  hash: string;
  ts: number;
  signature: string;
  operator_key: string;
}

// ---------- Transparency log ----------

export function eventHashInput(e: Pick<LogEvent, "prev" | "seq" | "ts" | "type" | "site_id" | "url_hash" | "detail">): string {
  return [e.prev, e.seq, e.ts, e.type, e.site_id, e.url_hash, e.detail].join("\n");
}

/** Appends one event to the chain. seq is the primary key, so a concurrent append makes this retry. */
async function appendLog(env: Env, type: LogEvent["type"], siteId: string, url: string, detail = ""): Promise<void> {
  const urlHash = await sha256(url);
  for (let attempt = 0; attempt < 5; attempt++) {
    const last = await env.DB.prepare("SELECT seq, hash FROM log ORDER BY seq DESC LIMIT 1").first<{ seq: number; hash: string }>();
    const event = { prev: last?.hash ?? GENESIS, seq: (last?.seq ?? 0) + 1, ts: Date.now(), type, site_id: siteId, url_hash: urlHash, detail };
    const hash = await sha256(eventHashInput(event));
    try {
      await env.DB.prepare("INSERT INTO log (seq, ts, type, site_id, url, url_hash, detail, prev, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(event.seq, event.ts, type, siteId, url, urlHash, detail, event.prev, hash)
        .run();
      return;
    } catch (err) {
      if (!/unique|constraint/i.test(String(err))) throw err;
    }
  }
  throw new Error("Could not append to the transparency log");
}

async function siteEvents(env: Env, id: string): Promise<LogEvent[]> {
  const { results } = await env.DB.prepare("SELECT * FROM log WHERE site_id = ? ORDER BY seq DESC LIMIT 100").bind(id).all<LogEvent>();
  return results;
}

async function recentEvents(env: Env, limit: number): Promise<LogEvent[]> {
  const { results } = await env.DB.prepare("SELECT * FROM log ORDER BY seq DESC LIMIT ?").bind(limit).all<LogEvent>();
  return results;
}

// ---------- Checking a site ----------

/** Where the proof was found. DNS proves control of the domain; file, of the site; meta, of the page. */
type Method = "dns" | "file" | "meta";

type Check =
  | { ok: true; title: string; description: string; method: Method; proof: string; security: Security }
  | { ok: false; reason: string; message: string };

/**
 * Fetches the page (and /.well-known/agentwork.txt for root URLs) and looks for the proof: a
 * statement naming this address, this challenge and this agent, signed by that agent's key.
 * Listings made before signatures (no key) still match on their plain token until re-proven.
 */
async function checkSite(env: Env, target: URL, expect: { token: string; agent_id: string; agent_pub: string }): Promise<Check> {
  const page = await fetchCapped(env, target);
  if (!page.ok) return page;
  if (!/html/i.test(page.type)) return { ok: false, reason: "not_html", message: `${target.href} didn't return an HTML page.` };
  const head = await readHead(page.body);

  const accept = async (candidates: string[]): Promise<string | null> => {
    for (const candidate of candidates.slice(0, 20)) {
      if (!expect.agent_pub) {
        if (candidate === expect.token) return candidate;
        continue;
      }
      if (!candidate.startsWith(PROOF_PREFIX)) continue;
      const proof = await readProof(candidate);
      const s = proof?.statement;
      if (s && s.aud === config(env).host && s.url === target.href && s.challenge === expect.token && s.key === expect.agent_pub && s.agent === expect.agent_id) return candidate;
    }
    return null;
  };

  // Strongest first: a proof in the domain's DNS wins over one served by the site.
  let method: Method | null = null;
  let proof: string | null = null;
  if (expect.agent_pub) {
    const records = await lookupTxt(`${DNS_LABEL}.${target.hostname}`);
    if (records) proof = await accept(records.flatMap((r) => r.split(/\s+/)).filter(Boolean));
    if (proof) method = "dns";
  }
  if (!proof) {
    proof = await accept(head.verify);
    if (proof) method = "meta";
  }
  if (!proof && target.pathname === "/") {
    const file = await fetchCapped(env, new URL("/.well-known/agentwork.txt", target.origin), 16_384);
    if (file.ok) proof = await accept(file.body.split(/\s+/).filter(Boolean));
    if (proof) method = "file";
  }
  if (!proof || !method) {
    return {
      ok: false,
      reason: "token_missing",
      message: `No valid proof found. Publish the proof token (the statement you were given, signed with your key) in a DNS TXT record at ${DNS_LABEL}.${target.hostname}, at ${target.origin}/.well-known/agentwork.txt (root URLs only), or in <meta name="agentwork-verify" content="…"> inside the page's <head>, then try again. A proof is rejected if its signature, address, challenge or key doesn't match this registration.`,
    };
  }
  return {
    ok: true,
    method,
    proof,
    security: securityOf(page.headers),
    title: clip(head.ogTitle || head.title || target.hostname, 100),
    description: clip(head.description || head.ogDescription, 240),
  };
}

/** Basic hardening headers on the page's response. Says nothing about whether the site is safe. */
function securityOf(h: Headers): Security {
  const csp = h.get("content-security-policy") ?? "";
  return {
    hsts: /max-age\s*=\s*"?[1-9]/i.test(h.get("strict-transport-security") ?? ""),
    csp: csp.trim().length > 0,
    frame: /^(deny|sameorigin)$/i.test((h.get("x-frame-options") ?? "").trim()) || /frame-ancestors/i.test(csp),
    nosniff: /nosniff/i.test(h.get("x-content-type-options") ?? ""),
    referrer: (h.get("referrer-policy") ?? "").trim().length > 0,
  };
}

type Fetched =
  | { ok: true; body: string; type: string; headers: Headers }
  | { ok: false; reason: string; message: string };

async function fetchCapped(env: Env, start: URL, maxBytes = MAX_PAGE_BYTES): Promise<Fetched> {
  let current = start;
  for (let hop = 0; hop < 4; hop++) {
    let res: Response;
    try {
      res = await fetch(current.href, {
        redirect: "manual",
        headers: { "user-agent": userAgent(env), accept: "text/html,text/plain;q=0.9,*/*;q=0.1" },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
    } catch {
      return { ok: false, reason: "unreachable", message: `Couldn't reach ${current.href}.` };
    }
    if (res.status >= 300 && res.status < 400) {
      const next = new URL(res.headers.get("location") ?? "", current);
      await res.body?.cancel();
      if (next.protocol !== "https:" || bare(next.hostname) !== bare(start.hostname)) {
        return { ok: false, reason: "redirects_elsewhere", message: `${current.href} redirects to another site (${next.hostname}). List the final URL instead.` };
      }
      current = next;
      continue;
    }
    if (!res.ok) {
      await res.body?.cancel();
      return { ok: false, reason: "http_error", message: `${current.href} answered HTTP ${res.status}.` };
    }
    return { ok: true, body: await readCapped(res, maxBytes), type: res.headers.get("content-type") ?? "", headers: res.headers };
  }
  return { ok: false, reason: "too_many_redirects", message: `${start.href} redirects too many times.` };
}

async function readCapped(res: Response, maxBytes: number): Promise<string> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (size < maxBytes) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    size += value.byteLength;
  }
  await reader.cancel().catch(() => {});
  const all = new Uint8Array(Math.min(size, maxBytes));
  let offset = 0;
  for (const c of chunks) {
    const part = c.subarray(0, all.length - offset);
    all.set(part, offset);
    offset += part.length;
    if (offset >= all.length) break;
  }
  return new TextDecoder().decode(all);
}

async function readHead(body: string) {
  const out = { title: "", ogTitle: "", description: "", ogDescription: "", verify: [] as string[] };
  let titleDone = false;
  const rewriter = new HTMLRewriter()
    .on("head title", {
      text(t) {
        if (!titleDone) out.title += t.text;
        if (t.lastInTextNode) titleDone = true;
      },
    })
    // Only <meta> inside <head>: text someone managed to post into the page's body (a comment,
    // a forum post, a reflected parameter) must never count as proof or as the site's description.
    .on("head meta", {
      element(e) {
        const key = (e.getAttribute("name") ?? e.getAttribute("property") ?? "").toLowerCase();
        const content = e.getAttribute("content") ?? "";
        if (key === "agentwork-verify") out.verify.push(content.trim());
        else if (key === "description" && !out.description) out.description = content;
        else if (key === "og:title" && !out.ogTitle) out.ogTitle = content;
        else if (key === "og:description" && !out.ogDescription) out.ogDescription = content;
      },
    });
  await rewriter.transform(new Response(body, { headers: { "content-type": "text/html" } })).arrayBuffer();
  return out;
}

// ---------- Helpers ----------

/** Public https URLs only: no IPs, no ports, no localhost-like names. Drops query and hash. */
function normalizeUrl(raw: unknown): URL | null {
  if (typeof raw !== "string" || raw.length > 300) return null;
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    return null;
  }
  const host = u.hostname.toLowerCase();
  if (u.protocol !== "https:" || u.port || u.username || u.password) return null;
  if (!host.includes(".") || /^[\d.]+$/.test(host) || host.includes(":") || host.startsWith("[")) return null;
  if (/(^|\.)(localhost|local|internal|test|example|invalid|onion)$/.test(host)) return null;
  u.hash = "";
  u.search = "";
  return u;
}

export interface Handle {
  id: string; // "<hash>@<vendor>"
  hash: string;
  vendor: string;
}

const VENDOR = /^[a-z0-9-]{1,30}(\.[a-z0-9-]{1,30}){1,4}$/;

/** Reverse-DNS id of who makes the agent, e.g. com.anthropic.claude. Self-declared. */
function cleanVendor(raw: unknown): string {
  const v = typeof raw === "string" ? raw.trim().toLowerCase() : "";
  return v.length <= 60 && VENDOR.test(v) ? v : "";
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return "";
  }
}

function parseHandle(raw: string): Handle | null {
  const m = new RegExp(`^([0-9a-f]{${HANDLE_HASH_LENGTH}})@(.+)$`).exec(raw);
  if (!m || !cleanVendor(m[2]) || cleanVendor(m[2]) !== m[2]) return null;
  return { id: raw, hash: m[1], vendor: m[2] };
}

async function listedBy(env: Env, agentId: string): Promise<Listing[]> {
  const { results } = await env.DB.prepare(
    `SELECT ${LISTING_COLUMNS} FROM sites WHERE status = 'listed' AND agent_id = ? ORDER BY listed_at DESC LIMIT 200`,
  )
    .bind(agentId)
    .all<ListingRow>();
  return results.map((r) => toListing(env, r));
}

function cleanAgent(raw: unknown): string {
  if (typeof raw !== "string") return "";
  return raw.replace(/[^\p{L}\p{N} ._\-/]/gu, "").trim().slice(0, 40);
}

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };
function clip(s: string, max: number): string {
  const decoded = s.replace(/&(#x[\da-f]+|#\d+|[a-z]+);/gi, (m, e: string) => {
    if (e[0] === "#") {
      const code = e[1].toLowerCase() === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return code > 0 && code < 0x110000 ? String.fromCodePoint(code) : "";
    }
    return ENTITIES[e.toLowerCase()] ?? m;
  });
  const clean = decoded.replace(/[\u0000-\u001f\u007f​-‏‪-‮]/g, " ").replace(/\s+/g, " ").trim();
  return clean.length > max ? `${clean.slice(0, max - 1).trimEnd()}…` : clean;
}

const bare = (h: string) => h.toLowerCase().replace(/^www\./, "");

type ListingRow = Omit<Listing, "security" | "shot_url" | "page"> & { security: string; shot: string };
const toListing = (env: Env, { shot, ...r }: ListingRow): Listing => {
  let security: Security | null = null;
  try {
    security = r.security ? (JSON.parse(r.security) as Security) : null;
  } catch {}
  return { ...r, security, shot_url: shot ? `${config(env).imgBase}/${shot}` : null, page: config(env).site + sitePath(r) };
};

async function listed(env: Env, limit: number): Promise<Listing[]> {
  const { results } = await env.DB.prepare(
    `SELECT ${LISTING_COLUMNS} FROM sites WHERE status = 'listed' ORDER BY listed_at DESC LIMIT ?`,
  )
    .bind(limit)
    .all<ListingRow>();
  return results.map((r) => toListing(env, r));
}

async function listing(env: Env, id: string): Promise<Listing | null> {
  const row = await env.DB.prepare(`SELECT ${LISTING_COLUMNS} FROM sites WHERE id = ? AND status = 'listed'`).bind(id).first<ListingRow>();
  return row ? toListing(env, row) : null;
}

async function countListed(env: Env): Promise<number> {
  const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM sites WHERE status = 'listed'").first<{ n: number }>();
  return row?.n ?? 0;
}

/** Counts per daily-salted IP hash, so no raw IP is ever stored. */
async function limited(request: Request, env: Env, action: keyof typeof LIMITS): Promise<boolean> {
  const { n, windowSec } = LIMITS[action];
  const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
  const day = new Date().toISOString().slice(0, 10);
  const key = `${action}:${(await sha256(`${env.HASH_SALT}|${day}|${ip}`)).slice(0, 32)}`;
  const win = Math.floor(Date.now() / 1000 / windowSec);
  const row = await env.DB.prepare(
    "INSERT INTO hits (key, win, n, exp) VALUES (?, ?, 1, ?) ON CONFLICT(key, win) DO UPDATE SET n = n + 1 RETURNING n",
  )
    .bind(key, win, Date.now() + 2 * 86_400_000)
    .first<{ n: number }>();
  return (row?.n ?? 0) > n;
}

function parseJson(raw: string): Record<string, unknown> | null {
  if (raw.length > MAX_BODY) return null;
  try {
    const v = JSON.parse(raw);
    return v && typeof v === "object" && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

async function readJson(request: Request): Promise<Record<string, unknown> | null> {
  return parseJson(await request.text());
}

async function sha256(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function safeEqual(a: string, b: string): boolean {
  const x = enc.encode(a);
  const y = enc.encode(b);
  return x.byteLength === y.byteLength && crypto.subtle.timingSafeEqual(x, y);
}

function randomHex(bytes: number): string {
  return [...crypto.getRandomValues(new Uint8Array(bytes))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "strict-transport-security": "max-age=31536000",
};

function html(c: Config, body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      ...SECURITY_HEADERS,
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy":
        `default-src 'none'; style-src 'self'; img-src 'self' ${c.imgOrigin}; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    },
  });
}

function text(body: string, status = 200, type = "text/plain; charset=utf-8", cache = "no-store"): Response {
  return new Response(body, { status, headers: { ...SECURITY_HEADERS, "content-type": type, "cache-control": cache } });
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { ...SECURITY_HEADERS, "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

function apiError(status: number, error: string, message: string): Response {
  return json({ error, message }, status);
}

function withCors(res: Response): Response {
  const out = new Response(res.body, res);
  out.headers.set("access-control-allow-origin", "*");
  out.headers.set("access-control-allow-methods", "GET, POST, DELETE, OPTIONS");
  out.headers.set("access-control-allow-headers", "content-type, authorization, x-agent-key, x-agent-namespace, x-agent-timestamp, x-agent-signature");
  return out;
}
