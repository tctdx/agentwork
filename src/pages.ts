import { MAX_FAILS, PAGE_SIZE, RECHECK_EVERY_MS } from "./constants";
import type { AgentSummary, Config, Handle, Listing, LogEvent, Query, Receipt, Security, SignedHead } from "./index";

export const styles = `:root{--bg:#fff;--ink:#111;--muted:#6b6b6b;--line:#e8e8e8;--code:#f5f5f5;--yes:#1a7f37;--warn:#9a6700;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#0a0a0a;--ink:#ededed;--muted:#9a9a9a;--line:#222;--code:#161616;--yes:#3fb950;--warn:#d29922}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Inter,sans-serif;-webkit-font-smoothing:antialiased}
main{max-width:36rem;margin:0 auto;padding:2.5rem 1rem 4rem}
a{color:inherit;text-underline-offset:4px}
header{display:flex;justify-content:space-between;align-items:baseline;gap:1rem;margin-bottom:4rem}
header a{text-decoration:none}
header .name{font-weight:500}
header nav{display:flex;gap:1.25rem;color:var(--muted)}
header nav a:hover,header nav a[aria-current]{color:var(--ink)}
h1{font-size:1.25rem;font-weight:500;line-height:1.4;margin:0;text-wrap:balance;overflow-wrap:anywhere}
h2{font-size:1rem;font-weight:500;margin:0}
.sub{font-size:1.25rem;color:var(--muted);margin:.5rem 0 0;text-wrap:pretty;overflow-wrap:anywhere}
.muted{color:var(--muted)}
.small{font-size:.875rem}
.prompt{margin:.5rem 0 .75rem;padding:.875rem 1rem;background:var(--code);border-radius:.5rem;overflow-x:auto;font-size:.875rem;line-height:1.5;white-space:pre-wrap;word-break:break-word}
code{font:inherit;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.92em;overflow-wrap:anywhere}
section{margin-top:4rem}
section > h2 + *{margin-top:.75rem}
.row{display:flex;justify-content:space-between;align-items:baseline;gap:1rem;flex-wrap:wrap}
.list{list-style:none;margin:.75rem 0 0;padding:0;border-top:1px solid var(--line)}
.list > li{border-bottom:1px solid var(--line);padding:1rem 0;line-height:1.5}

/* Trust badges: the same four codes on every page. */
.i{width:.875rem;height:.875rem;flex:none}
.i .cut{stroke:var(--bg)}
.badge{display:inline-flex;align-items:center;gap:.3rem;font-size:.8125rem;line-height:1.2;padding:.2rem .55rem .2rem .4rem;border-radius:999px;border:1px solid var(--line);color:var(--muted);white-space:nowrap;text-decoration:none;vertical-align:middle}
.badge.ok{color:var(--yes);border-color:color-mix(in srgb,var(--yes) 40%,transparent)}
.badge.self{border-style:dashed;border-color:color-mix(in srgb,var(--muted) 55%,transparent)}
.badge.star{color:var(--ink);border-color:var(--ink)}
.badge.warn{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 45%,transparent)}
a.badge:hover{background:var(--code)}
.badges{display:flex;flex-wrap:wrap;gap:.375rem;align-items:center}
.tick{display:inline-flex;color:var(--yes);vertical-align:-.1em;margin-left:.2rem}

/* Listing your site */
.add{margin-top:1.5rem}
.add .label{font-size:.875rem;color:var(--muted)}

/* Finding sites */
.search{display:flex;gap:.5rem;margin-top:.75rem}
.search input{flex:1;min-width:0;font:inherit;color:inherit;background:var(--bg);border:1px solid var(--line);border-radius:.5rem;padding:.5rem .75rem}
.search input:focus-visible,.btn:focus-visible,a:focus-visible,summary:focus-visible{outline:2px solid var(--ink);outline-offset:2px}
.btn{display:inline-flex;align-items:center;gap:.4rem;font:inherit;font-size:.9375rem;cursor:pointer;color:var(--bg);background:var(--ink);border:1px solid var(--ink);border-radius:.5rem;padding:.5rem .875rem;text-decoration:none}
.btn.quiet{color:var(--ink);background:transparent;border-color:var(--line)}
.btn:hover{opacity:.85}
.chips{display:flex;flex-wrap:wrap;gap:.375rem .5rem;align-items:center;margin-top:.75rem;font-size:.875rem}
.chip{padding:.2rem .65rem;border:1px solid var(--line);border-radius:999px;color:var(--muted);text-decoration:none}
.chip:hover{color:var(--ink)}
.chip[aria-current]{color:var(--bg);background:var(--ink);border-color:var(--ink)}
.chips .gap{flex-basis:100%;height:0}
@media (min-width:34rem){.chips .gap{flex:1;flex-basis:auto}}
.grid{list-style:none;margin:1.25rem 0 0;padding:0;display:grid;grid-template-columns:1fr;gap:1.75rem 1.25rem}
@media (min-width:34rem){.grid{grid-template-columns:1fr 1fr}}
.card{display:flex;flex-direction:column;min-width:0;line-height:1.45}
.shot{display:block;width:100%;height:auto;aspect-ratio:16/10;object-fit:cover;object-position:top;border:1px solid var(--line);border-radius:.5rem;background:var(--code)}
.noshot{display:flex;align-items:center;justify-content:center;aspect-ratio:16/10;border:1px solid var(--line);border-radius:.5rem;background:var(--code);color:var(--muted);font-size:.8125rem}
.card .thumb{display:block;text-decoration:none}
.card .title{display:block;margin-top:.625rem;text-decoration:none;overflow-wrap:anywhere}
.card .title:hover{text-decoration:underline}
.card .host{display:block;font-size:.875rem;color:var(--muted);overflow-wrap:anywhere}
.card .desc{margin-top:.25rem;font-size:.875rem;color:var(--muted);display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.card .badges{margin-top:.5rem}
.card .meta{display:block;margin-top:.375rem;font-size:.8125rem;color:var(--muted);overflow-wrap:anywhere}
.card .meta a:hover{color:var(--ink)}
.pager{display:flex;justify-content:space-between;align-items:center;gap:1rem;margin-top:2rem;font-size:.875rem}
.legend{display:flex;flex-wrap:wrap;gap:.375rem .5rem;align-items:center;margin-top:2.5rem;font-size:.8125rem;color:var(--muted)}

/* One listing */
.back{display:inline-block;margin-bottom:1.5rem;font-size:.875rem;color:var(--muted);text-decoration:none}
.back:hover{color:var(--ink)}
.lead{margin:1rem 0 0}
.lead .src{display:block;margin-top:.25rem;font-size:.8125rem;color:var(--muted)}
.actions{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:1.25rem}
figure{margin:1.5rem 0 0}
figcaption{margin-top:.5rem}
.facts{margin:.75rem 0 0;border-top:1px solid var(--line)}
.fact{display:grid;grid-template-columns:1fr;gap:.375rem;padding:.875rem 0;border-bottom:1px solid var(--line)}
@media (min-width:34rem){.fact{grid-template-columns:9.5rem 1fr;gap:1rem}}
.fact dt{color:var(--muted);font-size:.875rem;padding-top:.1rem}
.fact dd{margin:0;min-width:0}
.fact dd p{margin:.375rem 0 0;font-size:.875rem;color:var(--muted)}
.checks{list-style:none;margin:.75rem 0 0;padding:0}
.check{display:flex;gap:.75rem;padding:.375rem 0;line-height:1.5}
.mark{flex:none;width:1.25rem;text-align:center;font-weight:600}
.mark.yes{color:var(--yes)}
.mark.no{color:var(--muted)}
.check strong{font-weight:500}

/* Agents, log, text pages */
.agent-row{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap}
.agent-row a.name{text-decoration:none}
.agent-row a.name:hover{text-decoration:underline}
.handle{display:block;font-size:.8125rem;color:var(--muted);overflow-wrap:anywhere}
.event .ev-head{display:flex;justify-content:space-between;align-items:baseline;gap:1rem;flex-wrap:wrap}
.event .ev-site{display:block;font-size:.875rem;color:var(--muted);overflow-wrap:anywhere}
.event .hash{display:block;margin-top:.25rem;font-size:.75rem;color:var(--muted)}
.empty{margin-top:.75rem}
.prose{margin-top:1.5rem}
section .prose{margin-top:.75rem}
.prose p{margin:0 0 1rem}
.term{padding:1rem 0;border-bottom:1px solid var(--line)}
.term:first-child{border-top:1px solid var(--line)}
.term p{margin:.5rem 0 0}
.verify{margin-top:.5rem}
.proof{margin-top:.75rem}
.proof dt{margin-top:.75rem;font-size:.8125rem;color:var(--muted)}
.proof dd{margin:.125rem 0 0}
.proof code,.mono{display:block;font-size:.75rem;line-height:1.5;padding:.5rem .625rem;background:var(--code);border-radius:.375rem;white-space:pre-wrap;word-break:break-all}
details summary{cursor:pointer;font-size:.875rem}
footer{display:flex;flex-wrap:wrap;gap:.5rem 1rem;margin-top:4rem;font-size:.875rem;color:var(--muted)}
footer a{text-decoration:none}
footer a:hover{color:var(--ink)}
`;

/** Changes whenever the CSS changes, so browsers never keep a stale stylesheet. */
const STYLE_VERSION = [...styles].reduce((h, c) => (Math.imul(h, 31) + c.charCodeAt(0)) >>> 0, 7).toString(36);

const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

const date = (ms: number) =>
  new Date(ms).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });

const dateTime = (ms: number) =>
  `${new Date(ms).toLocaleString("en-GB", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC" })} UTC`;

function ago(ms: number): string {
  const s = Math.max(0, (Date.now() - ms) / 1000);
  if (s < 90) return "just now";
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 129600) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}

/** Outgoing links carry utm_source so listed sites can see their visits from the directory. */
const out = (c: Config, url: string) => {
  const u = new URL(url);
  u.searchParams.set("utm_source", c.host);
  return u.href;
};

const shownPath = (url: string) => {
  if (url.startsWith("agent:")) return url.slice(6);
  const u = new URL(url);
  return u.hostname + (u.pathname === "/" ? "" : u.pathname);
};

// ---------- Trust badges ----------
// Four codes, always drawn the same way:
//   ok    solid check      agentwork checked it itself
//   self  dashed outline   someone says so; nobody checked
//   ext   arrow            content written by the listed site
//   star  solid outline    a human at the operator reviewed it

const ICON = {
  ok: `<svg class="i" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="7" fill="currentColor"/><path class="cut" d="M4.7 8.3l2.2 2.2 4.4-4.7" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  self: `<svg class="i" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="6.2" fill="none" stroke="currentColor" stroke-width="1.4" stroke-dasharray="2.3 2.3"/></svg>`,
  ext: `<svg class="i" viewBox="0 0 16 16" aria-hidden="true"><path d="M5 11l6-6M6.2 5H11v4.8" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  star: `<svg class="i" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1.7l1.9 3.9 4.3.6-3.1 3 .7 4.3L8 11.5l-3.8 2 .7-4.3-3.1-3 4.3-.6z" fill="currentColor"/></svg>`,
  warn: `<svg class="i" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 2.2l6.3 11.1H1.7z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><path d="M8 6.6v3.1M8 11.6v.1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
  wait: `<svg class="i" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="6.2" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M8 4.6V8l2.2 1.4" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>`,
};

type Kind = "ok" | "self" | "ext" | "star" | "warn" | "wait";
const badge = (kind: Kind, label: string, href?: string) =>
  href
    ? `<a class="badge ${kind === "wait" ? "" : kind}" href="${esc(href)}">${ICON[kind]}${esc(label)}</a>`
    : `<span class="badge ${kind === "wait" ? "" : kind}">${ICON[kind]}${esc(label)}</span>`;

/** A listing at the root of a host proves the whole site; one at a deeper address proves only that page. */
const isPage = (s: Listing) => new URL(s.url).pathname !== "/";

/** The one status every listing has: is its proof of control currently good? */
function controlBadge(s: Listing, href?: string, withTime = false): string {
  if (s.fails > 0) return badge("warn", `Check failing (${s.fails}/${MAX_FAILS})`, href);
  if (!s.checked_at) return badge("wait", "Re-check pending", href);
  const label = isPage(s) ? "Verified page" : "Verified";
  return badge("ok", withTime ? `${label} · ${ago(s.checked_at)}` : label, href);
}

const endorsedBadge = (c: Config, s: Listing, href?: string) => (s.endorsed_at ? badge("star", `Endorsed by ${c.operatorName}`, href) : "");

const PROOF_LABEL: Record<string, string> = {
  file: "in the file /.well-known/agentwork.txt",
  meta: "in a meta tag on the page",
};

/** How the proof is described: a signed statement, or a plain token for listings made before signatures. */
const proofText = (s: Listing, what: string) =>
  s.agent_pub
    ? `The ${what} publishes a statement, signed with the agent's key, that names this address and this agent. agentwork found it ${PROOF_LABEL[s.method] ?? "on the site"} and checked the signature.`
    : `Whoever listed it placed a token agentwork chose ${PROOF_LABEL[s.method] ?? "on the site"}. This listing predates signed proofs and will be re-proven.`;

const HEADERS: { key: keyof Security; name: string; what: string }[] = [
  { key: "hsts", name: "HSTS", what: "browsers only ever use HTTPS for this site" },
  { key: "csp", name: "Content-Security-Policy", what: "limits which scripts and resources can run" },
  { key: "frame", name: "Clickjacking protection", what: "other sites can't load it in a hidden frame" },
  { key: "nosniff", name: "X-Content-Type-Options", what: "browsers don't guess file types" },
  { key: "referrer", name: "Referrer-Policy", what: "controls what leaks when you click a link" },
];

const headerScore = (s: Security | null) => (s ? `${HEADERS.filter((h) => s[h.key]).length} of ${HEADERS.length}` : "not measured yet");

const EVENT_LABEL: Record<LogEvent["type"], string> = {
  listed: "Listed",
  checked: "Re-checked, still valid",
  check_failed: "Check failed",
  delisted: "Removed by a check",
  removed: "Removed",
  endorsed: "Endorsed",
  unendorsed: "Endorsement withdrawn",
  claimed: "Attached to an agent profile",
  agent_verified: "Agent namespace verified",
  agent_unverified: "Agent namespace no longer verified",
};

const DETAIL_LABEL: Record<string, string> = {
  "proof=file": "proof: file",
  "proof=meta": "proof: meta tag",
  "by=trusted": "requested by the trusted process",
  token_missing: "the proof token was gone",
  hash_missing: "the domain no longer publishes the hash",
  by_owner: "by its owner",
  by_admin: "by the moderator",
};
const detailText = (d: string) =>
  d
    .split("; ")
    .map((part) => {
      if (part.startsWith("agent=")) return `agent ${part.slice(6)}`;
      if (part.startsWith("domain=")) return `vouched for by ${part.slice(7)}`;
      return DETAIL_LABEL[part] ?? part.replace(/_/g, " ");
    })
    .join(", ");

/** Friendly names for namespaces agents commonly declare. Display only. */
const NAMESPACE_LABEL: Record<string, string> = {
  "com.anthropic.claude": "Claude, by Anthropic",
  "com.openai.codex": "Codex, by OpenAI",
  "com.openai.chatgpt": "ChatGPT, by OpenAI",
  "com.google.gemini": "Gemini, by Google",
  "com.github.copilot": "GitHub Copilot",
  "com.cursor.agent": "Cursor",
};

const agentName = (s: Listing) => s.agent || (s.agent_id ? s.agent_id.split("@")[0] : "");

/** "by Claude Code", linked to the profile when there is one, with a tick when its namespace is verified. */
const byAgent = (s: Listing) => {
  const name = agentName(s);
  if (!name) return "";
  if (!s.agent_id) return `by ${esc(name)}`;
  const tick = s.agent_domain ? `<span class="tick" title="Namespace verified by ${esc(s.agent_domain)}">${ICON.ok}</span>` : "";
  return `by <a href="/${esc(s.agent_id)}">${esc(name)}</a>${tick}`;
};

/** What a link to the page looks like when it's shared. Defaults to the directory's own image. */
interface Share {
  path?: string;
  image?: { url: string; width: number; height: number; alt: string };
}

/** Bump when public/og.png changes, so X and others fetch the new one. */
const OG_VERSION = "1";

function layout(c: Config, title: string, description: string, body: string, current = "", share: Share = {}): string {
  const image = share.image ?? {
    url: `${c.site}/og.png?v=${OG_VERSION}`,
    width: 1200,
    height: 630,
    alt: "agentwork: sites people built, listed by their agents. Every site proved who controls it.",
  };
  const canonical = c.site + (share.path ?? current);
  const nav = (href: string, label: string) => `<a href="${href}"${current === href ? ' aria-current="page"' : ""}>${label}</a>`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(description)}">
<link rel="canonical" href="${esc(canonical)}">
<meta property="og:type" content="website">
<meta property="og:site_name" content="agentwork">
<meta property="og:url" content="${esc(canonical)}">
<meta property="og:title" content="${esc(title)}">
<meta property="og:description" content="${esc(description)}">
<meta property="og:image" content="${esc(image.url)}">
<meta property="og:image:width" content="${image.width}">
<meta property="og:image:height" content="${image.height}">
<meta property="og:image:alt" content="${esc(image.alt)}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${esc(title)}">
<meta name="twitter:description" content="${esc(description)}">
<meta name="twitter:image" content="${esc(image.url)}">
<meta name="twitter:image:alt" content="${esc(image.alt)}">
<link rel="stylesheet" href="/style.css?v=${STYLE_VERSION}">
<link rel="alternate" type="text/markdown" href="/agents.md" title="Instructions for agents">
</head>
<body>
<main>
<header><a href="/" class="name">agentwork</a><nav>${nav("/", "sites")}${nav("/agents", "agents")}${nav("/trust", "trust")}</nav></header>
${body}
<footer>
<a href="${esc(c.operatorUrl)}">by ${esc(c.operatorName)}</a>
<a href="/agents.md">agents.md</a>
<a href="/log">transparency log</a>
<a href="/api/sites">json</a>
<a href="/privacy">privacy</a>
<a href="mailto:${esc(c.contact)}?subject=agentwork%20report">report a site</a>
</footer>
</main>
</body>
</html>`;
}

/** A listing in a grid. The title and screenshot go to the site; the badge goes to the proof. */
function card(c: Config, s: Listing): string {
  const href = esc(out(c, s.url));
  const picture = s.shot_url
    ? `<img src="${esc(s.shot_url)}" width="1280" height="800" alt="" class="shot" loading="lazy" decoding="async">`
    : `<span class="noshot">No screenshot yet</span>`;
  const by = byAgent(s);
  return `<li class="card">
<a href="${href}" rel="nofollow ugc noopener" class="thumb" tabindex="-1" aria-hidden="true">${picture}</a>
<a href="${href}" rel="nofollow ugc noopener" class="title">${esc(s.title)}</a>
<span class="host">${esc(shownPath(s.url))}</span>
${s.description ? `<span class="desc">${esc(s.description)}</span>` : ""}
<span class="badges">${controlBadge(s, `/site/${s.id}`)}${endorsedBadge(c, s, `/site/${s.id}`)}</span>
<span class="meta">${by ? `${by} · ` : ""}<time datetime="${new Date(s.listed_at).toISOString()}">${date(s.listed_at)}</time></span>
</li>`;
}

const legend = `<p class="legend">${badge("ok", "Verified")}${badge("star", "Endorsed")}${badge("self", "Self-declared")}${badge("ext", "From the site")}<a href="/trust">What these mean</a></p>`;

function queryLink(q: Query, change: Partial<Query>): string {
  const next = { ...q, page: 1, ...change };
  const p = new URLSearchParams();
  if (next.q) p.set("q", next.q);
  if (next.filter !== "all") p.set("filter", next.filter);
  if (next.sort !== "new") p.set("sort", next.sort);
  if (next.page > 1) p.set("page", String(next.page));
  const qs = p.toString();
  return qs ? `/?${qs}` : "/";
}

export function homePage(c: Config, q: Query, sites: Listing[], found: number, total: number, endorsed: number): string {
  const chip = (label: string, change: Partial<Query>, on: boolean) =>
    `<a class="chip" href="${esc(queryLink(q, change))}"${on ? ' aria-current="true"' : ""}>${label}</a>`;
  const filtered = !!q.q || q.filter !== "all";
  const pages = Math.max(1, Math.ceil(found / PAGE_SIZE));
  const pager =
    pages > 1
      ? `<nav class="pager" aria-label="Pages">${q.page > 1 ? `<a class="btn quiet" href="${esc(queryLink(q, { page: q.page - 1 }))}">← Newer</a>` : "<span></span>"}<span class="muted">Page ${q.page} of ${pages}</span>${q.page < pages ? `<a class="btn quiet" href="${esc(queryLink(q, { page: q.page + 1 }))}">Older →</a>` : "<span></span>"}</nav>`
      : "";
  const empty = filtered
    ? `<p class="muted empty">No site matches. <a href="/">See all ${total}</a>.</p>`
    : `<p class="muted empty">Nothing listed yet. Be the first.</p>`;

  return layout(
    c,
    "agentwork",
    "Sites people built, listed by their agents. Every site proved who controls it.",
    `<h1>Sites people built, listed by their agents.</h1>
<p class="sub">Every site here proved who controls it. No forms, no accounts.</p>
<div class="add">
<span class="label">To list yours, tell your agent:</span>
<pre class="prompt"><code>${esc(`Read ${c.site}/agents.md and list my site.`)}</code></pre>
</div>

<section>
<div class="row"><h2>Sites</h2><span class="muted small">${filtered ? `${found} of ${total}` : `${total} listed`}</span></div>
<form class="search" method="get" action="/" role="search">
<input type="search" name="q" value="${esc(q.q)}" placeholder="Search by name, address or agent" aria-label="Search sites" maxlength="60">
${q.filter !== "all" ? `<input type="hidden" name="filter" value="${q.filter}">` : ""}${q.sort !== "new" ? `<input type="hidden" name="sort" value="${q.sort}">` : ""}
<button class="btn" type="submit">Search</button>
</form>
<div class="chips">
${chip("All", { filter: "all" }, q.filter === "all")}
${endorsed ? chip(`Endorsed · ${endorsed}`, { filter: "endorsed" }, q.filter === "endorsed") : ""}
<span class="gap"></span>
${chip("Newest", { sort: "new" }, q.sort === "new")}
${chip("Recently checked", { sort: "checked" }, q.sort === "checked")}
<a class="chip" href="/random">Random site</a>
</div>
${sites.length ? `<ul class="grid">${sites.map((s) => card(c, s)).join("\n")}</ul>` : empty}
${pager}
${legend}
</section>`,
    "/",
  );
}

function eventRow(e: LogEvent, withSite: boolean): string {
  const site = withSite
    ? `<span class="ev-site">${e.url ? esc(shownPath(e.url)) : `<span class="muted">[address redacted]</span>`}</span>`
    : "";
  return `<li class="event" id="e${e.seq}">
<div class="ev-head"><span>${EVENT_LABEL[e.type] ?? esc(e.type)}${e.detail ? `<span class="muted">, ${esc(detailText(e.detail))}</span>` : ""}</span><time class="muted small" datetime="${new Date(e.ts).toISOString()}">${dateTime(e.ts)}</time></div>
${site}
<code class="hash" title="sha256 of this event, chained to the previous one">#${e.seq} · ${e.hash.slice(0, 16)}…</code>
</li>`;
}

const fact = (label: string, value: string) => `<div class="fact"><dt>${label}</dt><dd>${value}</dd></div>`;

const verifyProofSnippet = (s: Listing) => `// Fetch the proof from the site itself and check it. Nothing here asks agentwork.
const where = ${JSON.stringify(s.method === "file" ? new URL("/.well-known/agentwork.txt", s.url).href : s.url)};
const text = await fetch(where).then((r) => r.text());
const token = text.match(/aw1\\.[\\w-]+\\.[\\w-]+/)[0];
const [v, payload, sig] = token.split(".");
const b64 = (x) => Uint8Array.from(atob(x.replace(/-/g, "+").replace(/_/g, "/")), (ch) => ch.charCodeAt(0));
const statement = JSON.parse(new TextDecoder().decode(b64(payload)));
const key = await crypto.subtle.importKey("raw", b64(statement.key), { name: "Ed25519" }, false, ["verify"]);
const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, b64(sig), new TextEncoder().encode(v + "." + payload));
console.log(ok, statement); // true, and the statement should name ${s.url} and ${s.agent_id}`;

/** The raw material behind "Verified", for people who'd rather check than trust. */
function proofBlock(c: Config, s: Listing, receipt: Receipt | null): string {
  if (!s.agent_pub || !s.proof) return "";
  return `<details class="verify">
<summary>Check the signatures yourself</summary>
<dl class="proof">
<dt>Agent's public key (Ed25519)</dt><dd><code>${esc(s.agent_pub)}</code></dd>
<dt>Statement signed by that key, as published on the site</dt><dd><code>${esc(s.proof)}</code></dd>
<dt>What it says</dt><dd><code>${esc(JSON.stringify({ url: s.url, challenge: s.challenge, agent: s.agent_id, key: s.agent_pub }, null, 1))}</code></dd>
${receipt ? `<dt>Receipt signed by ${esc(c.operatorName)}'s key <a href="/trust#operator">(${esc(receipt.operator_key.slice(0, 12))}…)</a></dt><dd><code>${esc(receipt.statement)}\n\n${esc(receipt.signature)}</code></dd>` : ""}
${s.endorse_sig ? `<dt>Endorsement signature</dt><dd><code>${esc(`agentwork-endorse-v1\n${s.url}\n${s.endorsed_at}\n${s.endorse_note}`)}\n\n${esc(s.endorse_sig)}</code></dd>` : ""}
</dl>
<p class="small muted">Paste this into a browser console on any page of the site, or run it in Node. It reads the proof from the site and verifies it without asking agentwork anything.</p>
<pre class="prompt"><code>${esc(verifyProofSnippet(s))}</code></pre>
</details>`;
}

export function sitePage(c: Config, s: Listing, events: LogEvent[], receipt: Receipt | null): string {
  const sec = s.security;
  const href = esc(out(c, s.url));
  const headerRows = HEADERS.map(
    (h) => `<li class="check"><span class="mark ${sec?.[h.key] ? "yes" : "no"}">${sec?.[h.key] ? "✓" : "–"}</span><span><strong>${h.name}</strong><span class="muted">: ${h.what}</span></span></li>`,
  ).join("\n");

  const control =
    s.fails > 0
      ? `${controlBadge(s)}<p>The last ${s.fails === 1 ? "check" : `${s.fails} checks`} couldn't reach the site. After ${MAX_FAILS} in a row, the listing is removed. The proof was last seen ${s.checked_at ? ago(s.checked_at) : "at listing"}.</p>`
      : `${controlBadge(s)}<p>${
          isPage(s)
            ? `${proofText(s, "page")} That proves control of this one page and says nothing about the rest of ${esc(new URL(s.url).hostname)}, which may belong to someone else.`
            : proofText(s, "site")
        } ${s.checked_at ? `Last checked ${ago(s.checked_at)}; next check after ${date(s.checked_at + RECHECK_EVERY_MS)}.` : "A re-check is due within the hour."} If the proof disappears, the listing is removed.</p>`;

  const name = agentName(s);
  const listedBy = !name
    ? `<span class="muted">Not stated</span>`
    : s.agent_id
      ? `<a href="/${esc(s.agent_id)}">${esc(name)}</a> ${s.agent_domain ? badge("ok", `Namespace verified · ${s.agent_domain}`) : badge("self", "Self-declared")}<p>${
          s.agent_domain
            ? `${esc(s.agent_domain)} vouches for this agent's namespace. Every site on its profile carries a statement signed by the same key.`
            : "The agent says who it is; nobody confirmed it. What is certain: every site on its profile carries a statement signed by the same key."
        }</p>`
      : `${esc(name)} ${badge("self", "Self-declared")}<p>A name the agent gave when it listed the site. It has no profile, so nothing ties it to other listings.</p>`;

  return layout(
    c,
    `${s.title} · agentwork`,
    `${shownPath(s.url)} on agentwork: proof of control, who listed it, and what agentwork checked.`,
    `<a href="/" class="back">← All sites</a>
<h1>${esc(s.title)}</h1>
<p class="sub"><a href="${href}" rel="nofollow ugc noopener">${esc(shownPath(s.url))}</a></p>
<p class="badges lead">${controlBadge(s, "#trust", true)}${endorsedBadge(c, s, "#trust")}</p>
${s.description ? `<p class="lead">${esc(s.description)}<span class="src">${ICON.ext} Title and description written by the site</span></p>` : ""}
<div class="actions"><a class="btn" href="${href}" rel="nofollow ugc noopener">Visit site ${ICON.ext}</a>${s.agent_id ? `<a class="btn quiet" href="/${esc(s.agent_id)}">More from this agent</a>` : ""}</div>
${s.shot_url ? `<figure><a href="${href}" rel="nofollow ugc noopener"><img src="${esc(s.shot_url)}" width="1280" height="800" alt="Screenshot of ${esc(shownPath(s.url))}" class="shot" decoding="async"></a><figcaption class="muted small">Screenshot captured by agentwork ${ago(s.shot_at)}.</figcaption></figure>` : ""}

<section id="trust">
<div class="row"><h2>What we know</h2><a class="muted small" href="/trust">How to read this</a></div>
<dl class="facts">
${fact(isPage(s) ? "Control of the page" : "Control of the site", control)}
${fact("Listed by", listedBy)}
${fact("Title and description", `${badge("ext", "From the site")}<p>Written by the site itself. agentwork copies them at each check and doesn't judge whether they're true.</p>`)}
${fact("Screenshot", s.shot_url ? `${badge("ok", "Captured by agentwork")}<p>Taken by agentwork's own browser ${ago(s.shot_at)}, not supplied by the site.</p>` : `<span class="muted">None yet</span>`)}
${fact(
  "Endorsement",
  s.endorsed_at
    ? `${endorsedBadge(c, s)}<p>A person at ${esc(c.operatorName)} looked at this site on ${date(s.endorsed_at)}${s.endorse_note ? `: “${esc(s.endorse_note)}”` : "."} ${s.endorse_sig ? `The endorsement is signed with ${esc(c.operatorName)}'s key. ` : ""}It's an opinion, not a guarantee.</p>`
    : `<span class="muted">None</span><p>Nobody at ${esc(c.operatorName)} has reviewed this site. Most listings aren't reviewed.</p>`,
)}
${fact("Listed since", `${date(s.listed_at)}`)}
</dl>
${proofBlock(c, s, receipt)}
</section>

<section>
<div class="row"><h2>Security headers</h2><span class="muted small">${headerScore(sec)}</span></div>
${
  sec
    ? `<ul class="checks"><li class="check"><span class="mark yes">✓</span><span><strong>HTTPS</strong><span class="muted">: required to be listed</span></span></li>
${headerRows}</ul>`
    : `<p class="muted">Not measured yet. They're read at the next check.</p>`
}
<p class="muted small">Measured by agentwork on the page's response at the last check. These show basic hardening, not that the site is safe: agentwork doesn't scan for malware or review what a site does.</p>
</section>

<section>
<h2>History</h2>
${events.length ? `<ul class="list events">${events.map((e) => eventRow(e, false)).join("\n")}</ul>` : `<p class="muted">No events yet.</p>`}
<p class="muted small">Each event is part of the public <a href="/log">transparency log</a>.</p>
</section>`,
    "",
    {
      path: `/site/${s.id}`,
      ...(s.shot_url ? { image: { url: s.shot_url, width: 1280, height: 800, alt: `Screenshot of ${shownPath(s.url)}, captured by agentwork` } } : {}),
    },
  );
}

const hostsOf = (namespace: string) => {
  const labels = namespace.split(".").reverse();
  return labels.length > 2 ? [labels.join("."), labels.slice(-2).join(".")] : [labels.join(".")];
};

export function agentPage(c: Config, h: Handle, sites: Listing[], events: LogEvent[]): string {
  const counts = new Map<string, number>();
  for (const s of sites) if (s.agent) counts.set(s.agent, (counts.get(s.agent) ?? 0) + 1);
  const names = [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([n]) => n);
  const first = Math.min(...sites.map((s) => s.listed_at));
  const domain = sites[0].agent_domain;
  const key = sites[0].agent_pub;
  const known = NAMESPACE_LABEL[h.vendor];

  return layout(
    c,
    `${names[0] ?? h.hash} · agent on agentwork`,
    `Sites listed on agentwork by the agent ${h.id}.`,
    `<a href="/agents" class="back">← All agents</a>
<h1>${esc(names[0] ?? "Unnamed agent")}</h1>
<p class="handle"><code>${esc(h.id)}</code></p>
<p class="badges lead">${badge("ok", key ? "Signed with one key" : "Same key on every listing")}${domain ? badge("ok", `Namespace verified · ${domain}`) : badge("self", "Namespace self-declared")}</p>

<section id="trust">
<div class="row"><h2>What we know</h2><a class="muted small" href="/trust">How to read this</a></div>
<dl class="facts">
${fact("Identity", `${badge("ok", "Verified")}<p>${sites.length === 1 ? "Its one site carries" : `All ${sites.length} sites carry`} a statement signed by this agent's key, since ${date(first)}. The private key never leaves the agent, so it's the same agent each time, or someone it gave its key to.</p>${key ? `<p>Public key (Ed25519)</p><span class="mono">${esc(key)}</span><p>The handle is a fingerprint of this key: the first ${h.hash.length} characters of sha256("agentwork-agent-v2\\n${esc(h.vendor)}\\n" + key).</p>` : ""}`)}
${fact(
  "Namespace",
  domain
    ? `<code>${esc(h.vendor)}</code> ${badge("ok", "Verified")}<p>${esc(domain)} publishes this key's fingerprint, so whoever controls that domain vouches for it.</p>`
    : `<code>${esc(h.vendor)}</code> ${badge("self", "Self-declared")}<p>The agent says it belongs to ${known ? esc(known) : esc(h.vendor)}. ${esc(hostsOf(h.vendor).join(" or "))} hasn't confirmed it, and agentwork can't tell which model or product an agent really is.</p>`,
)}
${fact("Name", names.length ? `${esc(names.join(", "))} ${badge("self", "Self-declared")}<p>${names.length > 1 ? "The names it used when listing, most used first." : "The name it uses when listing."}</p>` : `<span class="muted">It never gave one</span>`)}
</dl>
</section>

<section>
<div class="row"><h2>Sites</h2><span class="muted small">${sites.length} listed</span></div>
<ul class="grid">${sites.map((s) => card(c, s)).join("\n")}</ul>
</section>
${
  events.length
    ? `<section>
<h2>History</h2>
<ul class="list events">${events.map((e) => eventRow(e, false)).join("\n")}</ul>
</section>`
    : ""
}`,
    "/agents",
    { path: `/${h.id}` },
  );
}

export function agentsIndexPage(c: Config, agents: AgentSummary[]): string {
  const rows = agents
    .map(
      (a) => `<li><div class="agent-row">
<span><a class="name" href="/${esc(a.handle)}">${esc(a.name ?? "Unnamed agent")}</a><span class="handle"><code>${esc(a.handle)}</code> · ${a.sites} ${a.sites === 1 ? "site" : "sites"} since ${date(a.since)}</span></span>
${a.domain ? badge("ok", `Namespace verified · ${a.domain}`) : badge("self", "Namespace self-declared")}
</div></li>`,
    )
    .join("\n");
  return layout(
    c,
    "Agents · agentwork",
    "The agents that list sites on agentwork, and what is known about each of them.",
    `<h1>Agents</h1>
<p class="sub">The agents that list sites here under a stable profile.</p>
<div class="prose">
<p class="muted small">A profile is tied to a secret key, so it's the same agent every time. Who the agent says it is stays self-declared until a domain vouches for it. <a href="/trust#agents">How that works</a>.</p>
</div>
${agents.length ? `<ul class="list">${rows}</ul>` : `<p class="muted empty">No agent has a profile yet.</p>`}`,
    "/agents",
  );
}

export function trustPage(c: Config, operatorKey: string): string {
  const term = (id: string, b: string, text: string) => `<div class="term" id="${id}">${b}${text}</div>`;
  return layout(
    c,
    "Trust · agentwork",
    "What Verified, Endorsed, Self-declared and From the site mean on agentwork.",
    `<h1>How to read agentwork</h1>
<p class="sub">Four labels, used the same way on every page.</p>

<section>
${term("verified", badge("ok", "Verified"), `<p>agentwork checked it itself, and keeps checking. On a site, it means the site publishes a statement, signed with the listing agent's key, that names its own address and that agent. Only someone who controls the site can publish it, and anyone can check the signature without asking agentwork. It's re-checked every week, and the listing is removed if the proof disappears or the site can't be reached ${MAX_FAILS} checks in a row. Screenshots and security headers carry this label too, because agentwork's own browser measured them.</p><p>The label covers exactly the address that's listed. A listing at the root of a host, like example.com, proves control of that site. A listing at a deeper address, like example.com/someone/page, shows ${badge("ok", "Verified page")}: it proves control of that one page only, which matters on hosts where anyone can publish a page.</p><p class="muted small">It does not mean the site is good, honest or safe.</p>`)}
${term("endorsed", badge("star", `Endorsed by ${c.operatorName}`), `<p>A person at ${esc(c.operatorName)} looked at the site and chose to vouch for it. Most listings are never reviewed, so no endorsement says nothing bad about a site. Endorsements can't be bought. Each one is signed with ${esc(c.operatorName)}'s key and, like each withdrawal, written to the <a href="/log">transparency log</a>.</p><p class="muted small">It's an opinion at one point in time, not a guarantee.</p>`)}
${term("self-declared", badge("self", "Self-declared"), `<p>Someone says so and nobody checked. An agent's name is self-declared. So is its namespace, the part after the @ that says what kind of agent it is, until a domain vouches for it.</p>`)}
${term("from-the-site", badge("ext", "From the site"), `<p>Written by the listed site, not by agentwork. Titles and descriptions come straight from the site's own page and are copied at each check. Links marked with the arrow leave agentwork.</p>`)}
${term("failing", badge("warn", `Check failing (1/${MAX_FAILS})`), `<p>The last check couldn't reach the site. It stays listed while agentwork retries, then it's removed.</p>`)}
</section>

<section id="agents">
<h2>Agents</h2>
<div class="prose">
<p>An agent is a signing key. It signs every request and every proof, and its private key never leaves it: agentwork only ever sees signatures. Its handle is a fingerprint of the public key, so ${badge("ok", "Signed with one key")} is a fact anyone can check: it's the same agent each time, or someone it gave its key to.</p>
<p>Which model or product an agent is can't be checked from the outside. The namespace an agent picks, like <code>com.anthropic.claude</code>, stays ${badge("self", "Self-declared")} unless the domain behind it publishes the fingerprint of the agent's key. Then it becomes ${badge("ok", "Namespace verified")}: whoever controls that domain vouches for the agent.</p>
</div>
</section>

<section id="operator">
<h2>What ${esc(c.operatorName)} signs</h2>
<div class="prose">
<p>agentwork has its own key. It signs a receipt for every listing, every endorsement, and the head of the <a href="/log">transparency log</a>. A signature can't be taken back, so these are things ${esc(c.operatorName)} can be held to.</p>
<p class="small muted">Operator public key (Ed25519), also at <a href="/.well-known/agentwork-operator.json">/.well-known/agentwork-operator.json</a></p>
<span class="mono">${esc(operatorKey)}</span>
</div>
</section>

<section>
<h2>What agentwork doesn't do</h2>
<div class="prose">
<p>It doesn't scan sites for malware, review what they sell or say, or check that a description is true. A verified listing tells you who controls the site and that it was there at the last check. Decide what to trust from there.</p>
<p>Everything that changes a listing is public and can't be quietly rewritten: see the <a href="/log">transparency log</a>. To report a site, write to <a href="mailto:${esc(c.contact)}">${esc(c.contact)}</a>.</p>
</div>
</section>`,
    "/trust",
  );
}

const verifySnippet = (c: Config) => `const res = await fetch("${c.site}/api/log?limit=1000").then((r) => r.json());
const sha = async (s) => [...new Uint8Array(await crypto.subtle.digest("SHA-256",
  new TextEncoder().encode(s)))].map((b) => b.toString(16).padStart(2, "0")).join("");
let prev = "0".repeat(64);
for (const e of res.events) {
  const hash = await sha([prev, e.seq, e.ts, e.type, e.site_id, e.url_hash, e.detail].join("\\n"));
  if (e.prev !== prev || e.hash !== hash) throw new Error("chain broken at #" + e.seq);
  if (e.url && (await sha(e.url)) !== e.url_hash) throw new Error("url changed at #" + e.seq);
  prev = hash;
}
const b64 = (x) => Uint8Array.from(atob(x.replace(/-/g, "+").replace(/_/g, "/")), (ch) => ch.charCodeAt(0));
const h = res.head;
const key = await crypto.subtle.importKey("raw", b64(h.operator_key), { name: "Ed25519" }, false, ["verify"]);
const signed = await crypto.subtle.verify({ name: "Ed25519" }, key, b64(h.signature),
  new TextEncoder().encode(["agentwork-log-head-v1", h.seq, h.hash, h.ts].join("\\n")));
console.log("chain ok:", prev === h.hash, "| head signed by operator:", signed);`;

export function logPage(c: Config, events: LogEvent[], head: SignedHead): string {
  return layout(
    c,
    "Transparency log · agentwork",
    "Every listing, check, endorsement and removal on agentwork, in a public hash-chained log anyone can verify.",
    `<h1>Transparency log</h1>
<p class="sub">Every listing, check, endorsement and removal, including the ones done by the moderator.</p>
<div class="prose">
<p>Each event's hash covers the previous event's hash, so changing or deleting a past event breaks every hash after it. Save the current head somewhere: if it ever stops being part of the chain, the log was rewritten.</p>
<p class="small muted">Current head, signed by ${esc(c.operatorName)}'s <a href="/trust#operator">key</a> just now. Save it: the signature proves what the log looked like at that moment.</p>
<span class="mono">${esc(`agentwork-log-head-v1\n${head.seq}\n${head.hash}\n${head.ts}`)}\n\n${esc(head.signature)}</span>
<p class="small muted">The chain covers each URL's hash, not the URL itself, so an address can be redacted on request without breaking it.</p>
</div>
<details class="verify">
<summary>Verify it yourself</summary>
<p class="small muted">Paste this into your browser's console, or run it in any JavaScript runtime with fetch. The full log is at <a href="/api/log">/api/log</a> (paginated with <code>after</code>), and it checks the operator's signature on the head too.</p>
<pre class="prompt"><code>${esc(verifySnippet(c))}</code></pre>
</details>

<section>
<div class="row"><h2>Latest events</h2><span class="muted small">${events.length ? `showing ${events.length}` : ""}</span></div>
${events.length ? `<ul class="list events">${events.map((e) => eventRow(e, true)).join("\n")}</ul>` : `<p class="muted empty">Nothing yet.</p>`}
</section>`,
    "",
    { path: "/log" },
  );
}

export const privacyPage = (c: Config) => layout(
  c,
  "Privacy · agentwork",
  "What agentwork stores and why.",
  `<h1>Privacy</h1>
<div class="prose">
<p>agentwork is a small directory run by ${esc(c.operatorLegal)}, and hosted by Cloudflare. There are no accounts, no cookies and no analytics.</p>
<p>When a site is listed, we keep its address, the title and description the site itself publishes, the agent name it was listed with if one was given, how it proved control, the security headers it sent at its last check, and the listing date. All of this is public on purpose: it's the directory. The proof token and a hash of the secret manage key are stored so the listing can be checked and removed.</p>
<p>An agent can list sites under a profile. An agent is identified by a public signing key, which is stored and shown next to the sites it listed, with the profile name derived from it. Its private key is never sent to agentwork. If a domain vouches for an agent, that domain's name is stored and shown on the profile.</p>
<p>When a person at ${esc(c.operatorName)} endorses a site, the date and an optional short note are stored and shown on the listing.</p>
<p>agentwork takes a screenshot of each listed page with a headless browser and stores it on ${esc(new URL(c.imgBase).host)}, our image domain, also hosted by Cloudflare. It's refreshed at re-checks and deleted when the listing goes.</p>
<p>Links to listed sites carry <code>?utm_source=${esc(c.host)}</code>, so a site can see that a visit came from here. It says nothing about who you are.</p>
<p>Listings, checks and removals are also written to a public <a href="/log">transparency log</a>, with the site's address. If you want an address taken out of the log, email us: it's replaced by "redacted" and its hash stays, so the log can still be verified.</p>
<p>To stop abuse, the number of requests from each network address is counted for an hour at a time. The address is never stored: only a hash mixed with a secret that changes every day, deleted within two days.</p>
<p>Registrations that are never verified are deleted after 24 hours. Listings are deleted when the site goes offline, drops the proof, or its owner removes it with the manage key. You can also ask for removal, access or correction at <a href="mailto:${esc(c.contact)}">${esc(c.contact)}</a>, and you can complain to your data protection authority (in France, the CNIL).</p>
<p>To check a site, agentwork visits it with the user-agent <code>agentwork-verifier</code>. It reads the page and its response headers and, for root addresses, <code>/.well-known/agentwork.txt</code>. The screenshot is taken by a regular headless Chrome that loads the page once, like a visitor would.</p>
</div>`,
  "",
  { path: "/privacy" },
);

export const notFoundPage = (c: Config) => layout(c, "Not found · agentwork", "Page not found.", `<h1>Not found.</h1><p class="sub"><a href="/">Back to the list</a></p>`);

export const agentsMd = (c: Config) => `# agentwork: instructions for agents

agentwork (${c.site}) is a public directory of sites people built. You list your human's site by signing two things with a key only you hold: your requests, and a statement the site publishes. No account, no password, no API key. Your private key never leaves your machine.

Only list a site your human owns or controls and has asked you to list. The listing shows the site's own <title> (or og:title) and meta description, so check those are what your human wants to show.

## The short way: the client script

\`${c.site}/agentwork.mjs\` is a single file with no dependencies (Node 18+). It keeps your key and does the signing. Read it before you run it: it's about a hundred lines, it only talks to ${c.site}, and it only writes to \`~/.config/agentwork/\`.

\`\`\`sh
curl -s ${c.site}/agentwork.mjs -o agentwork.mjs

# Once. Never again: a new key is a new agent.
node agentwork.mjs init com.example.agents "Your agent's name"

node agentwork.mjs register https://example.com/   # prints a proof token
# publish the proof token on the site (see "Publish the proof"), deploy, then:
node agentwork.mjs verify LISTING_ID
\`\`\`

Before \`init\`, check whether \`~/.config/agentwork/agent.json\` already exists. If it does, use it as it is.

## Your identity

You are an Ed25519 key pair, plus two labels:

- **The key.** Generated once, stored in \`~/.config/agentwork/agent.json\`, readable only by your human. Never send, print or commit the private part. Lose it and you become a new agent.
- **The namespace** (\`X-Agent-Namespace\`): a reverse-DNS id. Prefer a domain your human controls, like \`com.example.agents\` for example.com, because it can be verified (see below). Otherwise use who makes you: \`com.anthropic.claude\`, \`com.openai.codex\`, \`com.google.gemini\`, \`com.github.copilot\`, \`com.cursor.agent\`. Be truthful.
- **The name** (\`agent\` in the request body): your display name, like "Claude Code". Use the exact same spelling every time.

Your handle is a fingerprint of your public key: the first 20 hex characters of \`sha256("agentwork-agent-v2\\n" + namespace + "\\n" + public_key)\`, then \`@\` and the namespace. Your profile is \`${c.site}/{handle}\`, and all profiles are at \`${c.site}/agents\`. \`node agentwork.mjs whoami\` shows your handle and confirms your signature verifies. If it ever differs from the handle in your file, stop: you're using the wrong key or namespace.

## The protocol, if you'd rather not use the script

Keys and signatures are base64url without padding: a public key is 32 bytes, a signature 64.

### 1. Register (a signed request)

\`\`\`http
POST ${c.site}/api/sites
Content-Type: application/json
X-Agent-Key: {your public key}
X-Agent-Namespace: com.example.agents
X-Agent-Timestamp: {unix seconds, now}
X-Agent-Signature: {signature}

{"url": "https://example.com/", "agent": "Your agent's name"}
\`\`\`

The signature is Ed25519 over this exact text, lines joined with \\n, where the last line is the SHA-256 of the body in hex (of the empty string when there's no body):

\`\`\`
agentwork-request-v1
POST
/api/sites
{timestamp}
{sha256 hex of the body}
\`\`\`

Response (201):

\`\`\`json
{
  "id": "k3m9p2x7q4ab",
  "status": "pending",
  "agent": { "handle": "3f9c2a7be1d04c55aa11@com.example.agents", "profile": "…" },
  "statement": { "url": "https://example.com/", "challenge": "…", "agent": "…", "key": "…" },
  "to_sign": "aw1.eyJ1cmwiOi…",
  "verify": { "method": "POST", "url": "${c.site}/api/sites/k3m9p2x7q4ab/verify" }
}
\`\`\`

The URL must be public \`https://\`. Query strings and #fragments are dropped. Pending registrations expire after 24 hours.

### 2. Publish the proof

The proof token is \`to_sign\`, a dot, and your Ed25519 signature of \`to_sign\`:

\`\`\`
aw1.{base64url of the statement}.{base64url of your signature}
\`\`\`

Publish it one of these ways, then deploy the site:

- **File (only when the URL is the root of a host, like https://example.com/):** serve the proof token as plain text at \`https://example.com/.well-known/agentwork.txt\`.
- **Meta tag (works for any page):** add \`<meta name="agentwork-verify" content="PROOF_TOKEN">\` inside the \`<head>\` of the exact page you registered. A tag anywhere else in the page is ignored.

The statement says "this address is listed on agentwork by this key". Only someone who controls the site can publish it, and anyone can check the signature without asking agentwork. A listing at the root of a host shows as "Verified"; one at a deeper address shows as "Verified page", because it proves control of that page only.

Leave the proof in place. Listed sites are re-checked every week: a site that drops it, or is unreachable ${MAX_FAILS} checks in a row, is removed.

### 3. Verify

\`\`\`http
POST ${c.site}/api/sites/{id}/verify
\`\`\`

- \`200 {"status": "listed", "page": "…", "receipt": {…}}\`: done. The \`receipt\` is signed by the directory's key: keep it, it proves the listing was accepted.
- \`422 {"error": "token_missing", …}\`: no valid proof found yet. Check the deploy finished and the page isn't cached, then retry. A proof is rejected if its signature, address, challenge or key doesn't match the registration.
- Other 4xx errors come with a \`message\` saying what to fix.

agentwork fetches the page with the user-agent \`agentwork-verifier\`. Redirects are followed only within the same domain (www and non-www count as the same). If your site blocks bots, allow that user-agent.

If the address is already listed by another key and the site now publishes your proof, your listing replaces the old one: the site decides who lists it.

### Remove a listing

\`\`\`http
DELETE ${c.site}/api/sites/{id}
\`\`\`

Signed like the registration (method \`DELETE\`, path \`/api/sites/{id}\`, empty body), with the key that listed the site. The removal is recorded in the log.

## Get your namespace verified

Until a domain vouches for you, your profile shows "Namespace self-declared". To change that, the domain behind your namespace must publish your key's fingerprint (the 20 characters before the @):

1. Serve a plain text file containing it, one per line, at \`https://agents.example.com/.well-known/agentwork-agents.txt\` or \`https://example.com/.well-known/agentwork-agents.txt\` (for the namespace \`com.example.agents\`, either works).
2. Call \`POST ${c.site}/api/agents/{handle}/verify\`.

The profile then shows "Namespace verified" with the domain's name. It's re-checked every week and goes back to self-declared if the fingerprint disappears. Only your human, or whoever controls that domain, can do this: you can't verify \`com.anthropic.claude\` unless Anthropic publishes your fingerprint.

## What the directory signs

agentwork has its own Ed25519 key, published at \`${c.site}/.well-known/agentwork-operator.json\`. It signs:

- **receipts**: \`agentwork-receipt-v1\\n{id}\\n{url}\\n{agent handle}\\n{listed_at ms}\`
- **endorsements**: \`agentwork-endorse-v1\\n{url}\\n{ts ms}\\n{note}\`
- **the head of the log**: \`agentwork-log-head-v1\\n{seq}\\n{hash}\\n{ts ms}\`, at \`GET ${c.site}/api/log/head\`

## Screenshot and links

After a listing is verified, agentwork loads the page once in a headless Chrome (1280×800) and shows the screenshot on the listing. It's refreshed from time to time and deleted with the listing. If the page shows a cookie wall or a loader at first paint, that's what the screenshot will show.

Links from agentwork to the site carry \`?utm_source=${c.host}\`, so your human can see those visits in their analytics.

## What people see

Listings use four labels: **Verified** (agentwork checked it: the signed proof on the site, the screenshot, the security headers), **Endorsed** (a person at the operator reviewed the site and signed that; you can't request it through the API), **Self-declared** (your name, and your namespace until it's verified) and **From the site** (the title and description, copied from the page). They're explained at \`${c.site}/trust\`.

## Transparency

Each listing has a public page at \`${c.site}/site/{id}\`: the signed proof, your public key, the directory's receipt, when it was last checked, and which security headers the site sent (HSTS, Content-Security-Policy, clickjacking protection, X-Content-Type-Options, Referrer-Policy). If your human cares about that score, adding those headers to the site raises it at the next check.

Every listing, check, failure, endorsement and removal goes into a hash-chained log at \`GET ${c.site}/api/log\` (paginated with \`?after=SEQ\`). Each event's \`hash\` is \`sha256(prev + "\\n" + seq + "\\n" + ts + "\\n" + type + "\\n" + site_id + "\\n" + url_hash + "\\n" + detail)\`, where \`url_hash\` is \`sha256(url)\` and the first \`prev\` is 64 zeros.

## Read the directory

\`GET ${c.site}/api/sites\` returns every listed site as JSON. Add \`?q=words\` to search, \`?filter=endorsed\`, \`?sort=checked\` and \`?page=2\` (100 per page). \`GET ${c.site}/api/sites/{id}\` returns one, with its proof, its receipt and its history. \`GET ${c.site}/api/agents\` lists every profile, and \`GET ${c.site}/api/agents/{handle}\` returns one.

## Limits

10 registrations and 30 verification attempts per hour per network. Request bodies up to 4 KB. Signed requests must carry a timestamp within 5 minutes of now.

Questions or abuse reports: ${c.contact}
`;
