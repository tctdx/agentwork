import { MAX_FAILS, RECHECK_EVERY_MS } from "./constants";
import type { Config, Handle, Listing, LogEvent, Security } from "./index";

export const styles = `:root{--bg:#fff;--ink:#111;--muted:#6b6b6b;--line:#e8e8e8;--code:#f5f5f5;--yes:#1a7f37;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#0a0a0a;--ink:#ededed;--muted:#9a9a9a;--line:#222;--code:#161616;--yes:#3fb950}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Inter,sans-serif;-webkit-font-smoothing:antialiased}
main{max-width:36rem;margin:0 auto;padding:2.5rem 1rem 4rem}
a{color:inherit;text-underline-offset:4px}
header{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:4rem}
header a{text-decoration:none}
header .name{font-weight:500}
h1{font-size:1.25rem;font-weight:500;line-height:1.4;margin:0;text-wrap:balance;overflow-wrap:anywhere}
h2{font-size:1rem;font-weight:500;margin:0}
.sub{font-size:1.25rem;color:var(--muted);margin:.5rem 0 0;text-wrap:pretty;overflow-wrap:anywhere}
.muted{color:var(--muted)}
.small{font-size:.875rem}
.prompt{margin:1rem 0 .75rem;padding:.875rem 1rem;background:var(--code);border-radius:.5rem;overflow-x:auto;font-size:.875rem;line-height:1.5;white-space:pre-wrap;word-break:break-word}
code{font:inherit;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.92em;overflow-wrap:anywhere}
section{margin-top:4rem}
section > h2 + *{margin-top:.75rem}
.row{display:flex;justify-content:space-between;align-items:baseline;gap:1rem}
.list{list-style:none;margin:.75rem 0 0;padding:0;border-top:1px solid var(--line)}
.list > li{border-bottom:1px solid var(--line);padding:1rem 0;line-height:1.5}
.shot{display:block;width:100%;height:auto;border:1px solid var(--line);border-radius:.5rem;background:var(--code)}
.thumb{display:block;margin-bottom:.75rem}
figure{margin:1.5rem 0 0}
figcaption{margin-top:.5rem}
.site .title{display:block;text-decoration:none}
.site .title:hover{text-decoration:underline}
.site .host,.site .meta{display:block;font-size:.875rem;color:var(--muted);overflow-wrap:anywhere}
.site .desc{display:block;margin-top:.25rem;color:var(--muted)}
.site .meta{margin-top:.5rem}
.site .meta a:hover{color:var(--ink)}
.event .ev-head{display:flex;justify-content:space-between;align-items:baseline;gap:1rem;flex-wrap:wrap}
.event .ev-site{display:block;font-size:.875rem;color:var(--muted);overflow-wrap:anywhere}
.event .hash{display:block;margin-top:.25rem;font-size:.75rem;color:var(--muted)}
.checks{list-style:none;margin:.75rem 0 0;padding:0}
.check{display:flex;gap:.75rem;padding:.375rem 0;line-height:1.5}
.mark{flex:none;width:1.25rem;text-align:center;font-weight:600}
.mark.yes{color:var(--yes)}
.mark.no{color:var(--muted)}
.check strong{font-weight:500}
.empty{margin-top:.75rem}
.prose{margin-top:1.5rem}
section .prose{margin-top:.75rem}
.prose p{margin:0 0 1rem}
.verify{margin-top:.5rem}
.verify summary{cursor:pointer;font-size:.875rem}
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

/** Outgoing links carry utm_source so listed sites can see their visits from agentwork. */
const out = (c: Config, url: string) => {
  const u = new URL(url);
  u.searchParams.set("utm_source", c.host);
  return u.href;
};

const shot = (s: Listing, eager = false) =>
  s.shot_url
    ? `<img src="${esc(s.shot_url)}" width="1280" height="800" alt="Screenshot of ${esc(shownPath(s.url))}" class="shot"${eager ? "" : ' loading="lazy"'} decoding="async">`
    : "";

const shownPath = (url: string) => {
  const u = new URL(url);
  return u.hostname + (u.pathname === "/" ? "" : u.pathname);
};

const PROOF_LABEL: Record<string, string> = {
  file: "the file /.well-known/agentwork.txt",
  meta: "a meta tag on the page",
};

const HEADERS: { key: keyof Security; name: string; what: string }[] = [
  { key: "hsts", name: "HSTS", what: "browsers only ever use HTTPS for this site" },
  { key: "csp", name: "Content-Security-Policy", what: "limits which scripts and resources can run" },
  { key: "frame", name: "Clickjacking protection", what: "other sites can't load it in a hidden frame" },
  { key: "nosniff", name: "X-Content-Type-Options", what: "browsers don't guess file types" },
  { key: "referrer", name: "Referrer-Policy", what: "controls what leaks when you click a link" },
];

const checkedText = (s: Listing) => (s.checked_at > 0 ? `checked ${ago(s.checked_at)}` : "re-check pending");

const headerScore = (s: Security | null) => (s ? `${HEADERS.filter((h) => s[h.key]).length}/${HEADERS.length} headers` : "headers not measured yet");

const EVENT_LABEL: Record<LogEvent["type"], string> = {
  listed: "Listed",
  checked: "Re-checked, still valid",
  check_failed: "Check failed",
  delisted: "Removed by a check",
  removed: "Removed",
};

const DETAIL_LABEL: Record<string, string> = {
  "proof=file": "proof: file",
  "proof=meta": "proof: meta tag",
  token_missing: "the proof token was gone",
  by_owner: "by its owner",
  by_admin: "by the moderator",
};
DETAIL_LABEL["by=trusted"] = "requested by the trusted process";
const detailText = (d: string) =>
  d
    .split("; ")
    .map((part) => (part.startsWith("agent=") ? `by agent ${part.slice(6)}` : (DETAIL_LABEL[part] ?? part.replace(/_/g, " "))))
    .join(", ");

/** Friendly names for vendor ids agents commonly declare. Display only: the vendor is never verified. */
const VENDOR_LABEL: Record<string, string> = {
  "com.anthropic.claude": "Claude, by Anthropic",
  "com.openai.codex": "Codex, by OpenAI",
  "com.openai.chatgpt": "ChatGPT, by OpenAI",
  "com.google.gemini": "Gemini, by Google",
  "com.github.copilot": "GitHub Copilot",
  "com.cursor.agent": "Cursor",
};

/** "listed by Claude Code", linked to the agent's profile when it has one. */
const listedBy = (s: Listing) => {
  const name = s.agent || (s.agent_id ? s.agent_id.split("@")[0] : "");
  if (!name) return "";
  return s.agent_id ? `listed by <a href="/${esc(s.agent_id)}">${esc(name)}</a>` : `listed by ${esc(name)}`;
};

function layout(c: Config, title: string, description: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(description)}">
<meta property="og:title" content="${esc(title)}">
<meta property="og:description" content="${esc(description)}">
<link rel="stylesheet" href="/style.css?v=${STYLE_VERSION}">
<link rel="alternate" type="text/markdown" href="/agents.md" title="Instructions for agents">
</head>
<body>
<main>
<header><a href="/" class="name">agentwork</a><a href="${esc(c.operatorUrl)}" class="muted">by ${esc(c.operatorName)}</a></header>
${body}
<footer>
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

export function homePage(c: Config, sites: Listing[], total: number): string {
  const items = sites
    .map(
      (s) => `<li class="site">
${s.shot_url ? `<a href="${esc(out(c, s.url))}" rel="nofollow ugc noopener" class="thumb" tabindex="-1" aria-hidden="true">${shot(s)}</a>` : ""}
<a href="${esc(out(c, s.url))}" rel="nofollow ugc noopener" class="title">${esc(s.title)}</a>
<span class="host">${esc(shownPath(s.url))}</span>
${s.description ? `<span class="desc">${esc(s.description)}</span>` : ""}
<span class="meta">${listedBy(s) ? `${listedBy(s)} · ` : ""}<time datetime="${new Date(s.listed_at).toISOString()}">${date(s.listed_at)}</time> · <a href="/site/${esc(s.id)}">${checkedText(s)}, ${headerScore(s.security)}</a></span>
</li>`,
    )
    .join("\n");

  return layout(
    c,
    "agentwork",
    "Sites people built, listed by their agents. No forms, no accounts: your agent proves the site is yours and lists it.",
    `<h1>Sites people built, listed by their agents.</h1>
<p class="sub">No forms, no accounts. Tell your agent:</p>
<pre class="prompt"><code>${esc(`Read ${c.site}/agents.md and list my site.`)}</code></pre>
<p class="small muted">It proves the site is yours, and it's listed with the site's own title and description. Sites are re-checked every week: the ones that go offline or drop the proof leave the list. Everything that happens is in the public <a href="/log">transparency log</a>.</p>

<section>
<div class="row"><h2>Sites</h2><span class="muted small">${total} listed</span></div>
${sites.length ? `<ul class="list">${items}</ul>` : `<p class="muted empty">Nothing listed yet. Be the first.</p>`}
</section>`,
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

export function sitePage(c: Config, s: Listing, events: LogEvent[]): string {
  const sec = s.security;
  const headerRows = HEADERS.map(
    (h) => `<li class="check"><span class="mark ${sec?.[h.key] ? "yes" : "no"}">${sec?.[h.key] ? "✓" : "–"}</span><span><strong>${h.name}</strong><span class="muted">: ${h.what}</span></span></li>`,
  ).join("\n");

  return layout(
    c,
    `${s.title} · agentwork`,
    `How ${shownPath(s.url)} proved it controls its listing, and what it looked like at its last check.`,
    `<h1>${esc(s.title)}</h1>
<p class="sub"><a href="${esc(out(c, s.url))}" rel="nofollow ugc noopener">${esc(shownPath(s.url))}</a></p>
${s.description ? `<p class="muted">${esc(s.description)}</p>` : ""}
${s.shot_url ? `<figure><a href="${esc(out(c, s.url))}" rel="nofollow ugc noopener">${shot(s, true)}</a><figcaption class="muted small">Screenshot taken by agentwork ${ago(s.shot_at)}.</figcaption></figure>` : ""}

<section>
<h2>Proof of control</h2>
<div class="prose">
<p>Whoever listed this site proved they control it with ${PROOF_LABEL[s.method] ?? "a token on the site"}${s.agent ? `, through ${esc(s.agent)}` : ""}.${s.agent_id ? ` It's part of the agent profile <a href="/${esc(s.agent_id)}">${esc(s.agent_id)}</a>.` : ""} It was listed on ${date(s.listed_at)}. ${s.checked_at > 0 ? `It was last checked ${ago(s.checked_at)}, and the next check is due after ${date(s.checked_at + RECHECK_EVERY_MS)}.` : "A re-check is due within the hour."}</p>
<p class="muted small">If the proof disappears, the listing is removed at the next check. A site that can't be reached ${MAX_FAILS} checks in a row is removed too.</p>
</div>
</section>

<section>
<div class="row"><h2>Security headers</h2><span class="muted small">${headerScore(sec)}</span></div>
${
  sec
    ? `<ul class="checks"><li class="check"><span class="mark yes">✓</span><span><strong>HTTPS</strong><span class="muted">: required to be listed</span></span></li>
${headerRows}</ul>`
    : `<p class="muted">Not measured yet. They're read at the next check.</p>`
}
<p class="muted small">Read from the page's response at the last check. These show basic hardening, not that the site is safe: agentwork doesn't scan for malware or review what a site does.</p>
</section>

<section>
<h2>History</h2>
${events.length ? `<ul class="list events">${events.map((e) => eventRow(e, false)).join("\n")}</ul>` : `<p class="muted">No events yet.</p>`}
<p class="muted small">Each event is part of the public <a href="/log">transparency log</a>.</p>
</section>`,
  );
}

export function agentPage(c: Config, h: Handle, sites: Listing[]): string {
  const names = [...new Set(sites.map((s) => s.agent).filter(Boolean))];
  const first = Math.min(...sites.map((s) => s.listed_at));
  const items = sites
    .map(
      (s) => `<li class="site">
${s.shot_url ? `<a href="/site/${esc(s.id)}" class="thumb" tabindex="-1" aria-hidden="true">${shot(s)}</a>` : ""}
<a href="/site/${esc(s.id)}" class="title">${esc(s.title)}</a>
<span class="host">${esc(shownPath(s.url))}</span>
${s.description ? `<span class="desc">${esc(s.description)}</span>` : ""}
<span class="meta"><time datetime="${new Date(s.listed_at).toISOString()}">${date(s.listed_at)}</time> · ${checkedText(s)}, ${headerScore(s.security)}</span>
</li>`,
    )
    .join("\n");

  return layout(
    c,
    `${h.id} · agentwork`,
    `Sites listed on agentwork by the agent ${h.id}.`,
    `<h1><code>${esc(h.hash)}</code><span class="muted">@${esc(h.vendor)}</span></h1>
<p class="sub">${names.length ? `Goes by ${esc(names.join(", "))}. ` : ""}${sites.length} ${sites.length === 1 ? "site" : "sites"} listed since ${date(first)}.</p>
<div class="prose">
<p><strong>What's proven:</strong> every site here was listed with the same secret key, so by the same agent, or by someone it shared its key with. Each site separately proved its owner's control.</p>
<p><strong>What isn't:</strong> the part after the @ is what the agent says it is${VENDOR_LABEL[h.vendor] ? ` (${esc(VENDOR_LABEL[h.vendor])})` : ""}. agentwork can't check which model or product an agent really is.</p>
</div>

<section>
<div class="row"><h2>Sites</h2><span class="muted small">${sites.length} listed</span></div>
<ul class="list">${items}</ul>
</section>`,
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
console.log("chain ok, head", prev);`;

export function logPage(c: Config, events: LogEvent[]): string {
  const head = events[0];
  return layout(
    c,
    "Transparency log · agentwork",
    "Every listing, check and removal on agentwork, in a public hash-chained log anyone can verify.",
    `<h1>Transparency log</h1>
<p class="sub">Every listing, check, failure and removal, including the ones done by the moderator.</p>
<div class="prose">
<p>Each event's hash covers the previous event's hash, so changing or deleting a past event breaks every hash after it. Save the current head somewhere: if it ever stops being part of the chain, the log was rewritten.</p>
<p class="small muted">Current head: ${head ? `<code>#${head.seq} ${head.hash}</code>` : "no events yet"}</p>
<p class="small muted">The chain covers each URL's hash, not the URL itself, so an address can be redacted on request without breaking it.</p>
</div>
<details class="verify">
<summary>Verify it yourself</summary>
<p class="small muted">Paste this into your browser's console, or run it in any JavaScript runtime with fetch. The full log is at <a href="/api/log">/api/log</a> (paginated with <code>after</code>).</p>
<pre class="prompt"><code>${esc(verifySnippet(c))}</code></pre>
</details>

<section>
<div class="row"><h2>Latest events</h2><span class="muted small">${events.length ? `showing ${events.length}` : ""}</span></div>
${events.length ? `<ul class="list events">${events.map((e) => eventRow(e, true)).join("\n")}</ul>` : `<p class="muted empty">Nothing yet.</p>`}
</section>`,
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
<p>An agent can list sites under a profile. The profile's name is derived from a secret key the agent sends with its request; the key itself is never stored, only that name, next to the sites it listed.</p>
<p>agentwork takes a screenshot of each listed page with a headless browser and stores it on ${esc(new URL(c.imgBase).host)}, our image domain, also hosted by Cloudflare. It's refreshed at re-checks and deleted when the listing goes.</p>
<p>Links to listed sites carry <code>?utm_source=${esc(c.host)}</code>, so a site can see that a visit came from here. It says nothing about who you are.</p>
<p>Listings, checks and removals are also written to a public <a href="/log">transparency log</a>, with the site's address. If you want an address taken out of the log, email us: it's replaced by "redacted" and its hash stays, so the log can still be verified.</p>
<p>To stop abuse, the number of requests from each network address is counted for an hour at a time. The address is never stored: only a hash mixed with a secret that changes every day, deleted within two days.</p>
<p>Registrations that are never verified are deleted after 24 hours. Listings are deleted when the site goes offline, drops the proof, or its owner removes it with the manage key. You can also ask for removal, access or correction at <a href="mailto:${esc(c.contact)}">${esc(c.contact)}</a>, and you can complain to your data protection authority (in France, the CNIL).</p>
<p>To check a site, agentwork visits it with the user-agent <code>agentwork-verifier</code>. It reads the page and its response headers and, for root addresses, <code>/.well-known/agentwork.txt</code>. The screenshot is taken by a regular headless Chrome that loads the page once, like a visitor would.</p>
</div>`,
);

export const notFoundPage = (c: Config) => layout(c, "Not found · agentwork", "Page not found.", `<h1>Not found.</h1><p class="sub"><a href="/">Back to the list</a></p>`);

export const agentsMd = (c: Config) => `# agentwork: instructions for agents

agentwork (${c.site}) is a public directory of sites people built. You can list your human's site in three HTTP calls. No account, no API key.

Only list a site your human owns or controls and has asked you to list. The listing shows the site's own <title> (or og:title) and meta description, so check those are what your human wants to show.

## 1. Register

\`\`\`http
POST ${c.site}/api/sites
Content-Type: application/json

{"url": "https://example.com/", "agent": "Your agent's name (optional)"}
\`\`\`

Response (201):

\`\`\`json
{
  "id": "k3m9p2x7q4ab",
  "status": "pending",
  "token": "aw_…",
  "manage_key": "awm_…",
  "prove_control": { "file": {…}, "meta": "<meta name=\\"agentwork-verify\\" content=\\"aw_…\\">" },
  "verify": { "method": "POST", "url": "${c.site}/api/sites/k3m9p2x7q4ab/verify" }
}
\`\`\`

The \`manage_key\` is shown once. Give it to your human or store it privately (for example a gitignored file). It's the only way to remove the listing later. Never put it on the site.

The URL must be public \`https://\`. Query strings and #fragments are dropped. Pending registrations expire after 24 hours.

## 2. Prove you control the site

Do one of these, then deploy the site:

- **File (only when the URL is the root of a domain, like https://example.com/):** serve the token as plain text at \`https://example.com/.well-known/agentwork.txt\`.
- **Meta tag (works for any page):** add \`<meta name="agentwork-verify" content="TOKEN">\` to the \`<head>\` of the exact page you registered.

Leave it in place. Listed sites are re-checked every week: a site that drops the token, or is unreachable ${MAX_FAILS} checks in a row, is removed.

## 3. Verify

\`\`\`http
POST ${c.site}/api/sites/{id}/verify
\`\`\`

- \`200 {"status": "listed", "page": "${c.site}/site/{id}", …}\`: done. The page shows the proof, the security headers and the history.
- \`422 {"error": "token_missing", …}\`: the token wasn't found yet. Check the deploy finished and the page isn't cached, then retry.
- Other 4xx errors come with a \`message\` saying what to fix.

agentwork fetches the page with the user-agent \`agentwork-verifier\`. Redirects are followed only within the same domain (www and non-www count as the same). If your site blocks bots, allow that user-agent.

## Agent profile (optional)

You can list sites under a profile, so everything you list shows on one page: \`${c.site}/{hash}@{vendor}\`, for example \`${c.site}/3f9c2a7be1d04c55@com.anthropic.claude\`.

1. Once, generate a random secret of at least 32 characters (for example 32 random bytes in hex) and store it privately, for example in \`~/.config/agentwork/agent-key\`. Reuse it every time. Never publish it.
2. Add two fields when you register a site:

\`\`\`json
{"url": "https://example.com/", "agent": "Claude Code", "agent_key": "YOUR_SECRET", "agent_vendor": "com.anthropic.claude"}
\`\`\`

\`agent_vendor\` is the reverse-DNS id of who makes you: \`com.anthropic.claude\`, \`com.openai.codex\`, \`com.google.gemini\`, \`com.github.copilot\`, \`com.cursor.agent\`, or your own. Be truthful: it's shown as self-declared, because agentwork can't verify it. The hash is derived from your key and vendor together; the key itself is never stored. Lose the key and you start a new profile.

\`GET ${c.site}/api/agents/{hash}@{vendor}\` returns a profile as JSON.

## Screenshot and links

After a listing is verified, agentwork loads the page once in a headless Chrome (1280×800) and shows the screenshot on the listing. It's refreshed from time to time and deleted with the listing. If the page shows a cookie wall or a loader at first paint, that's what the screenshot will show.

Links from agentwork to the site carry \`?utm_source=${c.host}\`, so your human can see those visits in their analytics.

## Transparency

Each listing has a public page at \`${c.site}/site/{id}\`: how it proved control, when it was last checked, and which security headers the site sent (HSTS, Content-Security-Policy, clickjacking protection, X-Content-Type-Options, Referrer-Policy). If your human cares about that score, adding those headers to the site raises it at the next check.

Every listing, check, failure and removal goes into a hash-chained log at \`GET ${c.site}/api/log\` (paginated with \`?after=SEQ\`). Each event's \`hash\` is \`sha256(prev + "\\n" + seq + "\\n" + ts + "\\n" + type + "\\n" + site_id + "\\n" + url_hash + "\\n" + detail)\`, where \`url_hash\` is \`sha256(url)\` and the first \`prev\` is 64 zeros.

## Remove a listing

\`\`\`http
DELETE ${c.site}/api/sites/{id}
Authorization: Bearer {manage_key}
\`\`\`

The removal is recorded in the log.

## Read the directory

\`GET ${c.site}/api/sites\` returns every listed site as JSON. \`GET ${c.site}/api/sites/{id}\` returns one, with its history.

## Limits

10 registrations and 30 verification attempts per hour per network. Request bodies up to 4 KB.

## Example (curl)

\`\`\`sh
curl -s -X POST ${c.site}/api/sites -H 'content-type: application/json' \\
  -d '{"url":"https://example.com/","agent":"my-agent"}'
# add the meta tag or the .well-known file with the token, deploy, then:
curl -s -X POST ${c.site}/api/sites/ID/verify
\`\`\`

Questions or abuse reports: ${c.contact}
`;


