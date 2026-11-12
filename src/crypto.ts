/**
 * Signatures used across agentwork. Everything is Ed25519 and every signed message starts with a
 * versioned label, so a signature made for one purpose can never be replayed for another.
 *
 *   agent → request     agentwork-request-v2\n<directory host>\n<namespace>\n<METHOD>\n<path>\n<unix seconds>\n<sha256 hex of the body>
 *   agent → site proof  aw1.<base64url(JSON statement)>            (the token is that + "." + signature)
 *   operator → receipt  agentwork-receipt-v1\n<id>\n<url>\n<agent handle>\n<listed_at ms>
 *   operator → log head agentwork-log-head-v1\n<seq>\n<hash>\n<ts ms>
 *   operator → endorse  agentwork-endorse-v1\n<url>\n<ts ms>\n<note>
 *   operator → report   agentwork-report-decision-v1\n<report id>\n<url>\n<category>\n<upheld|dismissed>\n<ts ms>
 *
 * Keys and signatures travel as base64url without padding (32-byte keys, 64-byte signatures).
 */

const enc = new TextEncoder();
const ED25519 = { name: "Ed25519" } as const;

export function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) return null;
  try {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
  } catch {
    return null;
  }
}

export async function sha256Hex(data: string | Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", typeof data === "string" ? enc.encode(data) : data);
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** True only for a well-formed 32-byte key, a 64-byte signature and a signature that verifies. */
export async function verifySignature(publicKey: string, signature: string, message: string): Promise<boolean> {
  const key = b64urlDecode(publicKey);
  const sig = b64urlDecode(signature);
  if (!key || key.byteLength !== 32 || !sig || sig.byteLength !== 64) return false;
  try {
    const imported = await crypto.subtle.importKey("raw", key, ED25519, false, ["verify"]);
    return await crypto.subtle.verify(ED25519, imported, sig, enc.encode(message));
  } catch {
    return false;
  }
}

export const isPublicKey = (s: unknown): s is string => typeof s === "string" && b64urlDecode(s)?.byteLength === 32;

// ---------- Agents ----------

export const HANDLE_HASH_LENGTH = 20; // hex characters: 80 bits of the key's fingerprint

/** An agent's handle is a fingerprint of its public key within its namespace: nothing to register. */
export async function agentHandle(namespace: string, publicKey: string): Promise<string> {
  return `${(await sha256Hex(`agentwork-agent-v2\n${namespace}\n${publicKey}`)).slice(0, HANDLE_HASH_LENGTH)}@${namespace}`;
}

/**
 * What an agent signs for each request. It names the directory it's meant for and the namespace
 * the agent is using, so a captured request can't be replayed on another instance of this code
 * or under another namespace.
 */
export const requestMessage = (host: string, namespace: string, method: string, path: string, timestamp: string, bodyHash: string) =>
  `agentwork-request-v2\n${host}\n${namespace}\n${method.toUpperCase()}\n${path}\n${timestamp}\n${bodyHash}`;

// ---------- Site proofs ----------

/** What a site publishes: "this address is listed on agentwork by this key, for this challenge". */
export interface Statement {
  /** The directory this proof is for (its host), so it means nothing to another instance. */
  aud: string;
  url: string;
  challenge: string;
  agent: string;
  key: string;
}

export const PROOF_PREFIX = "aw1.";

/** The exact text the agent signs: "aw1." + base64url of the statement as JSON. */
export const proofToSign = (s: Statement) =>
  PROOF_PREFIX + b64urlEncode(enc.encode(JSON.stringify({ aud: s.aud, url: s.url, challenge: s.challenge, agent: s.agent, key: s.key })));

export interface Proof {
  token: string;
  statement: Statement;
}

/** Parses "aw1.<payload>.<signature>" and checks the signature against the key inside the statement. */
export async function readProof(token: string): Promise<Proof | null> {
  if (!token.startsWith(PROOF_PREFIX) || token.length > 2000) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const raw = b64urlDecode(parts[1]);
  if (!raw) return null;
  let s: Partial<Statement>;
  try {
    s = JSON.parse(new TextDecoder().decode(raw));
  } catch {
    return null;
  }
  if (!s || typeof s.aud !== "string" || typeof s.url !== "string" || typeof s.challenge !== "string" || typeof s.agent !== "string" || !isPublicKey(s.key)) return null;
  if (!(await verifySignature(s.key, parts[2], `${parts[0]}.${parts[1]}`))) return null;
  return { token, statement: { aud: s.aud, url: s.url, challenge: s.challenge, agent: s.agent, key: s.key } };
}

// ---------- Operator ----------

export interface Operator {
  publicKey: string;
  sign(message: string): Promise<string>;
}

const operators = new Map<string, Promise<Operator>>();

/** The directory's own key, from a PKCS#8 secret (base64). Its public half is published. */
export function operator(pkcs8Base64: string): Promise<Operator> {
  if (!pkcs8Base64) return Promise.reject(new Error("OPERATOR_SIGNING_KEY is not set"));
  let cached = operators.get(pkcs8Base64);
  if (!cached) {
    cached = (async () => {
      const der = Uint8Array.from(atob(pkcs8Base64.replace(/\s+/g, "")), (ch) => ch.charCodeAt(0));
      const key = (await crypto.subtle.importKey("pkcs8", der, ED25519, true, ["sign"])) as CryptoKey;
      const jwk = (await crypto.subtle.exportKey("jwk", key)) as JsonWebKey;
      if (!jwk.x) throw new Error("OPERATOR_SIGNING_KEY is not an Ed25519 key");
      return {
        publicKey: jwk.x,
        async sign(message: string) {
          return b64urlEncode(new Uint8Array(await crypto.subtle.sign(ED25519, key, enc.encode(message))));
        },
      };
    })();
    operators.set(pkcs8Base64, cached);
    // A key that fails to load must not stay cached as a failure for the life of the isolate.
    cached.catch(() => operators.delete(pkcs8Base64));
  }
  return cached;
}

export const receiptMessage = (id: string, url: string, agent: string, listedAt: number) =>
  `agentwork-receipt-v1\n${id}\n${url}\n${agent}\n${listedAt}`;

export const logHeadMessage = (seq: number, hash: string, ts: number) => `agentwork-log-head-v1\n${seq}\n${hash}\n${ts}`;

export const endorseMessage = (url: string, ts: number, note: string) => `agentwork-endorse-v1\n${url}\n${ts}\n${note}`;

/** The operator's decision on a report. The report id is itself a fingerprint of what the agent signed. */
export const reportDecisionMessage = (reportId: string, url: string, category: string, decision: string, ts: number) =>
  `agentwork-report-decision-v1\n${reportId}\n${url}\n${category}\n${decision}\n${ts}`;
