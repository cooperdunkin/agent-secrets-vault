/**
 * proxy/github.ts
 *
 * GitHub API proxy.
 * ASV retrieves the stored Personal Access Token and injects it — the agent never sees it.
 *
 * Supported actions:
 *   service: "github"
 *   action:  "repos.get" | "issues.create" | "pulls.create" | "contents.read"
 *
 * Security invariants:
 *   - The token is retrieved from the keystore and used only in the
 *     Authorization header; it is never returned to the caller.
 *   - Error messages never include the token.
 *   - Request body is built from validated + sanitized params only.
 */

import { Keystore } from "../vault/keystore.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ReposGetParams {
  owner: string;
  repo: string;
  [key: string]: unknown;
}

export interface IssueCreateParams {
  owner: string;
  repo: string;
  title: string;
  [key: string]: unknown;
}

export interface PullsCreateParams {
  owner: string;
  repo: string;
  title: string;
  head: string;
  base: string;
  [key: string]: unknown;
}

export interface ContentsReadParams {
  owner: string;
  repo: string;
  path: string;
  [key: string]: unknown;
}

interface ProxyResult {
  ok: true;
  data: unknown;
}

interface ProxyError {
  ok: false;
  error: string;
  status?: number;
}

type ProxyResponse = ProxyResult | ProxyError;

// ---------------------------------------------------------------------------
// Sanitization
// ---------------------------------------------------------------------------

/**
 * Strip any param key that looks like an API credential.
 * Defense-in-depth: the agent should never pass a token, but we sanitize anyway.
 */
export function sanitizeParams(
  params: Record<string, unknown>
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(params).filter(([k]) => {
      const lower = k.toLowerCase();
      return (
        !lower.includes("key") &&
        !lower.includes("secret") &&
        !lower.includes("token") &&
        !lower.includes("password") &&
        !lower.includes("auth")
      );
    })
  );
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

function requireString(params: Record<string, unknown>, key: string): string {
  const val = params[key];
  if (!val || typeof val !== "string" || val.trim().length === 0) {
    throw new Error(`Required param "${key}" must be a non-empty string.`);
  }
  return val;
}

function requireBaseObject(params: unknown): Record<string, unknown> {
  if (!params || typeof params !== "object" || Array.isArray(params)) {
    throw new Error("Params must be a non-null object.");
  }
  return params as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Per-action validation
// ---------------------------------------------------------------------------

export function validateReposGetParams(params: unknown): ReposGetParams {
  const p = requireBaseObject(params);
  requireString(p, "owner");
  requireString(p, "repo");
  return p as ReposGetParams;
}

export function validateIssueCreateParams(params: unknown): IssueCreateParams {
  const p = requireBaseObject(params);
  requireString(p, "owner");
  requireString(p, "repo");
  requireString(p, "title");
  return p as IssueCreateParams;
}

export function validatePullsCreateParams(params: unknown): PullsCreateParams {
  const p = requireBaseObject(params);
  requireString(p, "owner");
  requireString(p, "repo");
  requireString(p, "title");
  requireString(p, "head");
  requireString(p, "base");
  return p as PullsCreateParams;
}

export function validateContentsReadParams(params: unknown): ContentsReadParams {
  const p = requireBaseObject(params);
  requireString(p, "owner");
  requireString(p, "repo");
  requireString(p, "path");
  return p as ContentsReadParams;
}

// ---------------------------------------------------------------------------
// Shared fetch helper
// ---------------------------------------------------------------------------

const GITHUB_API_BASE = "https://api.github.com";

async function githubFetch(
  url: string,
  method: string,
  token: string,
  body?: unknown
): Promise<ProxyResponse> {
  let response: Response;
  try {
    response = await fetch(url, {
      method,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "agent-secrets-vault/0.1.0",
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (err) {
    // Scrub any accidental token leak from network error message
    const msg = (err as Error).message.replace(token, "[REDACTED]");
    return { ok: false, error: `Network error calling GitHub API: ${msg}` };
  }

  let responseData: unknown;
  try {
    responseData = await response.json();
  } catch {
    return {
      ok: false,
      error: `GitHub API returned non-JSON response (HTTP ${response.status}).`,
      status: response.status,
    };
  }

  if (!response.ok) {
    const errMsg =
      (responseData as { message?: string })?.message ?? `HTTP ${response.status}`;
    return { ok: false, error: `GitHub API error: ${errMsg}`, status: response.status };
  }

  return { ok: true, data: responseData };
}

// ---------------------------------------------------------------------------
// Action proxy functions
// ---------------------------------------------------------------------------

async function proxyReposGet(params: unknown, keystore: Keystore): Promise<ProxyResponse> {
  let validated: ReposGetParams;
  try {
    validated = validateReposGetParams(params);
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }

  let token: string;
  try {
    token = keystore.getSecret("github");
  } catch (err) {
    return { ok: false, error: `Could not retrieve GitHub secret from keystore: ${(err as Error).message}` };
  }

  const { owner, repo } = validated;
  const url = `${GITHUB_API_BASE}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
  const result = await githubFetch(url, "GET", token);
  token = "";
  return result;
}

async function proxyIssuesCreate(params: unknown, keystore: Keystore): Promise<ProxyResponse> {
  let validated: IssueCreateParams;
  try {
    validated = validateIssueCreateParams(params);
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }

  let token: string;
  try {
    token = keystore.getSecret("github");
  } catch (err) {
    return { ok: false, error: `Could not retrieve GitHub secret from keystore: ${(err as Error).message}` };
  }

  const { owner, repo, title, ...rest } = validated;
  const body = { title, ...sanitizeParams(rest as Record<string, unknown>) };
  const url = `${GITHUB_API_BASE}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues`;
  const result = await githubFetch(url, "POST", token, body);
  token = "";
  return result;
}

async function proxyPullsCreate(params: unknown, keystore: Keystore): Promise<ProxyResponse> {
  let validated: PullsCreateParams;
  try {
    validated = validatePullsCreateParams(params);
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }

  let token: string;
  try {
    token = keystore.getSecret("github");
  } catch (err) {
    return { ok: false, error: `Could not retrieve GitHub secret from keystore: ${(err as Error).message}` };
  }

  const { owner, repo, title, head, base, ...rest } = validated;
  const body = { title, head, base, ...sanitizeParams(rest as Record<string, unknown>) };
  const url = `${GITHUB_API_BASE}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls`;
  const result = await githubFetch(url, "POST", token, body);
  token = "";
  return result;
}

async function proxyContentsRead(params: unknown, keystore: Keystore): Promise<ProxyResponse> {
  let validated: ContentsReadParams;
  try {
    validated = validateContentsReadParams(params);
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }

  let token: string;
  try {
    token = keystore.getSecret("github");
  } catch (err) {
    return { ok: false, error: `Could not retrieve GitHub secret from keystore: ${(err as Error).message}` };
  }

  const { owner, repo, path } = validated;
  // path may contain slashes (file path) — do not encode the whole thing
  const url = `${GITHUB_API_BASE}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${path}`;
  const result = await githubFetch(url, "GET", token);
  token = "";
  return result;
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

export async function proxyGitHubAction(
  action: string,
  params: unknown,
  keystore: Keystore
): Promise<ProxyResponse> {
  switch (action) {
    case "repos.get":
      return proxyReposGet(params, keystore);
    case "issues.create":
      return proxyIssuesCreate(params, keystore);
    case "pulls.create":
      return proxyPullsCreate(params, keystore);
    case "contents.read":
      return proxyContentsRead(params, keystore);
    default:
      return { ok: false, error: `Unsupported GitHub action: "${action}".` };
  }
}
