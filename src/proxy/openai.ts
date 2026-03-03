/**
 * proxy/openai.ts
 *
 * OpenAI Responses API proxy.
 * ASV retrieves the stored API key and injects it — the agent never sees it.
 *
 * Supported:
 *   service: "openai"
 *   action:  "responses.create"
 *
 * Security invariants:
 *   - The API key is retrieved from the keystore and used only in the
 *     Authorization header; it is never returned to the caller.
 *   - Error messages never include the API key.
 *   - Request body is built from validated params only.
 */

import { Keystore } from "../vault/keystore.js";
import { proxyAnthropicMessages } from "./anthropic.js";
import { proxyGitHubAction } from "./github.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface OpenAIProxyParams {
  model: string;
  input: string | object;
  [key: string]: unknown;
}

export interface ProxyResult {
  ok: true;
  data: unknown;
}

export interface ProxyError {
  ok: false;
  error: string;
  status?: number;
}

export type ProxyResponse = ProxyResult | ProxyError;

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

function validateParams(params: unknown): OpenAIProxyParams {
  if (!params || typeof params !== "object" || Array.isArray(params)) {
    throw new Error('Params must be a non-null object.');
  }
  const p = params as Record<string, unknown>;

  if (!p.model || typeof p.model !== "string" || p.model.trim().length === 0) {
    throw new Error('Required param "model" must be a non-empty string.');
  }
  if (p.input === undefined || p.input === null) {
    throw new Error('Required param "input" is missing.');
  }
  if (typeof p.input !== "string" && typeof p.input !== "object") {
    throw new Error('"input" must be a string or object.');
  }

  return p as OpenAIProxyParams;
}

// ---------------------------------------------------------------------------
// Proxy function
// ---------------------------------------------------------------------------

/**
 * Calls the OpenAI Responses API on behalf of the agent.
 * Injects the stored API key — never returns it.
 */
export async function proxyOpenAIResponses(
  params: unknown,
  keystore: Keystore
): Promise<ProxyResponse> {
  // 1. Validate params
  let validated: OpenAIProxyParams;
  try {
    validated = validateParams(params);
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }

  // 2. Retrieve API key from keystore
  let apiKey: string;
  try {
    apiKey = keystore.getSecret("openai");
  } catch (err) {
    return {
      ok: false,
      error: `Could not retrieve OpenAI secret from keystore: ${(err as Error).message}`,
    };
  }

  // 3. Build request body (only known/validated fields — never include the key)
  const { model, input, ...rest } = validated;

  // Strip any fields that look like they might be API credentials
  // (defense-in-depth: agent should never pass a key, but we sanitize anyway)
  const sanitizedRest = Object.fromEntries(
    Object.entries(rest).filter(([k]) => {
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

  const body = { model, input, ...sanitizedRest };

  // 4. Call OpenAI
  let response: Response;
  try {
    response = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
        "User-Agent": "agent-secrets-vault/0.1.0",
      },
      body: JSON.stringify(body),
    });
  } catch (err) {
    // Network error — scrub any potential secret from the message
    const msg = (err as Error).message.replace(apiKey, "[REDACTED]");
    return { ok: false, error: `Network error calling OpenAI API: ${msg}` };
  } finally {
    // Overwrite local reference (belt-and-suspenders for GC)
    apiKey = "";
  }

  // 5. Parse response
  let responseData: unknown;
  try {
    responseData = await response.json();
  } catch {
    return {
      ok: false,
      error: `OpenAI API returned non-JSON response (HTTP ${response.status}).`,
      status: response.status,
    };
  }

  if (!response.ok) {
    // Extract error message without leaking the key
    const errMsg =
      (responseData as { error?: { message?: string } })?.error?.message ??
      `HTTP ${response.status}`;
    return {
      ok: false,
      error: `OpenAI API error: ${errMsg}`,
      status: response.status,
    };
  }

  return { ok: true, data: responseData };
}

// ---------------------------------------------------------------------------
// Dispatch (for extensibility — other services can be added here)
// ---------------------------------------------------------------------------

export async function proxyRequest(
  service: string,
  action: string,
  params: unknown,
  keystore: Keystore
): Promise<ProxyResponse> {
  if (service === "openai" && action === "responses.create") {
    return proxyOpenAIResponses(params, keystore);
  }

  if (service === "anthropic" && action === "messages.create") {
    return proxyAnthropicMessages(params, keystore);
  }

  if (
    service === "github" &&
    (action === "repos.get" ||
      action === "issues.create" ||
      action === "pulls.create" ||
      action === "contents.read")
  ) {
    return proxyGitHubAction(action, params, keystore);
  }

  return {
    ok: false,
    error: `No proxy implementation for service="${service}" action="${action}".`,
  };
}
