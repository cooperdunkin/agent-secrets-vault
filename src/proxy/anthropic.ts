/**
 * proxy/anthropic.ts
 *
 * Anthropic Messages API proxy.
 * ASV retrieves the stored API key and injects it — the agent never sees it.
 *
 * Supported:
 *   service: "anthropic"
 *   action:  "messages.create"
 *
 * Security invariants:
 *   - The API key is retrieved from the keystore and used only in the
 *     x-api-key header; it is never returned to the caller.
 *   - Error messages never include the API key.
 *   - Request body is built from validated + sanitized params only.
 */

import { Keystore } from "../vault/keystore.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AnthropicProxyParams {
  model: string;
  messages: Array<{ role: string; content: string }>;
  max_tokens: number;
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
 * Defense-in-depth: the agent should never pass a key, but we sanitize anyway.
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
// Validation
// ---------------------------------------------------------------------------

/** Validate Anthropic messages params. Throws with a descriptive message on failure. */
export function validateAnthropicParams(params: unknown): AnthropicProxyParams {
  if (!params || typeof params !== "object" || Array.isArray(params)) {
    throw new Error("Params must be a non-null object.");
  }
  const p = params as Record<string, unknown>;

  if (!p.model || typeof p.model !== "string" || p.model.trim().length === 0) {
    throw new Error('Required param "model" must be a non-empty string.');
  }
  if (!Array.isArray(p.messages) || p.messages.length === 0) {
    throw new Error('Required param "messages" must be a non-empty array.');
  }
  if (
    p.max_tokens === undefined ||
    p.max_tokens === null ||
    typeof p.max_tokens !== "number" ||
    !Number.isInteger(p.max_tokens) ||
    p.max_tokens <= 0
  ) {
    throw new Error('Required param "max_tokens" must be a positive integer.');
  }

  return p as AnthropicProxyParams;
}

// ---------------------------------------------------------------------------
// Proxy function
// ---------------------------------------------------------------------------

/**
 * Calls the Anthropic Messages API on behalf of the agent.
 * Injects the stored API key — never returns it.
 */
export async function proxyAnthropicMessages(
  params: unknown,
  keystore: Keystore
): Promise<ProxyResponse> {
  // 1. Validate params
  let validated: AnthropicProxyParams;
  try {
    validated = validateAnthropicParams(params);
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }

  // 2. Retrieve API key from keystore
  let apiKey: string;
  try {
    apiKey = keystore.getSecret("anthropic");
  } catch (err) {
    return {
      ok: false,
      error: `Could not retrieve Anthropic secret from keystore: ${(err as Error).message}`,
    };
  }

  // 3. Build sanitized request body (never include the key)
  const { model, messages, max_tokens, ...rest } = validated;
  const sanitizedRest = sanitizeParams(rest as Record<string, unknown>);
  const body = { model, messages, max_tokens, ...sanitizedRest };

  // 4. Call Anthropic Messages API
  let response: Response;
  try {
    response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify(body),
    });
  } catch (err) {
    const msg = (err as Error).message.replace(apiKey, "[REDACTED]");
    return { ok: false, error: `Network error calling Anthropic API: ${msg}` };
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
      error: `Anthropic API returned non-JSON response (HTTP ${response.status}).`,
      status: response.status,
    };
  }

  if (!response.ok) {
    const errMsg =
      (responseData as { error?: { message?: string } })?.error?.message ??
      `HTTP ${response.status}`;
    return {
      ok: false,
      error: `Anthropic API error: ${errMsg}`,
      status: response.status,
    };
  }

  return { ok: true, data: responseData };
}
