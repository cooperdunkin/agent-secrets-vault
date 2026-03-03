/**
 * keychain/keychain.ts
 *
 * OS keychain integration via keytar.
 * Supports macOS Keychain, Linux Secret Service (libsecret),
 * and Windows Credential Manager.
 *
 * keytar is loaded lazily via require() so that a missing native build
 * (e.g. libsecret not installed on Linux) produces a clear error at call
 * time rather than crashing the entire process on import.
 */

import type keytarTypes from "keytar";

// Service name and account used to identify ASV's master password in the keychain
const KEYCHAIN_SERVICE = "agent-secrets-vault";
const KEYCHAIN_ACCOUNT = "master-password";

type Keytar = typeof keytarTypes;

function loadKeytar(): Keytar {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    return require("keytar") as Keytar;
  } catch (err) {
    throw new Error(
      `OS keychain unavailable: ${(err as Error).message}. ` +
        `Install libsecret-1-dev (Linux) or use ASV_MASTER_PASSWORD env var instead.`
    );
  }
}

/** Store master password in OS keychain. */
export async function keychainSet(password: string): Promise<void> {
  const kt = loadKeytar();
  await kt.setPassword(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, password);
}

/** Retrieve master password from OS keychain. Returns null if not found. */
export async function keychainGet(): Promise<string | null> {
  const kt = loadKeytar();
  return kt.getPassword(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);
}

/** Delete master password from OS keychain. Returns true if it existed. */
export async function keychainDelete(): Promise<boolean> {
  const kt = loadKeytar();
  return kt.deletePassword(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);
}

/** Check if a master password is stored in OS keychain. */
export async function keychainExists(): Promise<boolean> {
  const kt = loadKeytar();
  const pw = await kt.getPassword(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);
  return pw !== null;
}
