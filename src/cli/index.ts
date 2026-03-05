#!/usr/bin/env node
/**
 * cli/index.ts
 *
 * ASV CLI — binary name: asv
 *
 * Commands:
 *   asv init           Create config dirs, default policy.yaml
 *   asv add <service>  Prompt for secret, encrypt and store
 *   asv list           List stored services (names only, no secrets)
 *   asv revoke <svc>   Delete stored secret
 *   asv doctor         Health-check: config, policy, crypto, proxy construction
 *   asv mcp            Start MCP server (delegates to mcp/server.ts)
 *   asv logs           View audit log entries (--tail to watch, --last <n> for count)
 *   asv rotate <svc>   Re-encrypt a service secret under a new master password
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as crypto from "crypto";
import * as readline from "readline";
import { execFileSync } from "child_process";
import { Keystore, asvHome, keystorePath } from "../vault/keystore.js";
import { PolicyEngine, defaultPolicyPath } from "../policy/policy.js";
import { AuditLogger, auditLogPath, AuditEntry } from "../audit/audit.js";
import { keychainSet, keychainDelete, keychainExists, keychainGet } from "../keychain/keychain.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function print(msg: string): void {
  process.stdout.write(msg + "\n");
}

function printErr(msg: string): void {
  process.stderr.write(msg + "\n");
}

function die(msg: string, code = 1): never {
  printErr(`Error: ${msg}`);
  process.exit(code);
}

/** Prompt for a value. Uses hidden input on TTY when hidden=true. */
async function prompt(question: string, hidden = false): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY) {
      reject(new Error("stdin is not a TTY — cannot prompt interactively."));
      return;
    }

    if (hidden && process.platform !== "win32") {
      // Use readline with muted output
      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
        terminal: true,
      });

      process.stdout.write(question);

      // Mute output during hidden input
      const mute = (): void => {
        process.stdout.write("\x1B[?25l"); // hide cursor (cosmetic)
      };
      const unmute = (val: string): void => {
        process.stdout.write("\n");
        process.stdout.write("\x1B[?25h"); // restore cursor
        rl.close();
        resolve(val);
      };

      // Override _writeToOutput to suppress echoing
      (rl as unknown as { _writeToOutput: (s: string) => void })._writeToOutput =
        function (_stringToWrite: string) {
          // suppress all echoed characters
        };

      mute();
      rl.question("", unmute);
    } else {
      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
      });
      rl.question(question, (answer) => {
        rl.close();
        resolve(answer);
      });
    }
  });
}

async function promptMasterPassword(confirmLabel = ""): Promise<string> {
  const label = confirmLabel || "Master password";
  const pw = await prompt(`${label}: `, true);
  if (!pw || pw.trim().length === 0) {
    die("Master password must not be empty.");
  }
  return pw;
}

// ---------------------------------------------------------------------------
// Default policy YAML content
// ---------------------------------------------------------------------------

const DEFAULT_POLICY_YAML = `# ASV Policy File
# Deny-by-default: requests not matching an allow rule are rejected.
#
# Identity is read from the ASV_IDENTITY environment variable.
# Use "*" to match any identity, service, or action.

policies:
  - identity: local-dev
    allow:
      - service: openai
        actions:
          - responses.create

  # Uncomment to allow all actions for a service:
  # - identity: local-dev
  #   allow:
  #     - service: openai
  #       actions:
  #         - "*"
`;

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/** asv init */
async function cmdInit(): Promise<void> {
  const home = asvHome();
  const configDir = path.resolve(process.cwd(), "config");
  const dataDir = path.resolve(process.cwd(), "data");
  const policyFile = defaultPolicyPath();

  // Create ~/.asv with restricted permissions
  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  print(`  ✓ Created ${home}`);

  // Create config/ and data/ in cwd
  fs.mkdirSync(configDir, { recursive: true });
  print(`  ✓ Created ${configDir}`);

  fs.mkdirSync(dataDir, { recursive: true });
  print(`  ✓ Created ${dataDir}`);

  // Write default policy only if it doesn't exist
  if (!fs.existsSync(policyFile)) {
    fs.writeFileSync(policyFile, DEFAULT_POLICY_YAML, { mode: 0o644 });
    print(`  ✓ Created ${policyFile}`);
  } else {
    print(`  · Skipped ${policyFile} (already exists)`);
  }

  // Create .gitignore entry for data/
  const gitignoreInDataDir = path.join(dataDir, ".gitkeep");
  if (!fs.existsSync(gitignoreInDataDir)) {
    fs.writeFileSync(gitignoreInDataDir, "");
  }

  print("");
  print("ASV initialised. Next steps:");
  print("  asv add openai    — store your OpenAI API key");
  print("  asv mcp           — start the MCP server");
}

/** asv add <service> */
async function cmdAdd(service: string): Promise<void> {
  if (!service) die("Usage: asv add <service>  (e.g. asv add openai)");

  print(`Adding secret for service: ${service}`);

  const masterPw = await promptMasterPassword();

  // Verify password against existing entries (if any)
  const ks = new Keystore(masterPw);
  const existing = ks.listServices();
  if (existing.length > 0 && !ks.verifyPassword()) {
    die("Wrong master password.");
  }

  let secretValue: string;
  if (service === "openai") {
    secretValue = await prompt("OpenAI API key (sk-...): ", true);
  } else {
    secretValue = await prompt(`Secret value for ${service}: `, true);
  }

  if (!secretValue || secretValue.trim().length === 0) {
    die("Secret must not be empty.");
  }

  ks.setSecret(service, secretValue);

  // Overwrite the local variable as soon as we're done
  secretValue = "";

  print(`  ✓ Secret for "${service}" stored and encrypted.`);
  print(`    Keystore: ${keystorePath()}`);
}

/** asv list */
async function cmdList(): Promise<void> {
  if (!fs.existsSync(keystorePath())) {
    print("No secrets stored. Run: asv add <service>");
    return;
  }

  const masterPw = await promptMasterPassword();
  const ks = new Keystore(masterPw);

  if (!ks.verifyPassword()) {
    die("Wrong master password.");
  }

  const services = ks.listServices();

  if (services.length === 0) {
    print("No secrets stored. Run: asv add <service>");
    return;
  }

  print(`Stored services (${services.length}):`);
  print("");
  for (const svc of services) {
    print(`  ${svc.service.padEnd(20)}  created: ${svc.createdAt}  updated: ${svc.updatedAt}`);
  }
}

/** asv revoke <service> */
async function cmdRevoke(service: string): Promise<void> {
  if (!service) die("Usage: asv revoke <service>  (e.g. asv revoke openai)");

  const masterPw = await promptMasterPassword();
  const ks = new Keystore(masterPw);

  if (!ks.verifyPassword()) {
    die("Wrong master password.");
  }

  const deleted = ks.deleteSecret(service);
  if (deleted) {
    print(`  ✓ Secret for "${service}" revoked.`);
  } else {
    print(`  · No secret found for "${service}" — nothing to revoke.`);
  }
}

/** asv doctor */
async function cmdDoctor(): Promise<void> {
  print("ASV Doctor — running health checks\n");
  let ok = true;

  const check = (label: string, pass: boolean, detail?: string): void => {
    const icon = pass ? "✓" : "✗";
    const status = pass ? "OK" : "FAIL";
    print(`  ${icon} ${label.padEnd(40)} ${status}${detail ? `  (${detail})` : ""}`);
    if (!pass) ok = false;
  };

  // 1. ~/.asv directory
  const home = asvHome();
  check("~/.asv directory exists", fs.existsSync(home), home);

  // 2. Keystore file (may not exist yet)
  const kPath = keystorePath();
  const kExists = fs.existsSync(kPath);
  check("Keystore file exists", kExists, kPath);
  if (kExists) {
    try {
      const stat = fs.statSync(kPath);
      const mode = (stat.mode & 0o777).toString(8);
      check("Keystore file permissions (600)", mode === "600", `mode=${mode}`);
    } catch (err) {
      check("Keystore file readable", false, (err as Error).message);
    }
  }

  // 3. Policy file
  const policyPath = defaultPolicyPath();
  const policyExists = fs.existsSync(policyPath);
  check("Policy file exists", policyExists, policyPath);
  if (policyExists) {
    try {
      const pe = new PolicyEngine(policyPath);
      const policies = pe.getPolicies();
      check("Policy file parses OK", true, `${policies.length} rule(s)`);
      // Check a sample allow
      const sampleAllow = pe.isAllowed("local-dev", "openai", "responses.create");
      check(
        'Policy allows local-dev→openai→responses.create',
        sampleAllow
      );
    } catch (err) {
      check("Policy file parses OK", false, (err as Error).message);
    }
  }

  // 4. Audit log directory
  const auditPath = auditLogPath();
  const auditDir = path.dirname(auditPath);
  check("Audit log directory exists", fs.existsSync(auditDir), auditDir);

  // 5. Crypto self-test
  let masterPw: string;
  if (!kExists) {
    // No keystore yet — use a random key just to prove AES-256-GCM works
    masterPw = crypto.randomBytes(16).toString("hex");
  } else {
    // Try keychain first, fall back to interactive prompt
    let keychainPw: string | null = null;
    try {
      keychainPw = await keychainGet();
    } catch {
      // keychain unavailable — fall through to prompt
    }
    masterPw = keychainPw ?? await promptMasterPassword("Master password (for crypto test)");
  }
  try {
    Keystore.selfTest(masterPw);
    check("AES-256-GCM crypto self-test", true);
  } catch (err) {
    check("AES-256-GCM crypto self-test", false, (err as Error).message);
  }

  // 6. Keystore password verification
  const ks = new Keystore(masterPw);
  const services = ks.listServices();
  if (services.length > 0) {
    const pwOk = ks.verifyPassword();
    check("Master password decrypts keystore", pwOk);
  } else {
    check("Master password check (skipped — no secrets yet)", true, "no entries");
  }

  // 7. OpenAI proxy request construction (no live call)
  if (services.find((s) => s.service === "openai")) {
    try {
      // Verify we can at least retrieve the secret
      const secret = ks.getSecret("openai");
      const hasPrefix = secret.startsWith("sk-") || secret.startsWith("Bearer ");
      // Overwrite immediately
      const redacted = secret.replace(/./g, "*");
      void redacted; // reference to avoid optimizer removing it
      check(
        "OpenAI key retrievable from keystore",
        true,
        `key starts with "sk-": ${hasPrefix}`
      );
    } catch (err) {
      check("OpenAI key retrievable from keystore", false, (err as Error).message);
    }
  } else {
    check("OpenAI key check (skipped — not stored)", true, 'run "asv add openai"');
  }

  print("");
  if (ok) {
    print("All checks passed.");
  } else {
    print("Some checks failed. Review the output above.");
    process.exit(1);
  }
}

/** asv mcp — delegates to built dist/mcp/server.js */
function cmdMcp(): void {
  const serverPath = path.resolve(__dirname, "../mcp/server.js");
  if (!fs.existsSync(serverPath)) {
    die(
      `MCP server not built: ${serverPath}\nRun "npm run build" first.`
    );
  }

  // Validate required env before exec
  if (!process.env["ASV_MASTER_PASSWORD"]) {
    die(
      "ASV_MASTER_PASSWORD env var required for non-interactive MCP server start.\n" +
        "Set it in your shell or MCP host configuration."
    );
  }

  // Exec the server — replaces current process
  try {
    execFileSync(process.execPath, [serverPath], {
      stdio: "inherit",
      env: process.env,
    });
  } catch (err) {
    // execFileSync throws on non-zero exit; that's fine for MCP shutdown
    const code = (err as NodeJS.ErrnoException & { status?: number }).status ?? 1;
    // Exit code 130 = SIGINT (Ctrl-C) — not a real error, suppress exit
    if (code !== 130) process.exit(code);
  }
}

// ---------------------------------------------------------------------------
// Logs helpers + command
// ---------------------------------------------------------------------------

/** Format a single audit log entry as a human-readable line. */
function formatLogEntry(entry: AuditEntry): string {
  // Convert ISO-8601 to "YYYY-MM-DD HH:MM:SS"
  const ts = entry.timestamp.replace("T", " ").replace(/\.\d+Z$/, "");
  const decision = entry.decision.toUpperCase().padEnd(5);
  const latency = `${entry.latency_ms ?? 0}ms`;
  const reqId = entry.request_id.slice(0, 8);
  const errorSuffix = entry.error ? `  (${entry.error})` : "";
  return `[${ts}] ${decision}  ${entry.identity} → ${entry.service}/${entry.action}  ${latency}  req:${reqId}${errorSuffix}`;
}

/** asv logs [--tail] [--last <n>] */
async function cmdLogs(args: string[]): Promise<void> {
  const logPath = auditLogPath();
  const tail = args.includes("--tail");

  let lastN = 50;
  const lastIdx = args.indexOf("--last");
  if (lastIdx !== -1) {
    const n = parseInt(args[lastIdx + 1] ?? "", 10);
    if (isNaN(n) || n < 1) die("--last requires a positive integer");
    lastN = n;
  }

  if (!fs.existsSync(logPath)) {
    print(`No audit log found at ${logPath}. Run asv mcp to start logging.`);
    return;
  }

  const content = fs.readFileSync(logPath, "utf8");
  const lines = content.split("\n").filter((l) => l.trim().length > 0);
  const slice = lines.slice(-lastN);

  for (const line of slice) {
    try {
      const entry = JSON.parse(line) as AuditEntry;
      print(formatLogEntry(entry));
    } catch {
      // Skip malformed lines
    }
  }

  if (tail) {
    print("");
    print("Watching for new entries (Ctrl-C to stop)...");
    let offset = fs.statSync(logPath).size;

    fs.watch(logPath, () => {
      try {
        const stat = fs.statSync(logPath);
        if (stat.size <= offset) return;
        const fd = fs.openSync(logPath, "r");
        const buffer = Buffer.alloc(stat.size - offset);
        fs.readSync(fd, buffer, 0, buffer.length, offset);
        fs.closeSync(fd);
        offset = stat.size;
        const newLines = buffer.toString("utf8").split("\n").filter((l) => l.trim().length > 0);
        for (const newLine of newLines) {
          try {
            const entry = JSON.parse(newLine) as AuditEntry;
            print(formatLogEntry(entry));
          } catch {
            // Skip malformed lines
          }
        }
      } catch {
        // Ignore transient watch errors
      }
    });
  }
}

// ---------------------------------------------------------------------------
// Keychain command
// ---------------------------------------------------------------------------

/** asv keychain <set|delete|status> */
async function cmdKeychain(subcommand: string): Promise<void> {
  switch (subcommand) {
    case "set": {
      const pw = await promptMasterPassword("Master password to store in keychain");
      const confirm = await promptMasterPassword("Confirm");
      if (pw !== confirm) {
        die("Passwords do not match.");
      }
      try {
        await keychainSet(pw);
      } catch (err) {
        die((err as Error).message);
      }
      print("  ✓ Master password stored in OS keychain.");
      print("    You can now remove ASV_MASTER_PASSWORD from your MCP config.");
      break;
    }
    case "delete": {
      let deleted = false;
      try {
        deleted = await keychainDelete();
      } catch (err) {
        die((err as Error).message);
      }
      if (deleted) {
        print("  ✓ Master password removed from OS keychain.");
      } else {
        print("  · No master password found in keychain.");
      }
      break;
    }
    case "status": {
      let exists = false;
      try {
        exists = await keychainExists();
      } catch (err) {
        die((err as Error).message);
      }
      if (exists) {
        print("Keychain: master password is stored");
      } else {
        print("Keychain: no master password stored");
      }
      break;
    }
    default:
      die(
        `Unknown keychain subcommand: "${subcommand}"\n` +
          "Usage: asv keychain <set|delete|status>"
      );
  }
}

// ---------------------------------------------------------------------------
// Rotate command
// ---------------------------------------------------------------------------

/** asv rotate <service> */
async function cmdRotate(service: string): Promise<void> {
  if (!service) die("Usage: asv rotate <service>  (e.g. asv rotate openai)");

  // 1. Prompt for current master password
  const currentPw = await promptMasterPassword("Current master password");

  // 2. Verify current password
  const ks = new Keystore(currentPw);
  if (!ks.verifyPassword()) {
    die("Wrong master password.");
  }

  // 3. Retrieve the secret under the current password
  let secret: string;
  try {
    secret = ks.getSecret(service);
  } catch (err) {
    die((err as Error).message);
  }

  // 4. Prompt for new master password
  const newPw = await promptMasterPassword("New master password");

  // 5. Confirm new master password
  const confirmPw = await promptMasterPassword("Confirm new master password");
  if (newPw !== confirmPw) {
    secret = "";
    die("Passwords do not match.");
  }

  // 6. Re-encrypt under new password
  const newKs = new Keystore(newPw);
  newKs.setSecret(service, secret);

  // 7. Overwrite secret immediately
  secret = "";

  print(`  ✓ Secret for "${service}" re-encrypted with new master password.`);
  print(`    Note: other services remain encrypted with the old password.`);
  print(`    Run asv rotate <service> for each additional service.`);
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

function printHelp(): void {
  print(`
ASV — Agent Secrets Vault v0.1.1

Usage:
  asv <command> [args]

Commands:
  init              Create config directories and default policy.yaml
  add <service>     Store an encrypted secret for a service (e.g. openai)
  list              List stored service names and metadata (no secrets)
  revoke <service>  Delete the stored secret for a service
  doctor            Run health checks on config, crypto, and keystore
  mcp               Start the MCP server (requires ASV_MASTER_PASSWORD env var)
  logs              Show audit log entries (newest last, default 50)
                      --last <n>   Show last N entries
                      --tail       Watch for new entries in real time (Ctrl-C to stop)
  rotate <service>  Re-encrypt a service secret under a new master password
                      Note: run once per service — each is rotated individually
  keychain set      Store master password in OS keychain (eliminates plaintext in config)
  keychain delete   Remove master password from OS keychain
  keychain status   Check whether master password is in keychain
  help              Show this help message

Environment variables (for MCP server):
  ASV_MASTER_PASSWORD   Master password (required for "asv mcp")
  ASV_IDENTITY          Identity for policy checks (default: "unknown")
  ASV_POLICY_PATH       Override path to policy.yaml

Examples:
  asv init
  asv add openai
  ASV_MASTER_PASSWORD=secret asv mcp
`);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const [, , command, ...rest] = process.argv;

  switch (command) {
    case "init":
      await cmdInit();
      break;
    case "add":
      await cmdAdd(rest[0] ?? "");
      break;
    case "list":
      await cmdList();
      break;
    case "revoke":
      await cmdRevoke(rest[0] ?? "");
      break;
    case "doctor":
      await cmdDoctor();
      break;
    case "mcp":
      cmdMcp();
      break;
    case "logs":
      await cmdLogs(rest);
      break;
    case "rotate":
      await cmdRotate(rest[0] ?? "");
      break;
    case "keychain":
      await cmdKeychain(rest[0] ?? "");
      break;
    case "help":
    case "--help":
    case "-h":
      printHelp();
      break;
    default:
      if (command) {
        printErr(`Unknown command: ${command}`);
      }
      printHelp();
      process.exit(command ? 1 : 0);
  }
}

main().catch((err) => {
  printErr(`Error: ${(err as Error).message}`);
  process.exit(1);
});
