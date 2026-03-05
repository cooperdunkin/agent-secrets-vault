# Agent Secrets Vault (ASV)

A local, MCP-compatible credential broker that lets AI agents call external services **without ever receiving raw credentials**.

---

## How It Works

```
Agent (Cursor / Claude Code)
  │
  │  request_credential({ service: "openai", action: "responses.create", params: {...} })
  ▼
ASV MCP Server  ──── policy check ──── audit log
  │
  │  injects stored API key
  ▼
OpenAI API  ──── raw response ────► back to agent

(API key is NEVER returned to the agent)
```

The agent describes what it needs. ASV checks the policy, calls the external API with the stored credential, and returns only the API response.

---

## 5-Minute Setup

### Prerequisites

- Node.js 20+
- npm

### 1. Install globally

```bash
npm install -g agent-secrets-vault
```

### 2. Initialise ASV

```bash
asv init
```

This creates:
- `~/.asv/`  — encrypted keystore and audit log (restricted to mode 700)
- `config/policy.yaml` — allow/deny rules
- `data/` — runtime data directory

### 3. Store your OpenAI API key

```bash
asv add openai
```

You will be prompted for:
1. Your **master password** (used to encrypt the key at rest — choose a strong one)
2. Your **OpenAI API key** (`sk-...`)

Neither value is echoed to the terminal.

### 4. Configure your MCP host

#### Cursor

Add to `~/.cursor/mcp.json` (or your project's `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "agent-secrets-vault": {
      "command": "node",
      "args": ["/absolute/path/to/agent-secrets-vault/dist/mcp/server.js"],
      "env": {
        "ASV_IDENTITY": "local-dev",
        "ASV_MASTER_PASSWORD": "your-master-password-here"
      }
    }
  }
}
```

#### Claude Code

Add to your Claude Code MCP config (`~/.claude/claude_code_config.json` or project `.claude/claude_code_config.json`):

```json
{
  "mcpServers": {
    "agent-secrets-vault": {
      "command": "node",
      "args": ["/absolute/path/to/agent-secrets-vault/dist/mcp/server.js"],
      "env": {
        "ASV_IDENTITY": "local-dev",
        "ASV_MASTER_PASSWORD": "your-master-password-here"
      }
    }
  }
}
```

> **Security note:** `ASV_MASTER_PASSWORD` in the MCP config file is stored in **plaintext on disk**. Use `asv keychain set` to store it in your OS keychain instead — see [Keychain Setup](#keychain-setup-recommended) below.

### 5. Verify everything works

```bash
asv doctor
```

---

## Keychain Setup (Recommended)

By default, `ASV_MASTER_PASSWORD` must be set in your MCP config file — stored in plaintext on disk. To eliminate this risk, store the master password in your OS keychain instead:

```bash
asv keychain set
```

Then update your MCP config to remove `ASV_MASTER_PASSWORD`:

```json
{
  "mcpServers": {
    "agent-secrets-vault": {
      "command": "node",
      "args": ["/absolute/path/to/agent-secrets-vault/dist/mcp/server.js"],
      "env": {
        "ASV_IDENTITY": "local-dev"
      }
    }
  }
}
```

ASV will retrieve the master password from your OS keychain automatically on startup.

**Linux users:** Install libsecret before running keychain commands:

```bash
# Ubuntu/Debian
sudo apt install libsecret-1-dev
# Fedora
sudo dnf install libsecret-devel
```

---

## CLI Reference

```
asv init                  Create config directories and default policy.yaml
asv add <service>         Store an encrypted secret (e.g. asv add openai)
asv list                  List stored services (names/metadata only, no secrets)
asv revoke <service>      Delete the stored secret for a service
asv doctor                Health-check: config, policy, crypto, keystore
asv mcp                   Start the MCP server (env var or keychain for password)
asv logs                  Show audit log entries (--tail to watch, --last N)
asv rotate <service>      Re-encrypt a service secret under a new master password
asv keychain set          Store master password in OS keychain
asv keychain delete       Remove master password from OS keychain
asv keychain status       Check whether master password is in keychain
asv help                  Show help
```

---

## MCP Tool Reference

ASV exposes **one tool**: `request_credential`

### Input

| Field | Type | Required | Description |
|---|---|---|---|
| `service` | string | ✓ | Service to call (e.g. `"openai"`) |
| `action` | string | ✓ | Action to perform (e.g. `"responses.create"`) |
| `justification` | string | ✓ | Why this call is being made (audit-logged) |
| `params` | object | ✓ | Service-specific request parameters |

### Output (allowed)

```json
{
  "ok": true,
  "result": { /* API response */ },
  "request_id": "uuid-v4"
}
```

### Output (denied)

```json
{
  "denied": true,
  "reason": "Policy denied: identity=\"local-dev\" service=\"openai\" action=\"...\"|",
  "request_id": "uuid-v4"
}
```

### Example agent usage

```
Use the request_credential tool to ask ASV to generate a response:

{
  "service": "openai",
  "action": "responses.create",
  "justification": "Summarising the uploaded document for the user",
  "params": {
    "model": "gpt-4o",
    "input": "Summarise the following text in 3 sentences: ..."
  }
}
```

---

## Policy Configuration

Edit `config/policy.yaml` to control which identities can call which services.

**Deny-by-default**: a request is rejected unless an explicit `allow` rule matches.

```yaml
policies:
  - identity: local-dev        # matches ASV_IDENTITY env var
    allow:
      - service: openai
        actions:
          - responses.create   # only this action is permitted

  # Wildcards
  - identity: "*"              # any identity
    allow:
      - service: public-svc
        actions:
          - "*"                # any action
```

### Identity resolution

The identity used for policy checks comes from the `ASV_IDENTITY` environment variable set in your MCP host config. Fallback: `"unknown"`.

---

## Encryption Details

| Property | Value |
|---|---|
| Algorithm | AES-256-GCM |
| Key derivation | PBKDF2-SHA-512, 210,000 iterations |
| Salt | 32 bytes, unique per entry |
| Nonce/IV | 12 bytes, unique per entry |
| Auth tag | 128 bits |
| Storage | `~/.asv/keystore.json`, mode 600 |

Each stored secret gets its own randomly generated salt and IV. The master password is never stored — only derived keys are used per-operation.

---

## Audit Log

All requests are logged to `~/.asv/audit.jsonl`. Each line is a JSON object:

```json
{
  "timestamp": "2025-01-15T10:30:00.000Z",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "identity": "local-dev",
  "service": "openai",
  "action": "responses.create",
  "decision": "allow",
  "justification": "Summarising document for user",
  "latency_ms": 342,
  "error": null
}
```

**Secrets are never logged.** The audit log contains only metadata.

---

## Environment Variables

| Variable | Context | Description |
|---|---|---|
| `ASV_MASTER_PASSWORD` | MCP server, `asv mcp` | Master password to unlock keystore. Optional if stored in OS keychain via `asv keychain set`; env var takes priority when set. |
| `ASV_IDENTITY` | MCP server | Identity for policy checks (default: `"unknown"`) |
| `ASV_POLICY_PATH` | MCP server | Override path to policy.yaml |

---

## Development

```bash
npm run build          # compile TypeScript → dist/
npm run build:watch    # watch mode
npm test               # run test suite (uses tsx, no build needed)
npm run test:built     # run tests against compiled output
npm run lint           # type-check without emitting
```

### Adding a new service

1. Create `src/proxy/<service>.ts` implementing `proxyRequest(params, keystore)`.
2. Register it in the dispatch table in `src/proxy/openai.ts` (`proxyRequest` function).
3. Add allow rules for the new service in `config/policy.yaml`.
4. Run `asv add <service>` to store the credential.

---

## Threat Model Notes

### What ASV protects against

| Threat | Mitigation |
|---|---|
| **Agent receives raw credential** | Credentials never appear in tool responses; the proxy injects them server-side |
| **Credential leaked in logs** | Audit log records only metadata; request bodies with potential secrets are never logged |
| **Credential stored in plaintext** | AES-256-GCM encryption at rest; unique salt+IV per entry prevents rainbow tables |
| **Unauthorised service access** | Deny-by-default YAML policy; identity-scoped allow rules |
| **Credential used for unintended action** | Policy rules are scoped to specific `service` + `action` pairs |
| **Secrets in source control** | `~/.asv/` is outside the repo; `data/` and `.env` files are `.gitignore`d |
| **Tampered keystore entry** | AES-GCM authentication tag detects any modification to ciphertext |

### What ASV does NOT protect against

| Threat | Notes |
|---|---|
| **Compromised local machine** | An attacker with OS-level access can read `~/.asv/keystore.json` and, if they have the master password, decrypt all secrets. Full disk encryption (FileVault, LUKS) is the appropriate defence. |
| **Malicious MCP host process** | The MCP host (Cursor, Claude Code) receives the full API response from ASV. A malicious or compromised host process could intercept this. ASV assumes the MCP host is trusted. |
| **`ASV_MASTER_PASSWORD` in MCP config** | Mitigated by `asv keychain set`, which stores the master password in your OS keychain (macOS Keychain, Linux Secret Service, Windows Credential Manager) so it never appears in config files. See [Keychain Setup](#keychain-setup-recommended). If you use the env var approach instead, restrict config file permissions with `chmod 600`. |
| **Memory scraping** | Decrypted secrets pass through process memory. An attacker with memory-read access (e.g. via ptrace) could extract them. |
| **Policy misconfiguration** | Overly broad wildcards (`"*"`) in policy.yaml grant wide access. Review policy rules carefully. |
| **Denial of service** | ASV supports per-identity rate limiting (configurable via `rateLimit.requestsPerMinute` in policy.yaml), but it is off by default and only limits request volume — not API quota consumption per request. A compromised agent could still exhaust API quota with large or expensive requests. |
| **Supply chain attacks** | ASV depends on `@modelcontextprotocol/sdk`, `js-yaml`, and `uuid`. Review their integrity in production deployments. |

### Recommended additional hardening

- Enable full-disk encryption on the host machine.
- Set restrictive permissions on your MCP config file: `chmod 600 ~/.cursor/mcp.json`
- Rotate the master password periodically (requires re-encrypting all entries).
- Review `~/.asv/audit.jsonl` regularly for unexpected requests.
- Use `asv keychain set` to store the master password in your OS keychain, eliminating the need for `ASV_MASTER_PASSWORD` in plaintext MCP config files.

---

## License

MIT
