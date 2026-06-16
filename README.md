<p align="center">
  <svg width="280" height="80" viewBox="0 0 280 80" xmlns="http://www.w3.org/2000/svg">
    <g transform="translate(40,40)">
      <path d="M-18,-28 L-28,-28 L-28,28 L-18,28" fill="none" stroke="#00D4AA" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"/>
      <path d="M18,-28 L28,-28 L28,28 L18,28" fill="none" stroke="#00D4AA" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"/>
      <path d="M0,-16 L-11,14 L11,14 Z" fill="#00D4AA"/>
      <line x1="-5.5" y1="2" x2="5.5" y2="2" stroke="#0D1117" stroke-width="2.2" stroke-linecap="round"/>
    </g>
    <text x="84" y="34" font-family="system-ui, -apple-system, sans-serif" font-size="26" font-weight="600" letter-spacing="4" fill="#E6EDF3">AEGIS</text>
    <line x1="84" y1="44" x2="264" y2="44" stroke="#00D4AA" stroke-width="0.6" opacity="0.35"/>
    <text x="84" y="58" font-family="system-ui, -apple-system, sans-serif" font-size="9" letter-spacing="2" fill="#8B949E">PII PRIVACY VAULT</text>
  </svg>
</p>

A **PII Data Privacy Vault** REST API built in Go. Instead of storing raw sensitive data (emails, phone numbers, card numbers) in your application database, you send them to AEGIS, get back an opaque token, and store that token. Only authorized roles can retrieve the real data — and every access is logged.

---

## Architecture

<p align="center">
  <img src="./assets/arch.png" alt="AEGIS Architecture" width="900"/>
</p>


---

## Quickstart

```bash
cp .env.example .env
# Edit .env: set JWT_SECRET (32+ chars) and VAULT_MASTER_KEY (exactly 32 chars)

docker-compose up --build
```

That's it. Postgres starts, migrations run, API is live at `http://localhost:8080`.

---

## Usage

Full step-by-step guide with curl examples for every endpoint → **[docs/USAGE_GUIDE.md](docs/USAGE_GUIDE.md)**

API reference → **[docs/API.md](docs/API.md)**

---

## RBAC Access Matrix

| Role     | email  | phone  | card_number | aadhaar | pan    | name   | dob    |
|----------|--------|--------|-------------|---------|--------|--------|--------|
| ADMIN    | FULL   | FULL   | FULL        | FULL    | FULL   | FULL   | FULL   |
| ANALYST  | MASKED | MASKED | **DENIED**  | MASKED  | MASKED | MASKED | MASKED |
| SERVICE  | MASKED | MASKED | FULL        | MASKED  | MASKED | MASKED | MASKED |
| VIEWER   | MASKED | MASKED | MASKED      | MASKED  | MASKED | MASKED | MASKED |

**Masking examples:**
- email: `john@example.com` → `j***@example.com`
- phone: `9876543210` → `******3210`
- card: `4111111111114242` → `****-****-****-4242`
- aadhaar: `123456781234` → `XXXX-XXXX-1234`
- pan: `ABCDE1234F` → `ABCDE****F`
- name: `John Doe` → `J*** D***`
- dob: `1990-07-15` → `****-**-15`

---

## Threat Model — What Happens If AEGIS Is Compromised?

This is the right question to ask about any vault system.

### Database leaked (without the master key)

Attacker gets rows of `enc_value` + `nonce` — both base64-encoded ciphertext. Without `VAULT_MASTER_KEY`, these are computationally infeasible to reverse. AES-256-GCM with a random nonce per record gives no pattern to exploit. **Raw PII remains safe.**

### `VAULT_MASTER_KEY` leaked

This is the single critical secret. If it leaks alongside the database, every record can be decrypted. **This is game over for all stored data.**

Mitigation for production:
- Never store the master key in a `.env` file on the server
- Use a dedicated secrets manager: **AWS KMS**, **HashiCorp Vault**, or **GCP Secret Manager**
- Ideally use envelope encryption — the master key itself is encrypted by a hardware-backed KMS key that never leaves the HSM
- Rotate the master key periodically (requires re-encrypting all vault records)

### `JWT_SECRET` leaked

Attacker can forge valid JWTs with any role (including `ADMIN`), then call `/detokenize` to retrieve raw values — provided the API is reachable and the DB is accessible. **Effectively full read access.**

Mitigation: short `JWT_EXPIRY_HOURS`, rotate the secret immediately on suspicion, use RS256 (asymmetric) JWTs in production so the signing key never needs to be shared.

### Audit logs as a detection layer

Every detokenize call is logged with `actor_id`, `ip_address`, and `timestamp` — even denied ones. Anomalous patterns (high volume from one actor, unusual IPs, DENIED spikes) signal an active breach before full exfiltration completes.

### Summary

| What leaks | Impact | Mitigation |
|---|---|---|
| Database only | None — ciphertext is opaque | AES-256-GCM (built in) |
| `VAULT_MASTER_KEY` | Full decryption of all records | Store in KMS, never in env files |
| `JWT_SECRET` | Attacker can impersonate any role | Short expiry, rotate immediately, use RS256 |
| Both key + DB | Total breach | Defense in depth — restrict DB network access, monitor audit logs. Production-grade mitigation: use Customer-Managed Keys (CMK) where the KEK lives in the customer's own AWS KMS account — even a full vendor-side compromise cannot decrypt data without the customer's key. |

---

## Design Decisions

**AES-256-GCM** — authenticated encryption. GCM provides both confidentiality and integrity: any tamper with the ciphertext causes decryption to fail rather than silently return garbage. A fresh 12-byte random nonce per record ensures identical values produce different ciphertexts.

**Soft deletes** — `deleted_at` timestamp instead of hard delete. Audit logs reference tokens; hard-deleting vault records would leave dangling audit entries. Soft delete preserves the audit trail while making the data inaccessible through normal API flows.

**Append-only audit logs** — no update or delete endpoint for audit records. The audit trail's value is in its immutability. Every STORE, DETOKENIZE, and DELETE is logged regardless of outcome.

**Role embedded in JWT** — no DB lookup per request for role resolution. Role changes only take effect on next login (short JWT expiry mitigates stale role window).

---

## Running Tests

```bash
go test ./internal/crypto/... ./internal/vault/... -v
```

---

## What's Next

See [`internal/llmproxy/README.md`](internal/llmproxy/README.md) — planned LLM proxy that detokenizes PII before sending prompts to external models, preventing raw PII from ever reaching OpenAI/Anthropic.

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `APP_PORT` | HTTP listen port (default: 8080) |
| `APP_ENV` | `development` or `production` |
| `DB_HOST` | Postgres host |
| `DB_PORT` | Postgres port |
| `DB_USER` | Postgres user |
| `DB_PASSWORD` | Postgres password |
| `DB_NAME` | Database name |
| `JWT_SECRET` | HMAC secret for JWT signing (min 32 chars) |
| `JWT_EXPIRY_HOURS` | JWT TTL in hours (default: 24) |
| `VAULT_MASTER_KEY` | AES-256 master key — **must be exactly 32 bytes** |
