# Key Rotation Guide

## How it works

Aegis uses **envelope encryption**. Every vault record has two layers:

```
plaintext PII  ──[DEK]──▶  enc_value   (stored in DB)
DEK            ──[KEK]──▶  enc_dek     (stored in DB)
```

- **DEK** (Data Encryption Key) — a random 32-byte key generated per record, encrypts the actual PII. Never stored in plaintext.
- **KEK** (Key Encryption Key) — your `VAULT_MASTER_KEY`. Only ever used to wrap/unwrap DEKs, never touches PII directly.

**During key rotation** only `enc_dek` is re-written. The `enc_value` (actual encrypted PII) is never touched. This means rotation is fast, safe, and proportional to the number of records — not the size of the data.

---

## Prerequisites

- Direct access to the server (or the machine that has DB access)
- The current `VAULT_MASTER_KEY` value
- A new random 32-byte key to replace it
- The `rotate-keys` binary built from this repo

### Build the binary

```bash
go build -o bin/rotate-keys ./cmd/rotate-keys
```

### Generate a new 32-byte key

```bash
# Using openssl
openssl rand -base64 24

# Or using /dev/urandom
head -c 32 /dev/urandom | base64 | head -c 32
```

> The key must be **exactly 32 bytes** when interpreted as a Go byte slice (i.e. 32 ASCII characters, or a base64 string that decodes to 32 bytes).

---

## One-time setup: migrating legacy records

> **Only needed once** — when first deploying envelope encryption on a system that already has vault records encrypted directly with the KEK (no `enc_dek` column populated).
>
> If you are deploying Aegis fresh, skip this step entirely.

```bash
VAULT_MASTER_KEY="<current 32-byte key>" \
DB_HOST=localhost DB_PORT=5432 DB_USER=postgres DB_PASSWORD=postgres DB_NAME=piivault \
./bin/rotate-keys --migrate
```

Expected output:
```
migrating legacy records to envelope encryption...
done: 42 record(s) migrated
```

After this runs once, every record has an `enc_dek` and this command becomes a permanent no-op. You do not need to run it again.

---

## Regular key rotation

Run this whenever you want to retire the current `VAULT_MASTER_KEY`.

### Step 1 — Generate the new key

```bash
openssl rand -base64 24
# example output: aBcDeFgHiJkLmNoPqRsTuVwXyZ012345
```

Keep this value — you will need it in step 3.

### Step 2 — Run the rotation tool

The tool reads the **current** key from `VAULT_MASTER_KEY` and the **new** key from `VAULT_NEW_MASTER_KEY`.

```bash
VAULT_MASTER_KEY="<current key>" \
VAULT_NEW_MASTER_KEY="<new key>" \
DB_HOST=localhost DB_PORT=5432 DB_USER=postgres DB_PASSWORD=postgres DB_NAME=piivault \
./bin/rotate-keys
```

Expected output:
```
starting key rotation...
key rotation complete: 42 record(s) re-wrapped
next steps:
  1. set VAULT_MASTER_KEY to the new key in your secrets manager / .env
  2. remove VAULT_NEW_MASTER_KEY
  3. restart the aegis server
```

> If the tool fails mid-way (e.g. DB goes down), it reports how many records were rotated before the error. Re-running is safe — records already on the new KEK will fail the unwrap with the old KEK and cause an error, so **do not change `VAULT_MASTER_KEY` in the environment until the tool exits with code 0**.

### Step 3 — Update the environment

Update `VAULT_MASTER_KEY` in your secrets manager, `.env`, or deployment config to the **new** key. Remove `VAULT_NEW_MASTER_KEY` entirely.

```bash
# .env example
VAULT_MASTER_KEY=<new key>
# VAULT_NEW_MASTER_KEY — remove this line
```

### Step 4 — Restart the server

```bash
# Docker Compose
docker compose restart app

# Or a full redeploy
docker compose up -d --force-recreate app
```

The server will now use the new KEK. All existing tokens continue to work — the DEKs were re-wrapped in step 2, so decryption is transparent.

### Step 5 — Verify

Pick any existing token and detokenize it. The plaintext should be identical to what was stored before rotation.

```bash
curl -s -X POST http://localhost:8084/api/v1/vault/detokenize \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"token":"tok_<existing token>"}' | jq .data.value
```

---

## What changes vs. what stays the same

| Column | After rotation |
|---|---|
| `enc_dek` | New value (re-wrapped with new KEK) |
| `enc_value` | **Unchanged** |
| `nonce` | **Unchanged** |
| All other columns | **Unchanged** |

---

## Rotation frequency recommendation

| Environment | Suggested cadence |
|---|---|
| Production | Every 90 days, or immediately after a suspected KEK leak |
| Staging | On demand |
| Development | Not required |

---

## What to do if the KEK is compromised

1. Generate a new key immediately.
2. Run `rotate-keys` as fast as possible — this invalidates the leaked KEK for all records.
3. Update `VAULT_MASTER_KEY` and restart.
4. Audit the audit log (`GET /api/v1/audit/logs`) for any unexpected `DETOKENIZE` activity during the exposure window.

> The DEKs are what actually protect your PII. A leaked KEK allows an attacker to unwrap DEKs — but only if they also have a copy of the database. Rotating the KEK as soon as possible closes that window.

---

## Troubleshooting

**`VAULT_MASTER_KEY must be exactly 32 bytes`**
The key you provided is not 32 bytes. Count the characters or use `echo -n "yourkey" | wc -c` to verify.

**`VAULT_NEW_MASTER_KEY must be different from the current VAULT_MASTER_KEY`**
You passed the same value for both. Generate a new key.

**`unwrap DEK for record <id>: authentication tag mismatch`**
The `VAULT_MASTER_KEY` you passed does not match what was used to wrap that record's DEK. Check that you are passing the correct current key, not the new one.

**`partial rotation: N record(s) rotated before error`**
The tool stopped mid-way. The first N records are now on the new KEK, the rest are still on the old KEK. **Do not update `VAULT_MASTER_KEY` yet.** Fix the underlying issue (DB connectivity, disk space, etc.) and re-run the tool from scratch — it will fail again on the first already-rotated record, which tells you the old key is no longer valid for those records. In this case you need to finish the rotation with the new key set as both old and new, or restore from a DB backup and re-run cleanly.
