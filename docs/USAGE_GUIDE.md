# AEGIS — User Guide

This guide walks through using AEGIS from scratch: setting up your account, storing sensitive data, retrieving it, and understanding what each role can see.

---

## What Is AEGIS?

Your application should never store raw PII (emails, phone numbers, card numbers) in its own database. Instead:

1. Send the sensitive value to AEGIS → get back a **token**
2. Store the token in your database
3. When you need the real value, call AEGIS with the token
4. AEGIS checks your role and returns full, masked, or denied access

The raw data stays encrypted inside AEGIS's vault. Your app only ever sees tokens.

---

## Prerequisites

- AEGIS running at `http://localhost:8080` (or your deployment URL)
- `curl` installed
- An account on the AEGIS instance (ask your admin, or register if open registration is enabled)

---

## Step 1 — Register an Account

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "password123",
    "role": "ADMIN"
  }'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "a1b2c3d4-...",
    "username": "alice",
    "role": "ADMIN"
  }
}
```

**Available roles:**

| Role | What they can see |
|------|-------------------|
| `ADMIN` | Full raw values for all field types |
| `SERVICE` | Full raw values for `card_number` only; masked for everything else |
| `ANALYST` | Masked values for `email`, `name`; denied for `card_number` |
| `VIEWER` | Masked values for all field types |

> Only `ADMIN` users can assign roles to other users.

---

## Step 2 — Login and Get Your Token

Every API call (except register/login) requires a JWT token in the `Authorization` header.

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "password123"
  }'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "user": {
      "id": "a1b2c3d4-...",
      "username": "alice",
      "role": "ADMIN"
    }
  }
}
```

Save the `token` value. Use it as `Bearer <token>` on all subsequent calls.

```bash
# Save for convenience
TOKEN="eyJhbGciOiJIUzI1NiIs..."
```

---

## Step 3 — Store a PII Value (Tokenize)

Send the sensitive value to the vault. You get back a token — store this in your database instead of the raw value.

**Supported field types:** `email`, `phone`, `card_number`, `aadhaar`, `pan`, `name`, `dob`

```bash
# Store an email
curl -X POST http://localhost:8080/api/v1/vault/tokenize \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "field_type": "email",
    "value": "john@example.com"
  }'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "token": "tok_7f3a9c1e-4b2d-4f8a-9c1e-7f3a9c1e4b2d",
    "field_type": "email",
    "created_at": "2026-05-31T10:00:00Z"
  }
}
```

The `token` is what you store. The raw email is never returned again unless explicitly detokenized by an authorized role.

**More examples:**

```bash
# Store a phone number
curl -X POST http://localhost:8080/api/v1/vault/tokenize \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"field_type": "phone", "value": "9876543210"}'

# Store a card number
curl -X POST http://localhost:8080/api/v1/vault/tokenize \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"field_type": "card_number", "value": "4111111111114242"}'

# Store a name
curl -X POST http://localhost:8080/api/v1/vault/tokenize \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"field_type": "name", "value": "John Doe"}'

# Store a PAN (format: ABCDE1234F)
curl -X POST http://localhost:8080/api/v1/vault/tokenize \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"field_type": "pan", "value": "ABCDE1234F"}'
```

---

## Step 4 — Retrieve a Value (Detokenize)

Submit a token to get the value back. What you see depends on your role.

```bash
curl -X POST http://localhost:8080/api/v1/vault/detokenize \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "tok_7f3a9c1e-4b2d-4f8a-9c1e-7f3a9c1e4b2d"
  }'
```

**Response varies by role:**

```bash
# ADMIN sees full value
{
  "token": "tok_7f3a9c1e-...",
  "field_type": "email",
  "value": "john@example.com",
  "access_level": "FULL"
}

# ANALYST sees masked value
{
  "token": "tok_7f3a9c1e-...",
  "field_type": "email",
  "value": "j***@example.com",
  "access_level": "MASKED"
}

# ANALYST on card_number → access denied
{
  "success": false,
  "error": "access denied for this field type"
}
```

**Masking rules by field type:**

| Field Type | Masked Example |
|------------|----------------|
| `email` | `john@example.com` → `j***@example.com` |
| `phone` | `9876543210` → `******3210` |
| `card_number` | `4111111111114242` → `****-****-****-4242` |
| `aadhaar` | `123456781234` → `XXXX-XXXX-1234` |
| `pan` | `ABCDE1234F` → `ABCDE****F` |
| `name` | `John Doe` → `J*** D***` |
| `dob` | `1990-07-15` → `****-**-15` |

---

## Step 5 — Check Token Metadata (Without Retrieving Value)

Get field type and creation timestamp without touching the raw value.

```bash
curl http://localhost:8080/api/v1/vault/tok_7f3a9c1e-.../metadata \
  -H "Authorization: Bearer $TOKEN"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "token": "tok_7f3a9c1e-...",
    "field_type": "email",
    "created_at": "2026-05-31T10:00:00Z",
    "created_by": "a1b2c3d4-..."
  }
}
```

---

## Step 6 — Delete a Vault Record (ADMIN only)

Soft-deletes the record. Token becomes invalid for future detokenize calls. Audit history is preserved.

```bash
curl -X DELETE http://localhost:8080/api/v1/vault/tok_7f3a9c1e-... \
  -H "Authorization: Bearer $TOKEN"
```

**Response:**
```json
{
  "success": true,
  "data": { "message": "record deleted" }
}
```

---

## Role Management (ADMIN only)

### List all roles and permissions

```bash
curl http://localhost:8080/api/v1/roles \
  -H "Authorization: Bearer $TOKEN"
```

### Assign a role to a user

```bash
curl -X POST http://localhost:8080/api/v1/users/<user-id>/role \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "ANALYST"}'
```

---

## Audit Logs (ADMIN only)

Every operation — store, detokenize attempt, delete — is logged automatically. You cannot delete audit logs.

### View all logs (paginated)

```bash
curl "http://localhost:8080/api/v1/audit/logs?page=1&limit=20" \
  -H "Authorization: Bearer $TOKEN"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "logs": [
      {
        "id": "uuid",
        "actor_id": "uuid",
        "action": "DETOKENIZE",
        "token": "tok_...",
        "field_type": "email",
        "access_level": "MASKED",
        "ip_address": "192.168.1.10",
        "success": true,
        "created_at": "2026-05-31T10:05:00Z"
      }
    ],
    "total": 42,
    "page": 1,
    "limit": 20
  }
}
```

### View all access history for a specific token

```bash
curl http://localhost:8080/api/v1/audit/logs/tok_7f3a9c1e-... \
  -H "Authorization: Bearer $TOKEN"
```

Useful for compliance reviews: see exactly who accessed a piece of PII, when, from what IP, and what access level they received.

---

## Health Check

```bash
curl http://localhost:8080/health
```

```json
{
  "success": true,
  "data": { "status": "ok", "version": "1.0.0", "uptime": "3600s" }
}
```

---

## Error Reference

| HTTP Status | Meaning |
|-------------|---------|
| `400` | Bad request — missing or invalid fields |
| `401` | No token / invalid / expired JWT |
| `403` | Your role doesn't have permission for this operation |
| `404` | Token not found or already deleted |
| `409` | Username already exists |
| `500` | Internal server error |

All errors return:
```json
{ "success": false, "error": "<description>" }
```

---

## Quick Reference — All Endpoints

| Method | Path | Auth | Role | Purpose |
|--------|------|------|------|---------|
| `POST` | `/api/v1/auth/register` | No | — | Create account |
| `POST` | `/api/v1/auth/login` | No | — | Get JWT |
| `POST` | `/api/v1/vault/tokenize` | Yes | Any | Store PII, get token |
| `POST` | `/api/v1/vault/detokenize` | Yes | Any | Retrieve value (role-gated) |
| `GET` | `/api/v1/vault/:token/metadata` | Yes | Any | Token info, no raw value |
| `DELETE` | `/api/v1/vault/:token` | Yes | ADMIN | Soft-delete record |
| `GET` | `/api/v1/roles` | Yes | Any | List role permissions |
| `POST` | `/api/v1/users/:id/role` | Yes | ADMIN | Assign role to user |
| `GET` | `/api/v1/audit/logs` | Yes | ADMIN | Paginated audit trail |
| `GET` | `/api/v1/audit/logs/:token` | Yes | ADMIN | Audit history for token |
| `GET` | `/health` | No | — | Service health |
