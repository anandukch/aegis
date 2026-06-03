# AEGIS Reference

Base URL: `http://localhost:8080`

All protected endpoints require `Authorization: Bearer <JWT>` header.

---

## Auth

### POST /api/v1/auth/register

Register a new user.

**Request**
```json
{
  "username": "alice",
  "password": "password123",
  "role": "ADMIN"
}
```

**Response 201**
```json
{
  "success": true,
  "data": {
    "id": "uuid",
    "username": "alice",
    "role": "ADMIN"
  }
}
```

Valid roles: `ADMIN`, `ANALYST`, `SERVICE`, `VIEWER`. Defaults to `VIEWER` if omitted or invalid.

---

### POST /api/v1/auth/login

**Request**
```json
{ "username": "alice", "password": "password123" }
```

**Response 200**
```json
{
  "success": true,
  "data": {
    "token": "<JWT>",
    "user": { "id": "uuid", "username": "alice", "role": "ADMIN" }
  }
}
```

---

## Vault

### POST /api/v1/vault/tokenize

Store a PII value and get back a token.

**Request**
```json
{ "field_type": "email", "value": "john@example.com" }
```

Supported `field_type` values: `email`, `phone`, `card_number`, `aadhaar`, `pan`, `name`, `dob`

**Response 201**
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

---

### POST /api/v1/vault/detokenize

Retrieve a value by token. Response depends on caller's role.

**Request**
```json
{ "token": "tok_7f3a9c1e-4b2d-4f8a-9c1e-7f3a9c1e4b2d" }
```

**Response 200 (ADMIN)**
```json
{
  "success": true,
  "data": {
    "token": "tok_...",
    "field_type": "email",
    "value": "john@example.com",
    "access_level": "FULL"
  }
}
```

**Response 200 (ANALYST)**
```json
{
  "success": true,
  "data": {
    "token": "tok_...",
    "field_type": "email",
    "value": "j***@example.com",
    "access_level": "MASKED"
  }
}
```

**Response 403 (DENIED)**
```json
{ "success": false, "error": "access denied for this field type" }
```

---

### GET /api/v1/vault/:token/metadata

Returns token metadata without the raw value.

**Response 200**
```json
{
  "success": true,
  "data": {
    "token": "tok_...",
    "field_type": "email",
    "created_at": "2026-05-31T10:00:00Z",
    "created_by": "uuid"
  }
}
```

---

### DELETE /api/v1/vault/:token

Soft-delete a vault record. **ADMIN only.**

**Response 200**
```json
{ "success": true, "data": { "message": "record deleted" } }
```

---

## RBAC

### GET /api/v1/roles

Returns the permission matrix for all roles.

### POST /api/v1/users/:id/role

Assign a role to a user. **ADMIN only.**

**Request**
```json
{ "role": "ANALYST" }
```

---

## Audit

### GET /api/v1/audit/logs

Paginated audit log. **ADMIN only.**

**Query params:** `page` (default 1), `limit` (default 20, max 100)

**Response 200**
```json
{
  "success": true,
  "data": {
    "logs": [...],
    "total": 42,
    "page": 1,
    "limit": 20
  }
}
```

Each log entry:
```json
{
  "id": "uuid",
  "actor_id": "uuid",
  "action": "DETOKENIZE",
  "token": "tok_...",
  "field_type": "email",
  "access_level": "MASKED",
  "ip_address": "127.0.0.1",
  "success": true,
  "failure_reason": "",
  "created_at": "2026-05-31T10:00:00Z"
}
```

---

### GET /api/v1/audit/logs/:token

All audit entries for a specific token. **ADMIN only.**

Audit entries with `action: "LLM_PROXY"` record each LLM proxy call (provider in `field_type`, tokens used in `token`).

---

## LLM Proxy

### POST /api/v1/llmproxy/chat

Tokenizes detected PII in the prompt, forwards sanitized text to an LLM, detokenizes the response. **Any authenticated role.**

**Request**
```json
{
  "prompt": "email john@example.com about card 4111111111114242",
  "provider": "openai"
}
```

**Response 200**
```json
{
  "success": true,
  "data": {
    "response": "I'll send an email to john@example.com...",
    "pii_detected": 2,
    "provider": "openai"
  }
}
```

**Response 503** — LLM provider unavailable

---

## Health

### GET /health

```json
{ "success": true, "data": { "status": "ok", "version": "1.0.0", "uptime": "42s" } }
```

---

## Error Responses

All errors follow:
```json
{ "success": false, "error": "<message>" }
```

| Status | Meaning |
|--------|---------|
| 400 | Bad request / validation error |
| 401 | Missing or invalid JWT |
| 403 | Insufficient role permissions |
| 404 | Token not found |
| 409 | Username already exists |
| 500 | Internal server error |
