# LLM Proxy

The LLM Proxy sits between your application and the OpenAI API. It tokenizes PII in outbound prompts via the Aegis vault, forwards only sanitized text to the model, then detokenizes the response before returning it to the caller.

**The LLM never sees raw PII.** The caller still sends and receives real values.

## Why this beats simple masking

Masking tools replace PII with redacted placeholders (`j***@example.com`). That works for display, but the LLM loses context — it cannot reply with the actual email address, reference a specific card ending, or take action on real identifiers.

Aegis LLM Proxy uses **round-trip fidelity**:

1. `john@example.com` → `tok_abc123` before the LLM call
2. LLM responds using the token: *"I'll email tok_abc123 about the refund"*
3. Proxy restores: *"I'll email john@example.com about the refund"*

The model operates on stable token references; the user gets human-readable output.

## Audit trail differentiator

Every proxy request writes an `LLM_PROXY` entry to `audit_logs`:

| Field | Value |
|-------|-------|
| `action` | `LLM_PROXY` |
| `actor_id` | JWT user who initiated the call |
| `token` | Comma-separated vault tokens used in the request |
| `field_type` | `openai` |
| `access_level` | Count of PII values tokenized |
| `success` | Whether the full round-trip completed |

This creates a compliance-grade record of every time PII was exposed to an external model — who triggered it, which tokens were involved, and whether it succeeded.

## Endpoint

```
POST /api/v1/llmproxy/chat
Authorization: Bearer <JWT>
```

**Request**
```json
{
  "prompt": "email john@example.com about card 4111111111114242",
  "provider": "openai"
}
```

**Response**
```json
{
  "success": true,
  "data": {
    "response": "I'll send an email to john@example.com regarding card ending 4242.",
    "pii_detected": 2,
    "provider": "openai"
  }
}
```

What the LLM actually received:
```
email tok_a1b2c3d4-... about card tok_e5f6g7h8-...
```

## Example curl

```bash
# Login first
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | jq -r '.data.token')

# Send prompt with PII — get real PII back, LLM sees tokens only
curl -X POST http://localhost:8080/api/v1/llmproxy/chat \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Write a short reply confirming email to john@example.com",
    "provider": "openai"
  }'
```

## Detected PII types

Regex-only detection (no external NLP):

| Type | Pattern |
|------|---------|
| `email` | Standard email format |
| `phone` | Indian mobile (`6-9` + 9 digits) |
| `card_number` | 15–16 digit card numbers |
| `aadhaar` | 12 digits with optional separators |
| `pan` | `ABCDE1234F` |

## Environment variables

| Variable | Description |
|----------|-------------|
| `LLM_PROVIDER` | Default provider: `openai` |
| `LLM_API_KEY` | OpenAI API key |
| `LLM_MODEL` | Model name (e.g. `gpt-4o`) |

## Error behaviour

| Condition | HTTP status |
|-----------|---------------|
| Vault tokenize fails | `500` — raw PII is never forwarded |
| LLM API down | `503` — clear unavailable message |
| No PII detected | Prompt forwarded as-is, no vault calls |

## Architecture

```
User prompt (real PII)
    ↓
detector.go (regex scan)
    ↓
vault.Service.Tokenize() (internal Go call)
    ↓
sanitized prompt → LLM API
    ↓
LLM response (contains tokens)
    ↓
vault.Service.Detokenize() (ADMIN role, internal)
    ↓
User response (real PII restored)
    ↓
audit_logs (LLM_PROXY entry)
```
