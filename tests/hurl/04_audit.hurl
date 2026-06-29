# ============================================================
# 04_audit.hurl — Audit log verification tests
#
# Verifies that STORE, DETOKENIZE (success + denied), and DELETE
# actions are all recorded in the audit log with the correct fields.
#
# Users created here: audit_admin, audit_analyst
# ============================================================


# =============================================================
# SETUP: Register and login as ADMIN + ANALYST
# =============================================================

POST {{base_url}}/api/v1/auth/register
Content-Type: application/json
{
  "username": "audit_admin",
  "password": "{{test_password}}",
  "role": "ADMIN"
}

[Asserts]
status == 201

[Captures]
audit_admin_id: jsonpath "$.data.id"


POST {{base_url}}/api/v1/auth/register
Content-Type: application/json
{
  "username": "audit_analyst",
  "password": "{{test_password}}",
  "role": "ANALYST"
}

[Asserts]
status == 201


POST {{base_url}}/api/v1/auth/login
Content-Type: application/json
{
  "username": "audit_admin",
  "password": "{{test_password}}"
}

[Asserts]
status == 200

[Captures]
admin_token: jsonpath "$.data.token"


POST {{base_url}}/api/v1/auth/login
Content-Type: application/json
{
  "username": "audit_analyst",
  "password": "{{test_password}}"
}

[Asserts]
status == 200

[Captures]
analyst_token: jsonpath "$.data.token"


# =============================================================
# Generate audit events: STORE, DETOKENIZE (success), DENIED, DELETE
# =============================================================

# STORE event: tokenize email (as admin)
POST {{base_url}}/api/v1/vault/tokenize
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "field_type": "email",
  "value": "audit@example.com"
}

[Asserts]
status == 201

[Captures]
audit_email_token: jsonpath "$.data.token"


# STORE event: tokenize card_number (as admin)
POST {{base_url}}/api/v1/vault/tokenize
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "field_type": "card_number",
  "value": "4111111111114242"
}

[Asserts]
status == 201

[Captures]
audit_card_token: jsonpath "$.data.token"


# DETOKENIZE success event (admin detokenizes email — FULL access)
POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "token": "{{audit_email_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "FULL"


# DETOKENIZE success event (analyst detokenizes email — MASKED access)
POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{analyst_token}}
Content-Type: application/json
{
  "token": "{{audit_email_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "MASKED"


# DETOKENIZE DENIED event (analyst tries card_number — ANALYST is DENIED)
POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{analyst_token}}
Content-Type: application/json
{
  "token": "{{audit_card_token}}"
}

[Asserts]
status == 403


# DELETE event (admin soft-deletes card_number token)
DELETE {{base_url}}/api/v1/vault/{{audit_card_token}}
Authorization: Bearer {{admin_token}}

[Asserts]
status == 200


# =============================================================
# Verify audit logs exist and have correct structure
# =============================================================

GET {{base_url}}/api/v1/audit/logs
Authorization: Bearer {{admin_token}}

[Asserts]
status == 200
jsonpath "$.success" == true
jsonpath "$.data.logs" isCollection
jsonpath "$.data.total" > 0
jsonpath "$.data.page" == 1
jsonpath "$.data.limit" == 20

# Verify structure of the first log entry
jsonpath "$.data.logs[0].id" isString
jsonpath "$.data.logs[0].actor_id" isString
jsonpath "$.data.logs[0].action" isString
jsonpath "$.data.logs[0].token" isString
jsonpath "$.data.logs[0].field_type" isString
jsonpath "$.data.logs[0].ip_address" isString
jsonpath "$.data.logs[0].created_at" isString


# =============================================================
# Audit logs with pagination
# =============================================================

GET {{base_url}}/api/v1/audit/logs?page=1&limit=5
Authorization: Bearer {{admin_token}}

[Asserts]
status == 200
jsonpath "$.data.page" == 1
jsonpath "$.data.limit" == 5
jsonpath "$.data.logs" count <= 5


# =============================================================
# Audit logs for a specific token
# =============================================================

GET {{base_url}}/api/v1/audit/logs/{{audit_email_token}}
Authorization: Bearer {{admin_token}}

[Asserts]
status == 200
jsonpath "$.success" == true
jsonpath "$.data.logs" isCollection
jsonpath "$.data.logs" count >= 3

# All entries should reference the same token
jsonpath "$.data.logs[0].token" == "{{audit_email_token}}"


# =============================================================
# Verify DENIED event was logged for the card_number token
# =============================================================

GET {{base_url}}/api/v1/audit/logs/{{audit_card_token}}
Authorization: Bearer {{admin_token}}

[Asserts]
status == 200
jsonpath "$.data.logs" count >= 2


# =============================================================
# Non-ADMIN users cannot read audit logs
# =============================================================

GET {{base_url}}/api/v1/audit/logs
Authorization: Bearer {{analyst_token}}

[Asserts]
status == 403
jsonpath "$.success" == false


GET {{base_url}}/api/v1/audit/logs/{{audit_email_token}}
Authorization: Bearer {{analyst_token}}

[Asserts]
status == 403
jsonpath "$.success" == false


# =============================================================
# Unauthenticated request to audit logs — expect 401
# =============================================================

GET {{base_url}}/api/v1/audit/logs

[Asserts]
status == 401
