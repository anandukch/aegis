# ============================================================
# 02_vault.hurl — Vault operations + RBAC enforcement tests
#
# Part A: Basic vault ops (tokenize, detokenize, metadata, delete)
# Part B: Role-based access enforcement for all roles × field types
#
# Users created here:
#   vault_admin (ADMIN), vault_analyst (ANALYST),
#   vault_service (SERVICE), vault_viewer (VIEWER),
#   vault_support (VIEWER → upgraded to custom SUPPORT role)
# ============================================================


# =============================================================
# SETUP: Register all test users
# =============================================================

POST {{base_url}}/api/v1/auth/register
Content-Type: application/json
{
  "username": "vault_admin",
  "password": "{{test_password}}",
  "role": "ADMIN"
}

[Asserts]
status == 201
jsonpath "$.success" == true


POST {{base_url}}/api/v1/auth/register
Content-Type: application/json
{
  "username": "vault_analyst",
  "password": "{{test_password}}",
  "role": "ANALYST"
}

[Asserts]
status == 201
jsonpath "$.success" == true


POST {{base_url}}/api/v1/auth/register
Content-Type: application/json
{
  "username": "vault_service",
  "password": "{{test_password}}",
  "role": "SERVICE"
}

[Asserts]
status == 201
jsonpath "$.success" == true


POST {{base_url}}/api/v1/auth/register
Content-Type: application/json
{
  "username": "vault_viewer",
  "password": "{{test_password}}",
  "role": "VIEWER"
}

[Asserts]
status == 201
jsonpath "$.success" == true


# vault_support starts as VIEWER — upgraded to SUPPORT role later
POST {{base_url}}/api/v1/auth/register
Content-Type: application/json
{
  "username": "vault_support",
  "password": "{{test_password}}",
  "role": "VIEWER"
}

[Asserts]
status == 201
jsonpath "$.success" == true

[Captures]
support_user_id: jsonpath "$.data.id"


# =============================================================
# SETUP: Login as ADMIN and tokenize all PII field types
# =============================================================

POST {{base_url}}/api/v1/auth/login
Content-Type: application/json
{
  "username": "vault_admin",
  "password": "{{test_password}}"
}

[Asserts]
status == 200
jsonpath "$.success" == true

[Captures]
admin_token: jsonpath "$.data.token"


# Tokenize email
POST {{base_url}}/api/v1/vault/tokenize
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "field_type": "email",
  "value": "john@example.com"
}

[Asserts]
status == 201
jsonpath "$.success" == true
jsonpath "$.data.token" matches "^tok_"
jsonpath "$.data.field_type" == "email"

[Captures]
email_token: jsonpath "$.data.token"


# Tokenize phone
POST {{base_url}}/api/v1/vault/tokenize
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "field_type": "phone",
  "value": "9876543210"
}

[Asserts]
status == 201
jsonpath "$.data.field_type" == "phone"

[Captures]
phone_token: jsonpath "$.data.token"


# Tokenize card_number
POST {{base_url}}/api/v1/vault/tokenize
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "field_type": "card_number",
  "value": "4111111111114242"
}

[Asserts]
status == 201
jsonpath "$.data.field_type" == "card_number"

[Captures]
card_token: jsonpath "$.data.token"


# Tokenize aadhaar
POST {{base_url}}/api/v1/vault/tokenize
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "field_type": "aadhaar",
  "value": "123456781234"
}

[Asserts]
status == 201
jsonpath "$.data.field_type" == "aadhaar"

[Captures]
aadhaar_token: jsonpath "$.data.token"


# Tokenize PAN
POST {{base_url}}/api/v1/vault/tokenize
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "field_type": "pan",
  "value": "ABCDE1234F"
}

[Asserts]
status == 201
jsonpath "$.data.field_type" == "pan"

[Captures]
pan_token: jsonpath "$.data.token"


# Tokenize name
POST {{base_url}}/api/v1/vault/tokenize
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "field_type": "name",
  "value": "John Doe"
}

[Asserts]
status == 201
jsonpath "$.data.field_type" == "name"

[Captures]
name_token: jsonpath "$.data.token"


# Tokenize DOB
POST {{base_url}}/api/v1/vault/tokenize
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "field_type": "dob",
  "value": "1990-07-15"
}

[Asserts]
status == 201
jsonpath "$.data.field_type" == "dob"

[Captures]
dob_token: jsonpath "$.data.token"


# Extra email token dedicated for the deletion test
POST {{base_url}}/api/v1/vault/tokenize
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "field_type": "email",
  "value": "delete@example.com"
}

[Asserts]
status == 201

[Captures]
delete_token: jsonpath "$.data.token"


# =============================================================
# PART A: Basic vault operations
# =============================================================

# Metadata: verify token metadata is returned correctly
GET {{base_url}}/api/v1/vault/{{email_token}}/metadata
Authorization: Bearer {{admin_token}}

[Asserts]
status == 200
jsonpath "$.success" == true
jsonpath "$.data.token" == "{{email_token}}"
jsonpath "$.data.field_type" == "email"
jsonpath "$.data.created_at" isString
jsonpath "$.data.created_by" isString


# Tokenize with invalid field type — expect 400
POST {{base_url}}/api/v1/vault/tokenize
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "field_type": "invalid_type",
  "value": "somevalue"
}

[Asserts]
status == 400
jsonpath "$.success" == false


# Tokenize with invalid PAN format — expect 400
POST {{base_url}}/api/v1/vault/tokenize
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "field_type": "pan",
  "value": "NOTAPAN"
}

[Asserts]
status == 400
jsonpath "$.success" == false


# Soft delete the dedicated delete_token
DELETE {{base_url}}/api/v1/vault/{{delete_token}}
Authorization: Bearer {{admin_token}}

[Asserts]
status == 200
jsonpath "$.success" == true
jsonpath "$.data.message" == "record deleted"


# Detokenize deleted token — expect 404
POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "token": "{{delete_token}}"
}

[Asserts]
status == 404
jsonpath "$.success" == false


# Metadata of deleted token — expect 404
GET {{base_url}}/api/v1/vault/{{delete_token}}/metadata
Authorization: Bearer {{admin_token}}

[Asserts]
status == 404


# Non-ADMIN user cannot delete vault records
POST {{base_url}}/api/v1/auth/login
Content-Type: application/json
{
  "username": "vault_viewer",
  "password": "{{test_password}}"
}

[Captures]
viewer_token_temp: jsonpath "$.data.token"


DELETE {{base_url}}/api/v1/vault/{{email_token}}
Authorization: Bearer {{viewer_token_temp}}

[Asserts]
status == 403


# =============================================================
# PART B: RBAC enforcement — ADMIN role (FULL on all fields)
# =============================================================

POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "token": "{{email_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "FULL"
jsonpath "$.data.value" == "john@example.com"
jsonpath "$.data.field_type" == "email"


POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "token": "{{phone_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "FULL"
jsonpath "$.data.value" == "9876543210"


POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "token": "{{card_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "FULL"
jsonpath "$.data.value" == "4111111111114242"


POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "token": "{{aadhaar_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "FULL"
jsonpath "$.data.value" == "123456781234"


POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "token": "{{pan_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "FULL"
jsonpath "$.data.value" == "ABCDE1234F"


POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "token": "{{name_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "FULL"
jsonpath "$.data.value" == "John Doe"


POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "token": "{{dob_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "FULL"
jsonpath "$.data.value" == "1990-07-15"


# =============================================================
# PART B: RBAC enforcement — ANALYST role
#   email → MASKED, phone → MASKED, card_number → DENIED (403)
#   all others → MASKED
# =============================================================

POST {{base_url}}/api/v1/auth/login
Content-Type: application/json
{
  "username": "vault_analyst",
  "password": "{{test_password}}"
}

[Asserts]
status == 200

[Captures]
analyst_token: jsonpath "$.data.token"


POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{analyst_token}}
Content-Type: application/json
{
  "token": "{{email_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "MASKED"
jsonpath "$.data.value" == "j***@example.com"


POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{analyst_token}}
Content-Type: application/json
{
  "token": "{{phone_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "MASKED"
jsonpath "$.data.value" == "******3210"


# ANALYST is DENIED for card_number
POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{analyst_token}}
Content-Type: application/json
{
  "token": "{{card_token}}"
}

[Asserts]
status == 403
jsonpath "$.success" == false
jsonpath "$.error" == "access denied for this field type"


POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{analyst_token}}
Content-Type: application/json
{
  "token": "{{aadhaar_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "MASKED"
jsonpath "$.data.value" == "XXXX-XXXX-1234"


POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{analyst_token}}
Content-Type: application/json
{
  "token": "{{pan_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "MASKED"
jsonpath "$.data.value" == "ABCDE****F"


POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{analyst_token}}
Content-Type: application/json
{
  "token": "{{name_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "MASKED"
jsonpath "$.data.value" == "J*** D***"


POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{analyst_token}}
Content-Type: application/json
{
  "token": "{{dob_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "MASKED"
jsonpath "$.data.value" == "****-**-15"


# =============================================================
# PART B: RBAC enforcement — SERVICE role
#   card_number → FULL, all others → MASKED
# =============================================================

POST {{base_url}}/api/v1/auth/login
Content-Type: application/json
{
  "username": "vault_service",
  "password": "{{test_password}}"
}

[Asserts]
status == 200

[Captures]
service_token: jsonpath "$.data.token"


POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{service_token}}
Content-Type: application/json
{
  "token": "{{card_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "FULL"
jsonpath "$.data.value" == "4111111111114242"


POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{service_token}}
Content-Type: application/json
{
  "token": "{{email_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "MASKED"
jsonpath "$.data.value" == "j***@example.com"


POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{service_token}}
Content-Type: application/json
{
  "token": "{{phone_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "MASKED"
jsonpath "$.data.value" == "******3210"


POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{service_token}}
Content-Type: application/json
{
  "token": "{{aadhaar_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "MASKED"
jsonpath "$.data.value" == "XXXX-XXXX-1234"


# =============================================================
# PART B: RBAC enforcement — VIEWER role (all MASKED)
# =============================================================

POST {{base_url}}/api/v1/auth/login
Content-Type: application/json
{
  "username": "vault_viewer",
  "password": "{{test_password}}"
}

[Asserts]
status == 200

[Captures]
viewer_token: jsonpath "$.data.token"


POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{viewer_token}}
Content-Type: application/json
{
  "token": "{{email_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "MASKED"
jsonpath "$.data.value" == "j***@example.com"


POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{viewer_token}}
Content-Type: application/json
{
  "token": "{{phone_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "MASKED"
jsonpath "$.data.value" == "******3210"


POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{viewer_token}}
Content-Type: application/json
{
  "token": "{{card_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "MASKED"
jsonpath "$.data.value" == "****-****-****-4242"


POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{viewer_token}}
Content-Type: application/json
{
  "token": "{{name_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "MASKED"
jsonpath "$.data.value" == "J*** D***"


POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{viewer_token}}
Content-Type: application/json
{
  "token": "{{dob_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "MASKED"
jsonpath "$.data.value" == "****-**-15"


# =============================================================
# PART B: RBAC enforcement — Custom SUPPORT role
#   * → MASKED (default), email → FULL, card_number → DENIED
# =============================================================

# Create SUPPORT role
POST {{base_url}}/api/v1/rbac/roles
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "name": "SUPPORT",
  "description": "Customer support with limited PII access"
}

[Asserts]
status == 201
jsonpath "$.success" == true
jsonpath "$.data.name" == "SUPPORT"
jsonpath "$.data.is_system" == false

[Captures]
support_role_id: jsonpath "$.data.id"


# Set default permission: all fields → MASKED
POST {{base_url}}/api/v1/rbac/roles/{{support_role_id}}/permissions
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "field_type": "*",
  "access_level": "MASKED"
}

[Asserts]
status == 200
jsonpath "$.success" == true


# Override: email → FULL
POST {{base_url}}/api/v1/rbac/roles/{{support_role_id}}/permissions
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "field_type": "email",
  "access_level": "FULL"
}

[Asserts]
status == 200
jsonpath "$.success" == true


# Override: card_number → DENIED
POST {{base_url}}/api/v1/rbac/roles/{{support_role_id}}/permissions
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "field_type": "card_number",
  "access_level": "DENIED"
}

[Asserts]
status == 200
jsonpath "$.success" == true


# Assign SUPPORT role to vault_support user
POST {{base_url}}/api/v1/users/{{support_user_id}}/role
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "role": "SUPPORT"
}

[Asserts]
status == 200
jsonpath "$.success" == true
jsonpath "$.data.message" == "role updated"


# Login as vault_support to get fresh JWT with SUPPORT role
POST {{base_url}}/api/v1/auth/login
Content-Type: application/json
{
  "username": "vault_support",
  "password": "{{test_password}}"
}

[Asserts]
status == 200
jsonpath "$.data.user.role" == "SUPPORT"

[Captures]
support_token: jsonpath "$.data.token"


# email → FULL (explicit override)
POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{support_token}}
Content-Type: application/json
{
  "token": "{{email_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "FULL"
jsonpath "$.data.value" == "john@example.com"


# phone → MASKED (falls back to * default)
POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{support_token}}
Content-Type: application/json
{
  "token": "{{phone_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "MASKED"
jsonpath "$.data.value" == "******3210"


# card_number → DENIED (explicit override)
POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{support_token}}
Content-Type: application/json
{
  "token": "{{card_token}}"
}

[Asserts]
status == 403
jsonpath "$.success" == false
jsonpath "$.error" == "access denied for this field type"


# name → MASKED (falls back to * default)
POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{support_token}}
Content-Type: application/json
{
  "token": "{{name_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "MASKED"
jsonpath "$.data.value" == "J*** D***"


# aadhaar → MASKED (falls back to * default)
POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{support_token}}
Content-Type: application/json
{
  "token": "{{aadhaar_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "MASKED"
jsonpath "$.data.value" == "XXXX-XXXX-1234"


# pan → MASKED (falls back to * default)
POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{support_token}}
Content-Type: application/json
{
  "token": "{{pan_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "MASKED"
jsonpath "$.data.value" == "ABCDE****F"


# dob → MASKED (falls back to * default)
POST {{base_url}}/api/v1/vault/detokenize
Authorization: Bearer {{support_token}}
Content-Type: application/json
{
  "token": "{{dob_token}}"
}

[Asserts]
status == 200
jsonpath "$.data.access_level" == "MASKED"
jsonpath "$.data.value" == "****-**-15"
