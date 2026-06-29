# ============================================================
# 03_rbac.hurl — RBAC management API tests
#
# Tests: list roles, create role, get role, update role,
#        set permissions, delete permission, delete role,
#        and guards (system role protection, non-admin access)
#
# Users created here: rbac_admin
# ============================================================


# =============================================================
# SETUP: Register and login as ADMIN
# =============================================================

POST {{base_url}}/api/v1/auth/register
Content-Type: application/json
{
  "username": "rbac_admin",
  "password": "{{test_password}}",
  "role": "ADMIN"
}

[Asserts]
status == 201


POST {{base_url}}/api/v1/auth/login
Content-Type: application/json
{
  "username": "rbac_admin",
  "password": "{{test_password}}"
}

[Asserts]
status == 200

[Captures]
admin_token: jsonpath "$.data.token"


# =============================================================
# List all roles — expect 4 seeded system roles
# =============================================================

GET {{base_url}}/api/v1/rbac/roles
Authorization: Bearer {{admin_token}}

[Asserts]
status == 200
jsonpath "$.success" == true
jsonpath "$.data.roles" count >= 4


# Legacy endpoint also works
GET {{base_url}}/api/v1/roles
Authorization: Bearer {{admin_token}}

[Asserts]
status == 200
jsonpath "$.success" == true


# =============================================================
# Create a new custom role: BILLING
# =============================================================

POST {{base_url}}/api/v1/rbac/roles
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "name": "BILLING",
  "description": "Billing team with full card access"
}

[Asserts]
status == 201
jsonpath "$.success" == true
jsonpath "$.data.name" == "BILLING"
jsonpath "$.data.description" == "Billing team with full card access"
jsonpath "$.data.is_system" == false
jsonpath "$.data.id" isString

[Captures]
billing_role_id: jsonpath "$.data.id"


# =============================================================
# Get role by ID
# =============================================================

GET {{base_url}}/api/v1/rbac/roles/{{billing_role_id}}
Authorization: Bearer {{admin_token}}

[Asserts]
status == 200
jsonpath "$.success" == true
jsonpath "$.data.name" == "BILLING"
jsonpath "$.data.id" == "{{billing_role_id}}"


# Get non-existent role ID — expect 404
GET {{base_url}}/api/v1/rbac/roles/00000000-0000-0000-0000-000000000000
Authorization: Bearer {{admin_token}}

[Asserts]
status == 404


# =============================================================
# Update role description
# =============================================================

PUT {{base_url}}/api/v1/rbac/roles/{{billing_role_id}}
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "name": "BILLING",
  "description": "Updated: Billing team with card and PAN access"
}

[Asserts]
status == 200
jsonpath "$.success" == true
jsonpath "$.data.description" == "Updated: Billing team with card and PAN access"
jsonpath "$.data.name" == "BILLING"


# =============================================================
# Set permissions on BILLING role
# =============================================================

# Default: * → MASKED
POST {{base_url}}/api/v1/rbac/roles/{{billing_role_id}}/permissions
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "field_type": "*",
  "access_level": "MASKED"
}

[Asserts]
status == 200
jsonpath "$.success" == true
jsonpath "$.data.field_type" == "*"
jsonpath "$.data.access_level" == "MASKED"


# card_number → FULL
POST {{base_url}}/api/v1/rbac/roles/{{billing_role_id}}/permissions
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "field_type": "card_number",
  "access_level": "FULL"
}

[Asserts]
status == 200
jsonpath "$.data.field_type" == "card_number"
jsonpath "$.data.access_level" == "FULL"


# pan → FULL
POST {{base_url}}/api/v1/rbac/roles/{{billing_role_id}}/permissions
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "field_type": "pan",
  "access_level": "FULL"
}

[Asserts]
status == 200
jsonpath "$.data.field_type" == "pan"
jsonpath "$.data.access_level" == "FULL"


# Verify BILLING role now has 3 permissions
GET {{base_url}}/api/v1/rbac/roles/{{billing_role_id}}
Authorization: Bearer {{admin_token}}

[Asserts]
status == 200
jsonpath "$.data.permissions" count == 3


# =============================================================
# Invalid permission values — expect 400
# =============================================================

POST {{base_url}}/api/v1/rbac/roles/{{billing_role_id}}/permissions
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "field_type": "invalid_field",
  "access_level": "FULL"
}

[Asserts]
status == 400
jsonpath "$.success" == false


POST {{base_url}}/api/v1/rbac/roles/{{billing_role_id}}/permissions
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "field_type": "email",
  "access_level": "INVALID_LEVEL"
}

[Asserts]
status == 400
jsonpath "$.success" == false


# =============================================================
# Delete a specific permission from BILLING role
# =============================================================

DELETE {{base_url}}/api/v1/rbac/roles/{{billing_role_id}}/permissions/pan
Authorization: Bearer {{admin_token}}

[Asserts]
status == 200
jsonpath "$.success" == true
jsonpath "$.data.message" == "permission removed"


# Verify BILLING now has 2 permissions (pan was removed)
GET {{base_url}}/api/v1/rbac/roles/{{billing_role_id}}
Authorization: Bearer {{admin_token}}

[Asserts]
status == 200
jsonpath "$.data.permissions" count == 2


# =============================================================
# Non-ADMIN user cannot access RBAC management endpoints
# =============================================================

POST {{base_url}}/api/v1/auth/register
Content-Type: application/json
{
  "username": "rbac_viewer",
  "password": "{{test_password}}",
  "role": "VIEWER"
}

[Asserts]
status == 201


POST {{base_url}}/api/v1/auth/login
Content-Type: application/json
{
  "username": "rbac_viewer",
  "password": "{{test_password}}"
}

[Captures]
viewer_token: jsonpath "$.data.token"


POST {{base_url}}/api/v1/rbac/roles
Authorization: Bearer {{viewer_token}}
Content-Type: application/json
{
  "name": "SHOULDFAIL",
  "description": "This should not be created"
}

[Asserts]
status == 403


GET {{base_url}}/api/v1/rbac/roles/{{billing_role_id}}
Authorization: Bearer {{viewer_token}}

[Asserts]
status == 403


# =============================================================
# Delete BILLING role (custom, no users assigned)
# =============================================================

DELETE {{base_url}}/api/v1/rbac/roles/{{billing_role_id}}
Authorization: Bearer {{admin_token}}

[Asserts]
status == 200
jsonpath "$.success" == true
jsonpath "$.data.message" == "role deleted"


# Verify BILLING is gone
GET {{base_url}}/api/v1/rbac/roles/{{billing_role_id}}
Authorization: Bearer {{admin_token}}

[Asserts]
status == 404


# =============================================================
# System role guards — cannot rename or delete system roles
# =============================================================

# Get ADMIN role ID first
GET {{base_url}}/api/v1/rbac/roles
Authorization: Bearer {{admin_token}}

[Captures]
admin_role_id: jsonpath "$.data.roles[0].id"


# Cannot delete a system role
DELETE {{base_url}}/api/v1/rbac/roles/{{admin_role_id}}
Authorization: Bearer {{admin_token}}

[Asserts]
status == 400
jsonpath "$.success" == false


# Cannot rename a system role
PUT {{base_url}}/api/v1/rbac/roles/{{admin_role_id}}
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "name": "SUPERADMIN",
  "description": "Attempt to rename system role"
}

[Asserts]
status == 400
jsonpath "$.success" == false


# =============================================================
# Role name validation — invalid characters
# =============================================================

POST {{base_url}}/api/v1/rbac/roles
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "name": "INVALID NAME WITH SPACES",
  "description": "Should fail validation"
}

[Asserts]
status == 400
jsonpath "$.success" == false
