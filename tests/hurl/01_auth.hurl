# ============================================================
# 01_auth.hurl — Auth flow regression tests
# Users created here: auth_admin, auth_viewer
# ============================================================

# --- Register ADMIN user ---
POST {{base_url}}/api/v1/auth/register
Content-Type: application/json
{
  "username": "auth_admin",
  "password": "{{test_password}}",
  "role": "ADMIN"
}

[Asserts]
status == 201
jsonpath "$.success" == true
jsonpath "$.data.username" == "auth_admin"
jsonpath "$.data.role" == "ADMIN"
jsonpath "$.data.id" isString

[Captures]
auth_admin_id: jsonpath "$.data.id"


# --- Login as ADMIN — happy path ---
POST {{base_url}}/api/v1/auth/login
Content-Type: application/json
{
  "username": "auth_admin",
  "password": "{{test_password}}"
}

[Asserts]
status == 200
jsonpath "$.success" == true
jsonpath "$.data.token" isString
jsonpath "$.data.user.username" == "auth_admin"
jsonpath "$.data.user.role" == "ADMIN"
jsonpath "$.data.user.id" == "{{auth_admin_id}}"

[Captures]
admin_token: jsonpath "$.data.token"


# --- Register VIEWER user ---
POST {{base_url}}/api/v1/auth/register
Content-Type: application/json
{
  "username": "auth_viewer",
  "password": "{{test_password}}",
  "role": "VIEWER"
}

[Asserts]
status == 201
jsonpath "$.success" == true
jsonpath "$.data.username" == "auth_viewer"
jsonpath "$.data.role" == "VIEWER"


# --- Register ANALYST user ---
POST {{base_url}}/api/v1/auth/register
Content-Type: application/json
{
  "username": "auth_analyst",
  "password": "{{test_password}}",
  "role": "ANALYST"
}

[Asserts]
status == 201
jsonpath "$.success" == true
jsonpath "$.data.role" == "ANALYST"


# --- Register with no role — should default to VIEWER ---
POST {{base_url}}/api/v1/auth/register
Content-Type: application/json
{
  "username": "auth_norole",
  "password": "{{test_password}}"
}

[Asserts]
status == 201
jsonpath "$.success" == true
jsonpath "$.data.role" == "VIEWER"


# --- Login with wrong password — expect 401 ---
POST {{base_url}}/api/v1/auth/login
Content-Type: application/json
{
  "username": "auth_admin",
  "password": "wrongpassword"
}

[Asserts]
status == 401
jsonpath "$.success" == false
jsonpath "$.error" == "invalid credentials"


# --- Login with nonexistent user — expect 401 ---
POST {{base_url}}/api/v1/auth/login
Content-Type: application/json
{
  "username": "auth_doesnotexist",
  "password": "{{test_password}}"
}

[Asserts]
status == 401
jsonpath "$.success" == false


# --- Register duplicate username — expect 409 ---
POST {{base_url}}/api/v1/auth/register
Content-Type: application/json
{
  "username": "auth_admin",
  "password": "{{test_password}}",
  "role": "VIEWER"
}

[Asserts]
status == 409
jsonpath "$.success" == false
jsonpath "$.error" == "username already exists"


# --- Register with password too short (< 8 chars) — expect 400 ---
POST {{base_url}}/api/v1/auth/register
Content-Type: application/json
{
  "username": "auth_shortpw",
  "password": "short"
}

[Asserts]
status == 400
jsonpath "$.success" == false


# --- Access a protected endpoint without token — expect 401 ---
GET {{base_url}}/api/v1/roles

[Asserts]
status == 401
