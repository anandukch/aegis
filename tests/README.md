# AEGIS Regression Tests

API-level regression tests using [Hurl](https://hurl.dev) — plain text HTTP request files with built-in assertions.

## Prerequisites

- AEGIS server running (`docker-compose up` or `go run cmd/server/main.go`)
- [Hurl installed](https://hurl.dev/docs/installation.html)

```bash
# Install Hurl on Ubuntu/Debian
curl -LO https://github.com/Orange-OpenSource/hurl/releases/latest/download/hurl_amd64.deb
sudo dpkg -i hurl_amd64.deb
```

## Running Tests

```bash
# Run the full suite (resets DB first, then runs all test files in order)
./tests/run_tests.sh

# Run against a different host
BASE_URL=http://staging.example.com ./tests/run_tests.sh

# Run without DB reset (useful for debugging a failure)
./tests/run_tests.sh --no-clean

# Run a single test file
./tests/run_tests.sh --file 02_vault
./tests/run_tests.sh --file 04_audit

# Or run a file directly with Hurl
hurl --variables-file tests/hurl/variables.env --test tests/hurl/03_rbac.hurl
```

Or via Make:

```bash
make test-regression   # same as ./tests/run_tests.sh
make test-all          # unit tests + regression tests
```

## Test Files

| File | What it tests |
|------|---------------|
| `00_health.hurl` | Health endpoint — API is up and responding |
| `01_auth.hurl` | Register, login, duplicate username, short password, wrong credentials |
| `02_vault.hurl` | Tokenize all field types, detokenize, metadata, soft delete, **full RBAC access matrix** |
| `03_rbac.hurl` | Create/update/delete roles, set/delete permissions, system role guards |
| `04_audit.hurl` | Audit log creation for STORE/DETOKENIZE/DELETE actions, pagination, access control |

## Test Data

All test users use a file-scoped prefix to avoid collisions across test files:

| File | Users created |
|------|---------------|
| `01_auth.hurl` | `auth_admin`, `auth_viewer`, `auth_analyst`, `auth_norole` |
| `02_vault.hurl` | `vault_admin`, `vault_analyst`, `vault_service`, `vault_viewer`, `vault_support` |
| `03_rbac.hurl` | `rbac_admin`, `rbac_viewer` |
| `04_audit.hurl` | `audit_admin`, `audit_analyst` |

PII test values used in `02_vault.hurl`:

| Field | Value | Masked |
|-------|-------|--------|
| email | `john@example.com` | `j***@example.com` |
| phone | `9876543210` | `******3210` |
| card_number | `4111111111114242` | `****-****-****-4242` |
| aadhaar | `123456781234` | `XXXX-XXXX-1234` |
| pan | `ABCDE1234F` | `ABCDE****F` |
| name | `John Doe` | `J*** D***` |
| dob | `1990-07-15` | `****-**-15` |

## RBAC Access Matrix Tested

`02_vault.hurl` verifies each role × field type combination:

| Role | email | phone | card_number | aadhaar | pan | name | dob |
|------|-------|-------|-------------|---------|-----|------|-----|
| ADMIN | FULL | FULL | FULL | FULL | FULL | FULL | FULL |
| ANALYST | MASKED | MASKED | **DENIED** | MASKED | MASKED | MASKED | MASKED |
| SERVICE | MASKED | MASKED | **FULL** | MASKED | — | — | — |
| VIEWER | MASKED | MASKED | MASKED | — | — | MASKED | MASKED |
| SUPPORT (custom) | **FULL** | MASKED | **DENIED** | MASKED | MASKED | MASKED | MASKED |

## DB Reset

The run script truncates `users`, `vault_records`, `audit_logs` and removes custom roles before each full run. System roles (ADMIN, ANALYST, SERVICE, VIEWER) are preserved.

The reset uses `docker compose exec postgres psql ...`. If you're running Postgres locally, set `CLEAN_DB=false` or pass `--no-clean` and manually reset:

```bash
psql -U postgres -d piivault -c "TRUNCATE users, vault_records, audit_logs RESTART IDENTITY CASCADE;"
psql -U postgres -d piivault -c "DELETE FROM roles WHERE is_system = FALSE;"
```

## CI/CD

Tests run automatically via `.github/workflows/regression.yml` on every push and pull request. The workflow:

1. Starts a Postgres service container
2. Builds and starts the AEGIS server
3. Runs `./tests/run_tests.sh --no-clean` (CI starts with a clean DB)
