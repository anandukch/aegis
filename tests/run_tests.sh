#!/usr/bin/env bash
# run_tests.sh — AEGIS Hurl regression test runner
#
# Usage:
#   ./tests/run_tests.sh                  # run all tests (default: cleans DB first)
#   ./tests/run_tests.sh --no-clean       # skip DB cleanup (useful for debugging)
#   ./tests/run_tests.sh --file 02_vault  # run a single test file

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HURL_DIR="$SCRIPT_DIR/hurl"
VARS_FILE="$HURL_DIR/variables.env"
BASE_URL="${BASE_URL:-http://localhost:8080}"
CLEAN_DB=true
SINGLE_FILE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-clean)
      CLEAN_DB=false
      shift
      ;;
    --file)
      SINGLE_FILE="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1"
      echo "Usage: $0 [--no-clean] [--file <test_file_prefix>]"
      exit 1
      ;;
  esac
done

# ---------------------------------------------------------------
# Check dependencies
# ---------------------------------------------------------------
if ! command -v hurl &>/dev/null; then
  echo ""
  echo "ERROR: Hurl is not installed."
  echo "Install it from: https://hurl.dev/docs/installation.html"
  echo ""
  echo "  On Ubuntu/Debian:"
  echo "    curl -LO https://github.com/Orange-OpenSource/hurl/releases/latest/download/hurl_amd64.deb"
  echo "    sudo dpkg -i hurl_amd64.deb"
  echo ""
  exit 1
fi

# ---------------------------------------------------------------
# Check that the API is running
# ---------------------------------------------------------------
echo "Checking API at $BASE_URL ..."
if ! curl -sf "$BASE_URL/health" >/dev/null; then
  echo ""
  echo "ERROR: AEGIS API is not reachable at $BASE_URL"
  echo "Start the server first:"
  echo "  docker-compose up -d"
  echo "  # or: go run cmd/server/main.go"
  echo ""
  exit 1
fi
echo "API is up."

# ---------------------------------------------------------------
# Reset the database (truncate test data, preserve system roles)
# ---------------------------------------------------------------
if [[ "$CLEAN_DB" == true ]]; then
  echo ""
  echo "Resetting database ..."

  # Determine how to reach Postgres: prefer docker compose, fall back to psql
  if docker compose ps 2>/dev/null | grep -q "postgres"; then
    PSQL_CMD="docker compose exec -T postgres psql -U postgres -d piivault"
  elif docker ps 2>/dev/null | grep -qE "aegis[_-]postgres"; then
    CONTAINER=$(docker ps --format '{{.Names}}' | grep -E "aegis[_-]postgres" | head -1)
    PSQL_CMD="docker exec -i $CONTAINER psql -U postgres -d piivault"
  else
    echo "WARNING: Could not find running Postgres container."
    echo "         Skipping DB reset. Re-run with --no-clean if DB is already clean."
    CLEAN_DB=false
  fi

  if [[ "$CLEAN_DB" == true ]]; then
    $PSQL_CMD <<'SQL'
TRUNCATE users, vault_records, audit_logs RESTART IDENTITY CASCADE;
DELETE FROM role_permissions WHERE role_id NOT IN (
  SELECT id FROM roles WHERE is_system = TRUE
);
DELETE FROM roles WHERE is_system = FALSE;
SQL
    echo "Database reset complete."
  fi
fi

# ---------------------------------------------------------------
# Run Hurl tests
# ---------------------------------------------------------------
echo ""
PASS=0
FAIL=0
FAILED_FILES=()

run_file() {
  local file="$1"
  local name
  name=$(basename "$file")
  echo "------------------------------------------------------------"
  echo "Running: $name"
  if hurl --variables-file "$VARS_FILE" \
          --variable "base_url=$BASE_URL" \
          --test \
          --color \
          "$file"; then
    echo "PASSED: $name"
    PASS=$((PASS + 1))
  else
    echo "FAILED: $name"
    FAIL=$((FAIL + 1))
    FAILED_FILES+=("$name")
  fi
  echo ""
}

if [[ -n "$SINGLE_FILE" ]]; then
  # Run a single file (match by prefix or full name)
  MATCHED=$(find "$HURL_DIR" -name "${SINGLE_FILE}*.hurl" | sort | head -1)
  if [[ -z "$MATCHED" ]]; then
    echo "ERROR: No test file matching '${SINGLE_FILE}' found in $HURL_DIR"
    exit 1
  fi
  run_file "$MATCHED"
else
  # Run all files in order
  for f in "$HURL_DIR"/*.hurl; do
    run_file "$f"
  done
fi

# ---------------------------------------------------------------
# Summary
# ---------------------------------------------------------------
echo "============================================================"
echo "Results: $PASS passed, $FAIL failed"
if [[ ${#FAILED_FILES[@]} -gt 0 ]]; then
  echo ""
  echo "Failed files:"
  for f in "${FAILED_FILES[@]}"; do
    echo "  - $f"
  done
  echo ""
  exit 1
fi
echo "All tests passed."
