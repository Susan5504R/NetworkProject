#!/bin/bash
# test_backend_api.sh — Test all Node.js backend API endpoints
# REQUIRES: curl, backend running on localhost:3000

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API_BASE="http://localhost:3000"
CONFIG_FILE="$PROJECT_ROOT/config.json"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

PASS_COUNT=0
FAIL_COUNT=0
TOTAL_TESTS=5

# Helpers 

print_header() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  Mini IDS — Backend API Test Suite${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "  API Base : ${YELLOW}${API_BASE}${NC}"
    echo -e "  Tests    : ${YELLOW}${TOTAL_TESTS}${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo ""
}

check_prerequisites() {
    echo -e "${BOLD}[PRE-CHECK] Verifying prerequisites...${NC}"

    if ! command -v curl &>/dev/null; then
        echo -e "  ${RED}✗${NC} curl not found"
        exit 1
    fi
    echo -e "  ${GREEN}✓${NC} curl found"

    # Check if backend is running
    if curl -s --max-time 3 "$API_BASE/api/health" > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} Backend is running on $API_BASE"
    else
        echo -e "  ${RED}✗${NC} Backend is NOT running on $API_BASE"
        echo -e "    Start it with: ${YELLOW}cd $PROJECT_ROOT/dashboard/backend && node server.js${NC}"
        exit 1
    fi
    echo ""
}

pass() {
    echo -e "  ${GREEN}✓ PASS${NC} — $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
    echo -e "  ${RED}✗ FAIL${NC} — $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

#Test Cases 

test_health_endpoint() {
    echo -e "${YELLOW}[TEST 1/5] GET /api/health${NC}"
    local response
    response=$(curl -s --max-time 5 "$API_BASE/api/health")

    if echo "$response" | grep -q '"status":"ok"'; then
        pass "Health endpoint returned status:ok"
    else
        fail "Health endpoint did not return expected response"
        echo -e "    Response: $response"
    fi
}

test_alerts_endpoint() {
    echo -e "${YELLOW}[TEST 2/5] GET /api/alerts${NC}"
    local response http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$API_BASE/api/alerts")

    if [ "$http_code" = "200" ]; then
        pass "Alerts endpoint returned HTTP 200"
    else
        fail "Alerts endpoint returned HTTP $http_code (expected 200)"
    fi
}

test_alerts_json_format() {
    echo -e "${YELLOW}[TEST 3/5] GET /api/alerts — Valid JSON array${NC}"
    local response
    response=$(curl -s --max-time 5 "$API_BASE/api/alerts")

    # Check it starts with [ (is a JSON array)
    if echo "$response" | head -c 1 | grep -q '\['; then
        pass "Alerts endpoint returns a JSON array"
    else
        fail "Alerts endpoint did not return a JSON array"
        echo -e "    First 100 chars: $(echo "$response" | head -c 100)"
    fi
}

test_settings_update() {
    echo -e "${YELLOW}[TEST 4/5] POST /api/settings — Update threshold${NC}"

    # Save original config
    local original_config=""
    if [ -f "$CONFIG_FILE" ]; then
        original_config=$(cat "$CONFIG_FILE")
    fi

    # Post new threshold
    local response http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        -X POST "$API_BASE/api/settings" \
        -H "Content-Type: application/json" \
        -d '{"threshold": 42}')

    if [ "$http_code" = "200" ]; then
        pass "Settings endpoint returned HTTP 200"
    else
        fail "Settings endpoint returned HTTP $http_code (expected 200)"
    fi

    # Verify config.json was updated
    echo -e "${YELLOW}[TEST 5/5] POST /api/settings — config.json updated${NC}"
    if [ -f "$CONFIG_FILE" ]; then
        local config_content
        config_content=$(cat "$CONFIG_FILE")
        if echo "$config_content" | grep -q '"threshold"'; then
            if echo "$config_content" | grep -q '42'; then
                pass "config.json contains threshold:42"
            else
                fail "config.json does not contain threshold value 42"
                echo -e "    Content: $config_content"
            fi
        else
            fail "config.json does not contain 'threshold' key"
            echo -e "    Content: $config_content"
        fi
    else
        fail "config.json does not exist at $CONFIG_FILE"
    fi

    # Restore original config
    if [ -n "$original_config" ]; then
        echo "$original_config" > "$CONFIG_FILE"
        echo -e "  ${CYAN}ℹ${NC}  Restored original config.json"
    fi
}

# Main 

print_header
check_prerequisites

test_health_endpoint
echo ""
test_alerts_endpoint
echo ""
test_alerts_json_format
echo ""
test_settings_update

# ─── Summary ────────────────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  API Test Results Summary${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}Passed : ${PASS_COUNT}/${TOTAL_TESTS}${NC}"
echo -e "  ${RED}Failed : ${FAIL_COUNT}/${TOTAL_TESTS}${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"

if [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}All API tests passed!${NC}"
else
    echo -e "  ${YELLOW}${BOLD}⚠  Some tests failed. Check the details above.${NC}"
fi
echo ""

exit "$FAIL_COUNT"
