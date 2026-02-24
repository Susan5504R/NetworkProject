#!/bin/bash
# test_all.sh — Master test runner for Mini IDS
# Runs all test suites in order:
#   1. Backend API tests  (no sudo required)
#   2. IDS Attack tests   (sudo required, IDS must be running)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

OVERALL_FAIL=0

echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                                                       ║${NC}"
echo -e "${CYAN}║${NC}   ${BOLD} Mini IDS — Complete Test Suite${NC}                  ${CYAN}║${NC}"
echo -e "${CYAN}║                                                       ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"

#  Suite 1: Backend API Tests 

echo ""
echo -e "${BOLD}━━━ SUITE 1: Backend API Tests ━━━${NC}"
bash "$SCRIPT_DIR/test_backend_api.sh"
if [ $? -ne 0 ]; then
    OVERALL_FAIL=1
fi

#  Suite 2: IDS Attack Simulation Tests 

echo ""
echo -e "${BOLD}━━━ SUITE 2: IDS Attack Simulation Tests ━━━${NC}"
echo -e "${YELLOW}Note: Attack tests require sudo and a running IDS engine.${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}⚠  Not running as root. Skipping attack simulation tests.${NC}"
    echo -e "   Re-run with: ${BOLD}sudo bash $0${NC}"
    OVERALL_FAIL=1
else
    bash "$SCRIPT_DIR/test_ids_attacks.sh"
    if [ $? -ne 0 ]; then
        OVERALL_FAIL=1
    fi
fi

#  Overall Summary 

echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}   ${BOLD} Overall Test Summary${NC}                             ${CYAN}║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"

if [ "$OVERALL_FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}ALL TEST SUITES PASSED!${NC}"
else
    echo -e "  ${YELLOW}${BOLD}⚠  SOME TESTS FAILED — review details above.${NC}"
fi
echo ""

exit "$OVERALL_FAIL"
