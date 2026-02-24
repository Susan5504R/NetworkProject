#!/bin/bash
# test_ids_attacks.sh — Simulate all 9 attack types against the running IDS
# REQUIRES: sudo, hping3, nmap, arping
# REQUIRES: IDS engine running (sudo ./ids_engine from project root)

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG_FILE="$PROJECT_ROOT/logs/alerts.json"
TARGET_IP="127.0.0.1"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

PASS_COUNT=0
FAIL_COUNT=0
TOTAL_TESTS=9

#Helpers

print_header() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}   Mini IDS — Attack Simulation Test Suite${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "  Target IP : ${YELLOW}${TARGET_IP}${NC}"
    echo -e "  Log File  : ${YELLOW}${LOG_FILE}${NC}"
    echo -e "  Tests     : ${YELLOW}${TOTAL_TESTS}${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo ""
}

check_prerequisites() {
    echo -e "${BOLD}[PRE-CHECK] Verifying prerequisites...${NC}"

    # Check root
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}✗ This script must be run as root (sudo)${NC}"
        exit 1
    fi
    echo -e "  ${GREEN}✓${NC} Running as root"

    # Check tools
    for tool in hping3 nmap arping curl; do
        if command -v $tool &>/dev/null; then
            echo -e "  ${GREEN}✓${NC} $tool found"
        else
            echo -e "  ${RED}✗${NC} $tool not found — install with: sudo apt-get install $tool"
            exit 1
        fi
    done

    # Check IDS is running
    if pgrep -x "ids_engine" > /dev/null || pgrep -x "mini_ids" > /dev/null; then
        echo -e "  ${GREEN}✓${NC} IDS engine is running"
    else
        echo -e "  ${RED}✗${NC} IDS engine is NOT running"
        echo -e "    Start it with: ${YELLOW}cd $PROJECT_ROOT && sudo ./ids_engine${NC}"
        exit 1
    fi

    # Ensure log directory exists
    mkdir -p "$PROJECT_ROOT/logs"
    echo -e "  ${GREEN}✓${NC} Log directory exists"
    echo ""
}

# Snapshot the log line count before an attack, then check for new lines after
get_log_line_count() {
    if [ -f "$LOG_FILE" ]; then
        wc -l < "$LOG_FILE"
    else
        echo "0"
    fi
}

check_alert() {
    local test_name="$1"
    local expected_type="$2"
    local lines_before="$3"

    # Get only NEW lines added since the attack started
    local lines_after
    lines_after=$(get_log_line_count)
    local new_lines=$((lines_after - lines_before))

    if [ "$new_lines" -gt 0 ]; then
        # Check only the new lines for the expected alert type
        if tail -n "$new_lines" "$LOG_FILE" | grep -q "\"type\": \"$expected_type\""; then
            echo -e "  ${GREEN}✓ PASS${NC} — ${test_name}: Found '${expected_type}' alert in logs"
            PASS_COUNT=$((PASS_COUNT + 1))
            return 0
        fi
    fi

    echo -e "  ${RED}✗ FAIL${NC} — ${test_name}: Expected '${expected_type}' alert not found"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    return 1
}

#Test Cases

test_port_scan() {
    echo -e "${YELLOW}[TEST 1/9] Port Scan Detection${NC}"
    echo -e "  Scanning ports 1-100 on $TARGET_IP..."
    local before
    before=$(get_log_line_count)

    nmap -p 1-100 "$TARGET_IP" > /dev/null 2>&1 || true

    sleep 3
    check_alert "Port Scan" "Port Scan" "$before"
}

test_syn_flood() {
    echo -e "${YELLOW}[TEST 2/9] SYN Flood Detection${NC}"
    echo -e "  Sending SYN flood to $TARGET_IP:80 for 3 seconds..."
    local before
    before=$(get_log_line_count)

    # Send SYN flood for 3 seconds then kill
    timeout 3 hping3 -S --flood -p 80 "$TARGET_IP" > /dev/null 2>&1 || true

    # Wait for stale connection detection (needs STALE_TIMEOUT_SEC = 10s)
    echo -e "  Waiting 15s for stale connection detection..."
    sleep 15
    check_alert "SYN Flood" "SYN Flood" "$before"
}

test_icmp_flood() {
    echo -e "${YELLOW}[TEST 3/9] ICMP Flood Detection${NC}"
    echo -e "  Sending ICMP flood to $TARGET_IP for 3 seconds..."
    local before
    before=$(get_log_line_count)

    timeout 3 hping3 --icmp --flood "$TARGET_IP" > /dev/null 2>&1 || true

    sleep 3
    check_alert "ICMP Flood" "ICMP Flood" "$before"
}

test_null_scan() {
    echo -e "${YELLOW}[TEST 4/9] Null Scan Detection${NC}"
    echo -e "  Sending TCP packets with no flags to $TARGET_IP:80..."
    local before
    before=$(get_log_line_count)

    # hping3 with no flags (default sends no TCP flags)
    hping3 -c 5 -p 80 "$TARGET_IP" > /dev/null 2>&1 || true

    sleep 3
    check_alert "Null Scan" "Null Scan" "$before"
}

test_xmas_scan() {
    echo -e "${YELLOW}[TEST 5/9] Xmas Scan Detection${NC}"
    echo -e "  Sending Xmas scan (FIN+PSH+URG) to $TARGET_IP:80..."
    local before
    before=$(get_log_line_count)

    # nmap Xmas scan
    nmap -sX -p 80 "$TARGET_IP" > /dev/null 2>&1 || true

    sleep 3
    check_alert "Xmas Scan" "Xmas Scan" "$before"
}

test_protocol_violation() {
    echo -e "${YELLOW}[TEST 6/9] Protocol Violation Detection (SYN+FIN)${NC}"
    echo -e "  Sending SYN+FIN packets to $TARGET_IP:80..."
    local before
    before=$(get_log_line_count)

    # SYN (-S) + FIN (-F) together is illegal
    hping3 -c 5 -S -F -p 80 "$TARGET_IP" > /dev/null 2>&1 || true

    sleep 3
    check_alert "Protocol Violation" "Protocol Violation" "$before"
}

test_arp_spoofing() {
    echo -e "${YELLOW}[TEST 7/9] ARP Spoofing Detection${NC}"

    # Detect primary network interface
    local iface
    iface=$(ip route | grep default | awk '{print $5}' | head -1)

    if [ -z "$iface" ] || [ "$iface" = "lo" ]; then
        echo -e "  ${YELLOW}⚠ SKIP${NC} — No non-loopback interface found for ARP test"
        echo -e "  ARP works only on Ethernet (not loopback). Skipping."
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return 0
    fi

    echo -e "  Using interface: $iface"

    # Get gateway IP
    local gateway
    gateway=$(ip route | grep default | awk '{print $3}' | head -1)

    if [ -z "$gateway" ]; then
        echo -e "  ${YELLOW}⚠ SKIP${NC} — No gateway found for ARP test"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return 0
    fi

    echo -e "  Sending conflicting ARP replies for gateway $gateway..."
    local before
    before=$(get_log_line_count)

    # First arping to let IDS learn the MAC
    arping -c 1 -I "$iface" "$gateway" > /dev/null 2>&1 || true
    sleep 2

    # Send ARP reply with a FAKE source MAC (different from the real one)
    # This uses a crafted packet to make the IDS see a MAC change
    hping3 -2 -c 1 "$gateway" > /dev/null 2>&1 || true

    sleep 3
    check_alert "ARP Spoofing" "ARP Spoofing" "$before"
}

test_sql_injection() {
    echo -e "${YELLOW}[TEST 8/9] SQL Injection Detection (Payload Inspection)${NC}"
    echo -e "  Sending HTTP request with SQL injection pattern..."
    local before
    before=$(get_log_line_count)

    # Send request with SQL injection payload to backend
    curl -s --max-time 5 "http://${TARGET_IP}:3000/api/alerts?q=%27%20OR%201%3D1" > /dev/null 2>&1 || true

    sleep 3
    check_alert "SQL Injection" "SQL Injection Attempt" "$before"
}

test_xss_attack() {
    echo -e "${YELLOW}[TEST 9/9] XSS Attack Detection (Payload Inspection)${NC}"
    echo -e "  Sending HTTP request with XSS payload..."
    local before
    before=$(get_log_line_count)

    # Send request with XSS payload to backend
    curl -s --max-time 5 "http://${TARGET_IP}:3000/api/alerts?q=%3Cscript%3Ealert(1)%3C/script%3E" > /dev/null 2>&1 || true

    sleep 3
    check_alert "XSS Attack" "XSS Attack" "$before"
}

# Main 

print_header
check_prerequisites

echo -e "${BOLD}Starting attack simulations...${NC}"
echo ""

test_port_scan
echo ""
test_syn_flood
echo ""
test_icmp_flood
echo ""
test_null_scan
echo ""
test_xmas_scan
echo ""
test_protocol_violation
echo ""
test_arp_spoofing
echo ""
test_sql_injection
echo ""
test_xss_attack

#Summary 

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Test Results Summary${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}Passed : ${PASS_COUNT}/${TOTAL_TESTS}${NC}"
echo -e "  ${RED}Failed : ${FAIL_COUNT}/${TOTAL_TESTS}${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"

if [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}All tests passed!${NC}"
else
    echo -e "  ${YELLOW}${BOLD}⚠  Some tests failed. Check the details above.${NC}"
fi
echo ""

exit "$FAIL_COUNT"
