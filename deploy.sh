#!/usr/bin/env bash
# This script:
#   1. Checks for required dependencies
#   2. Compiles the C++ packet-capture engine with -O3
#   3. Sets network capabilities (requires sudo)
#   4. Installs Node.js dependencies
#   5. Creates the logs directory
#   6. Starts both services via PM2
#
# Usage:
#   chmod +x deploy.sh && ./deploy.sh

set -euo pipefail

# Colors for pretty output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

print_header() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  Mini IDS — Deployment${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

step() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} ${BOLD}$1${NC}"
}

success() {
    echo -e "${GREEN}  ✓ $1${NC}"
}

warn() {
    echo -e "${YELLOW}  ⚠ $1${NC}"
}

fail() {
    echo -e "${RED}  ✗ $1${NC}"
    exit 1
}

#Pre-flight Checks

print_header

step "Step 1/6 — Checking dependencies..."

check_dep() {
    if command -v "$1" &>/dev/null; then
        success "$1 found ($(command -v "$1"))"
    else
        fail "$1 not found. Please install it first."
    fi
}

check_dep g++
check_dep node
check_dep npm

# Check for libpcap development headers
if dpkg -s libpcap-dev &>/dev/null 2>&1; then
    success "libpcap-dev found"
elif pkg-config --exists libpcap 2>/dev/null; then
    success "libpcap found (via pkg-config)"
else
    warn "libpcap-dev may not be installed. Compilation might fail."
    warn "Install with: sudo apt install libpcap-dev"
fi

# Check for PM2
if command -v pm2 &>/dev/null; then
    success "pm2 found"
else
    warn "pm2 not found. Installing globally..."
    npm install -g pm2 || fail "Failed to install PM2. Try: sudo npm install -g pm2"
    success "pm2 installed"
fi

# Check for setcap
if command -v setcap &>/dev/null; then
    success "setcap found"
else
    warn "setcap not found. Install with: sudo apt install libcap2-bin"
    warn "You will need to run the IDS with sudo instead."
fi

echo ""

#compile C++ Engine 

step "Step 2/6 — Compiling C++ IDS engine..."

g++ -O3 "$PROJECT_DIR/src/main.cpp" -o "$PROJECT_DIR/mini_ids" -lpcap \
    && success "Compiled mini_ids with -O3 optimization" \
    || fail "Compilation failed. Check that libpcap-dev is installed."

echo ""

# set Network Capabilities

step "Step 3/6 — Setting network capabilities..."

if command -v setcap &>/dev/null; then
    echo -e "  ${YELLOW}This step requires sudo to allow packet capture without root.${NC}"
    sudo setcap cap_net_raw,cap_net_admin=eip "$PROJECT_DIR/mini_ids" \
        && success "Capabilities set: cap_net_raw,cap_net_admin" \
        || warn "Failed to set capabilities. You may need to run mini_ids with sudo."
else
    warn "Skipping — setcap not available."
fi

echo ""

#Create Logs Directory

step "Step 4/6 — Preparing logs directory..."

mkdir -p "$PROJECT_DIR/logs"
# The logs dir may be owned by root from a previous sudo run of the IDS.
# Reclaim ownership so the IDS and dashboard can write to it.
if [ ! -w "$PROJECT_DIR/logs" ] || ([ -f "$PROJECT_DIR/logs/alerts.json" ] && [ ! -w "$PROJECT_DIR/logs/alerts.json" ]); then
    warn "Fixing logs/ permissions (requires sudo)..."
    sudo chown -R "$(whoami):$(whoami)" "$PROJECT_DIR/logs"
fi
chmod 755 "$PROJECT_DIR/logs"
# Create alerts.json if it doesn't exist
touch "$PROJECT_DIR/logs/alerts.json"
chmod 644 "$PROJECT_DIR/logs/alerts.json"
success "logs/ directory ready"

echo ""

# Install Node Dependencies 

step "Step 5/6 — Installing Node.js dependencies..."

(cd "$PROJECT_DIR/dashboard/backend" && npm install --production) \
    && success "Dependencies installed" \
    || fail "npm install failed"

echo ""

#Start with PM2 

step "Step 6/6 — Starting services with PM2..."

# Stop any existing instances
pm2 delete ecosystem.config.js 2>/dev/null || true

# Start fresh
(cd "$PROJECT_DIR" && pm2 start ecosystem.config.js) \
    && success "Services started" \
    || fail "PM2 failed to start services"

# Save PM2 process list (survives reboot with pm2 startup)
pm2 save --force
success "PM2 process list saved"

echo ""

#  Make logrotate executable 

chmod +x "$PROJECT_DIR/scripts/logrotate.sh" 2>/dev/null || true

#  Summary 

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  Deployment Complete!${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}Dashboard:${NC}      http://localhost:3000"
echo -e "  ${BOLD}API Health:${NC}     http://localhost:3000/api/health"
echo -e "  ${BOLD}View Processes:${NC}  pm2 list"
echo -e "  ${BOLD}View Logs:${NC}      pm2 logs"
echo -e "  ${BOLD}Stop All:${NC}       pm2 stop all"
echo -e "  ${BOLD}Restart All:${NC}    pm2 restart all"
echo ""
echo -e "  ${YELLOW}Optional — Auto-start on reboot:${NC}"
echo -e "    pm2 startup"
echo ""
echo -e "  ${YELLOW}Optional — Log rotation cron (every hour):${NC}"
echo -e "    crontab -e"
echo -e "    0 * * * * $PROJECT_DIR/scripts/logrotate.sh"
echo ""

pm2 list
