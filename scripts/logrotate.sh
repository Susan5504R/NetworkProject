#!/usr/bin/env bash
#rotates logs/alerts.json to prevent unbounded growth.
#keeps the last 5 rotations, compresses old ones with gzip.
# usage:
#./scripts/logrotate.sh
#Cron (every hour):
# 0 * * * * /home/sarah/Desktop/NetworkProject/scripts/logrotate.sh

set -euo pipefail

# resolve the project root (one level up from this script)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

LOG_DIR="$PROJECT_DIR/logs"
LOG_FILE="$LOG_DIR/alerts.json"
MAX_ROTATIONS=5
# rotate when file exceeds 5 MB
MAX_SIZE_BYTES=$((5 * 1024 * 1024))

#create logs directory
mkdir -p "$LOG_DIR"

#if no log file found then exit
if [[ ! -f "$LOG_FILE" ]] || [[ ! -s "$LOG_FILE" ]]; then
    echo "[logrotate] Nothing to rotate."
    exit 0
fi

#check file size
FILE_SIZE=$(stat -c%s "$LOG_FILE" 2>/dev/null || stat -f%z "$LOG_FILE" 2>/dev/null)
if (( FILE_SIZE < MAX_SIZE_BYTES )); then
    echo "[logrotate] File is ${FILE_SIZE} bytes (< ${MAX_SIZE_BYTES}). Skipping."
    exit 0
fi

echo "[logrotate] Rotating $LOG_FILE (${FILE_SIZE} bytes)..."

#remove the oldest rotation
if [[ -f "$LOG_FILE.$MAX_ROTATIONS.gz" ]]; then
    rm -f "$LOG_FILE.$MAX_ROTATIONS.gz"
fi

#shift existing rotations up by 1
for (( i = MAX_ROTATIONS - 1; i >= 1; i-- )); do
    next=$(( i + 1 ))
    if [[ -f "$LOG_FILE.$i.gz" ]]; then
        mv "$LOG_FILE.$i.gz" "$LOG_FILE.$next.gz"
    fi
done

# move current log to .1 and compress
mv "$LOG_FILE" "$LOG_FILE.1"
gzip "$LOG_FILE.1"

# create a fresh empty log file
touch "$LOG_FILE"

echo "[logrotate] Done. Rotated to $LOG_FILE.1.gz"
