# Mini IDS/IPS — Network Intrusion Detection & Prevention System

A real-time Intrusion Detection and Prevention System built from scratch in C++ using raw packet capture (`libpcap`). Detects 9 attack types across OSI Layers 2–5, automatically blocks malicious IPs via `iptables`, and streams alerts to a live web dashboard.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Network Traffic                           │
└────────────────────────────┬─────────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                  C++ IDS/IPS Engine (libpcap)                    │
│                                                                  │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐     │
│   │ Ethernet │→ │    IP    │→ │ TCP/UDP/ │→ │   Payload    │     │
│   │ Parser   │  │  Parser  │  │   ICMP   │  │  Inspector   │     │
│   │  (L2)    │  │  (L3)    │  │  (L4)    │  │    (L5)      │     │
│   └──────────┘  └──────────┘  └──────────┘  └──────────────┘     │
│                                                                  │
│   ┌──────────────────────┐    ┌──────────────────────────────┐   │
│   │  Detection Engine    │    │   IPS: iptables Blocking     │   │
│   │  (9 attack types)    │───▶│   (automatic IP ban)         │   │
│   └──────────────────────┘    └──────────────────────────────┘   │
│                │                                                 │
│                ▼                                                 │
│   ┌──────────────────────┐                                       │
│   │  logs/alerts.json    │  ◄── JSON-line format                 │
│   └──────────┬───────────┘                                       │
└──────────────┼───────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────────┐
│              Node.js / Express Backend API                       │
│                                                                  │
│   GET  /api/alerts   — returns parsed alerts as JSON array       │
│   POST /api/settings — updates detection sensitivity             │
│   GET  /api/health   — service health check                      │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│                   Web Dashboard (Frontend)                       │
│                                                                  │
│   ┌─────────────┐  ┌─────────────┐  ┌────────────────────────┐   │
│   │  Live Stats │  │ Sensitivity │  │   Alert Table          │   │
│   │  Cards      │  │   Slider    │  │   (auto-refresh 2s)    │   │
│   └─────────────┘  └─────────────┘  └────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

---

## Attack Detections

| # | Attack | OSI Layer | Detection Method |
|---|--------|-----------|------------------|
| 1 | **Port Scan** | L4 (TCP) | Tracks unique destination ports per source IP within a time window |
| 2 | **SYN Flood** | L4 (TCP) | Stateful tracking of half-open connections; alerts on stale SYNs |
| 3 | **ICMP Flood** | L3 (ICMP) | Rate-limiting ECHO requests per source IP (threshold: 50/sec) |
| 4 | **Null Scan** | L4 (TCP) | Detects TCP packets with no flags set |
| 5 | **Xmas Scan** | L4 (TCP) | Detects FIN+PSH+URG flag combination |
| 6 | **SYN+FIN Violation** | L4 (TCP) | Detects illegal simultaneous SYN and FIN flags |
| 7 | **ARP Spoofing** | L2 (Ethernet) | Tracks IP-to-MAC mappings; alerts on unexpected changes |
| 8 | **SQL Injection** | L5 (Payload) | Deep Packet Inspection for patterns like `' OR 1=1`, `UNION SELECT` |
| 9 | **XSS Attack** | L5 (Payload) | Deep Packet Inspection for `<script>` and `alert()` patterns |

**IPS Response:** All severe attacks trigger automatic IP blocking via `iptables -A INPUT -s <IP> -j DROP`.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Packet Engine | C++17, libpcap |
| IP Blocking | iptables (Linux) |
| Backend API | Node.js, Express |
| Frontend | HTML5, CSS3, JavaScript |
| Process Manager | PM2 |
| Build System | CMake / g++ |
| Testing | Bash, hping3, nmap, arping, curl |

---

## Project Structure

```
NetworkProject/
├── src/
│   └── main.cpp              # C++ IDS/IPS engine (packet capture + detection + blocking)
├── dashboard/
│   ├── backend/
│   │   └── server.js          # Express API (alerts, settings, health)
│   └── frontend/
│       ├── index.html         # Dashboard UI
│       ├── style.css          # Dark theme styling
│       └── app.js             # Live polling + stats + settings
├── tests/
│   ├── test_all.sh            # Master test runner
│   ├── test_ids_attacks.sh    # 9 attack simulations
│   └── test_backend_api.sh   # 5 API endpoint tests
├── scripts/
│   └── logrotate.sh           # Log rotation utility
├── deploy.sh                  # One-command deployment script
├── ecosystem.config.js        # PM2 process configuration
├── config.json                # Runtime detection thresholds
├── CMakeLists.txt             # CMake build configuration
└── README.md
```

---

## Quick Start

### 🐳 Run with Docker (Recommended)
The easiest way to run the project without installing C++ dependencies is via Docker.
1. Run `docker-compose up --build` or `sudo docker-compose up --build`
2. Open [http://localhost:3000](http://localhost:3000) to view the Dashboard.
3. Open a new terminal and run an attack (e.g., `nmap -Pn -sT -F 127.0.0.1`) to see live alerts.

### Prerequisites

- **Linux** (Ubuntu/Debian recommended)
- `g++` (C++17 support)
- `libpcap-dev` — `sudo apt install libpcap-dev`
- `Node.js` (v16+) and `npm`
- `PM2` — `npm install -g pm2`

### One-Command Deployment

```bash
chmod +x deploy.sh && ./deploy.sh
```

This will:
1. Check all dependencies
2. Compile the C++ engine with `-O3` optimization
3. Set network capabilities (`cap_net_raw`)
4. Create the logs directory
5. Install Node.js dependencies
6. Start all services via PM2

### Manual Build & Run

```bash
# Compile
g++ -O3 src/main.cpp -o mini_ids -lpcap

# Set capabilities (avoid running as root)
sudo setcap cap_net_raw,cap_net_admin=eip ./mini_ids

# Start the IDS engine
./mini_ids

# Start the dashboard (in another terminal)
cd dashboard/backend && npm install && node server.js
```

**Dashboard:** [http://localhost:3000](http://localhost:3000)

---

## Testing

### ⚠️ Important: Resetting the Firewall
Because the IPS automatically blocks malicious IPs using `iptables`, testing attacks on `127.0.0.1` will eventually block your local traffic, causing the dashboard to stop responding.

To unblock IPs and reset your firewall after testing, run:
\`\`\`bash
# Flush all iptables rules (use with caution on production servers)
sudo iptables -F
\`\`\`

### Run All Tests

```bash
# API tests (no sudo needed, backend must be running)
bash tests/test_backend_api.sh

# Attack simulation tests (requires sudo + IDS running)
sudo bash tests/test_ids_attacks.sh

# Both suites
sudo bash tests/test_all.sh
```

### Manual Attack Simulation

You can also test each detection individually. Make sure the IDS engine is running first (`sudo ./mini_ids`).

**Install simulation tools:**

```bash
sudo apt install hping3 nmap arping curl
```

**1. Port Scan**

```bash
nmap -p 1-100 127.0.0.1
```

**2. SYN Flood**

```bash
# Flood SYN packets to port 80 for 3 seconds
sudo timeout 3 hping3 -S --flood -p 80 127.0.0.1
# Wait ~15s for stale connection detection to trigger
```

**3. ICMP Flood**

```bash
sudo timeout 3 hping3 --icmp --flood 127.0.0.1
```

**4. Null Scan** (no TCP flags)

```bash
sudo hping3 -c 5 -p 80 127.0.0.1
```

**5. Xmas Scan** (FIN+PSH+URG)

```bash
sudo nmap -sX -p 80 127.0.0.1
```

**6. SYN+FIN Protocol Violation**

```bash
sudo hping3 -c 5 -S -F -p 80 127.0.0.1
```

**7. ARP Spoofing**

```bash
# Replace <iface> with your network interface (e.g., eth0, wlan0)
# Replace <gateway_ip> with your gateway (e.g., 192.168.1.1)
sudo arping -c 3 -I <iface> <gateway_ip>
```

**8. SQL Injection** (payload inspection)

```bash
curl "http://127.0.0.1:3000/api/alerts?q=%27%20OR%201%3D1"
```

**9. XSS Attack** (payload inspection)

```bash
curl "http://127.0.0.1:3000/api/alerts?q=%3Cscript%3Ealert(1)%3C/script%3E"
```

After each command, check `logs/alerts.json` or the dashboard at `http://localhost:3000` for the alert.

---

## Using the Dashboard
1. **Monitor Live Traffic:** The alert table auto-updates every 2 seconds. You do not need to refresh the page.
2. **Adjust Sensitivity:** Use the slider at the top to change the Port Scan threshold dynamically. Lower it to `5` to catch stealthy scans, or raise it to `50` to reduce noise. The C++ engine updates instantly without restarting.

## Accessing the Dashboard

Once the deployment script or Docker container is running, the Node.js backend serves the web interface on port 3000.

**To view the dashboard:**
1. Open your favorite web browser (Chrome, Firefox, Safari).
2. Navigate to: [http://localhost:3000](http://localhost:3000) or `http://127.0.0.1:3000`

*Note: The dashboard auto-refreshes every 2 seconds, so you can keep this tab open side-by-side with your terminal while you simulate attacks.*

## Dashboard Features

- **Live Alert Feed** — auto-refreshes every 2 seconds
- **Stat Cards** — total alerts, port scans, SYN floods, ARP spoofs, scan violations
- **Sensitivity Slider** — adjust detection threshold at runtime (no restart needed)
- **Dark Theme** — terminal-inspired UI with JetBrains Mono font

---

## Configuration

Detection sensitivity is controlled via `config.json`:

```json
{"threshold": 20}
```

- Adjustable through the dashboard slider (5–100 ports)
- The C++ engine re-reads this file before every port scan check
- Lower values = more sensitive (more alerts), higher values = fewer false positives

---

**Troubleshooting the Dashboard:**
* **"Connection Refused":** Ensure the Node.js backend is actually running. If using Docker, check `docker logs <container_name>`.
* **Port in Use:** If you already have another app running on port 3000 (like a React app), the dashboard won't start. You can change the port in `dashboard/backend/server.js` and `docker-compose.yml`.


## Key Design Decisions

1. **Stateful SYN Flood Detection** — Instead of simply counting SYN packets, the engine tracks pending TCP handshakes and alerts when too many go uncompleted (stale for >10s), reducing false positives.

2. **Time-Windowed Port Scan Detection** — Unique ports are counted within a sliding time window (5s) rather than cumulatively, preventing alert fatigue from normal traffic.

3. **Whitelisted Ports** — Ports 80, 443, and 53 are excluded from port scan detection to avoid flagging legitimate web/DNS traffic.

4. **JSON-Line Logging** — Alerts are appended as individual JSON objects (one per line) so the log file can be streamed and parsed incrementally without loading the entire file.

---

## License

This project was built for educational purposes as a network security demonstration.
