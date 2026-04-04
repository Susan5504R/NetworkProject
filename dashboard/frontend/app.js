const API_URL = 'http://localhost:3000/api/alerts';

async function fetchAlerts() {
    try {
        const response = await fetch(API_URL);
        const alerts = await response.json();

        //update stats
        updateStats(alerts);

        //update table
        renderTable(alerts);
    } catch (error) {
        console.error('Error fetching alerts:', error);
    }
}

function updateStats(alerts) {
    const totalAlerts = alerts.length;
    const portScans = alerts.filter(a => a.type === 'Port Scan').length;
    const synFloods = alerts.filter(a => a.type === 'SYN Flood').length;
    const arpSpoofs = alerts.filter(a => a.type === 'ARP Spoofing').length;
    const scanViolations = alerts.filter(a =>
        a.type === 'Null Scan' || a.type === 'Xmas Scan' || a.type === 'Protocol Violation'
    ).length;

    document.getElementById('total-alerts').textContent = totalAlerts;
    document.getElementById('port-scans').textContent = portScans;
    document.getElementById('syn-floods').textContent = synFloods;
    document.getElementById('arp-spoofs').textContent = arpSpoofs;
    document.getElementById('scan-violations').textContent = scanViolations;
}

function renderTable(alerts) {
    const tbody = document.getElementById('alerts-table');
    tbody.innerHTML = '';

    //reverse because latest first then older ones
    const reversedAlerts = [...alerts].reverse();

    reversedAlerts.forEach(alert => {
        const row = document.createElement('tr');

        const typeMap = {
            'Port Scan': 'type-port-scan',
            'SYN Flood': 'type-syn-flood',
            'ARP Spoofing': 'type-arp-spoof',
            'Null Scan': 'type-scan-violation',
            'Xmas Scan': 'type-scan-violation',
            'Protocol Violation': 'type-scan-violation'
        };
        const typeClass = typeMap[alert.type] || 'type-syn-flood';

        row.innerHTML = `
            <td>${alert.timestamp}</td>
            <td><span class="alert-type ${typeClass}">${alert.type}</span></td>
            <td>${alert.src_ip}</td>
            <td>${alert.details}</td>
        `;

        tbody.appendChild(row);
    });
}

//initial fetch this is required you forgot it
fetchAlerts();

//polling every 2 secs
setInterval(fetchAlerts, 2000);

//slider 
async function updateThreshold() {
    const val = document.getElementById('threshold-slider').value;
    try {
        await fetch('http://localhost:3000/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ threshold: parseInt(val) })
        });
        document.getElementById('threshold-val').textContent = val;
        alert("Threshold updated!");
    } catch (e) { console.error("Update failed", e); }
}

// Update the number display as you slide
document.getElementById('threshold-slider').oninput = function () {
    document.getElementById('threshold-val').textContent = this.value;
};
