const API_URL = 'http://localhost:3000/api/alerts';

async function fetchAlerts() {
    try {
        const response = await fetch(API_URL);
        const alerts = await response.json();

        // Update stats
        updateStats(alerts);

        // Update table
        renderTable(alerts);
    } catch (error) {
        console.error('Error fetching alerts:', error);
    }
}

function updateStats(alerts) {
    const totalAlerts = alerts.length;
    const portScans = alerts.filter(a => a.type === 'Port Scan').length;
    const synFloods = alerts.filter(a => a.type === 'SYN Flood').length;

    document.getElementById('total-alerts').textContent = totalAlerts;
    document.getElementById('port-scans').textContent = portScans;
    document.getElementById('syn-floods').textContent = synFloods;
}

function renderTable(alerts) {
    const tbody = document.getElementById('alerts-table');
    tbody.innerHTML = '';

    // Show latest alerts first
    const reversedAlerts = [...alerts].reverse();

    reversedAlerts.forEach(alert => {
        const row = document.createElement('tr');

        const typeClass = alert.type === 'Port Scan' ? 'type-port-scan' : 'type-syn-flood';

        row.innerHTML = `
            <td>${alert.timestamp}</td>
            <td><span class="alert-type ${typeClass}">${alert.type}</span></td>
            <td>${alert.src_ip}</td>
            <td>${alert.details}</td>
        `;

        tbody.appendChild(row);
    });
}

// Initial fetch
fetchAlerts();

// Poll every 2 seconds
setInterval(fetchAlerts, 2000);
