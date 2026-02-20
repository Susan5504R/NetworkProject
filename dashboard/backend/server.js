const express = require('express');
const cors = require('cors');
const fs = require('fs');
const app = express();
const path = require('path');

app.use(cors());
app.use(express.json());

// Config path for dynamic settings (read by C++ IDS)
const configPath = path.join(__dirname, '../../config.json');

app.post('/api/settings', (req, res) => {
    const newConfig = JSON.stringify(req.body);
    fs.writeFile(configPath, newConfig, (err) => {
        if (err) return res.status(500).json({ error: "Failed to save config" });
        res.json({ message: "Config updated" });
    });
});

// Path to the logs directory, relative to where server.js is run (dashboard/backend/)
// Assuming logs/alerts.json is at ../../logs/alerts.json from here?
// NO, user said "const logPath = '../logs/alerts.json'; // Adjust path based on your folder structure"
// My structure:
// Project/
//   logs/alerts.json
//   dashboard/backend/server.js
// So logPath should be '../../logs/alerts.json'

const logPath = path.join(__dirname, '../../logs/alerts.json');

app.get('/api/alerts', (req, res) => {
    fs.readFile(logPath, 'utf8', (err, data) => {
        if (err) {
            console.error("Error reading log file:", err);
            // If file doesn't exist, return empty array instead of error?
            if (err.code === 'ENOENT') {
                return res.json([]);
            }
            return res.status(500).json({ error: "Could not read logs" });
        }

        try {
            // The C++ file appends JSON line by line.
            // Filter out empty lines to avoid parse errors.
            const logs = data.trim().split('\n')
                .filter(line => line.trim() !== '')
                .map(line => {
                    try {
                        return JSON.parse(line);
                    } catch (e) {
                        console.error("Error parsing line:", line, e);
                        return null;
                    }
                })
                .filter(item => item !== null); // Filter out failed parses

            res.json(logs);
        } catch (e) {
            console.error("Error processing logs:", e);
            res.status(500).json({ error: "Error parsing logs" });
        }
    });
});

const PORT = 3000;
app.listen(PORT, () => console.log(`IDS API running on port ${PORT}`));
