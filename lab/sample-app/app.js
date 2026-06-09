const http = require('http');

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    app: 'dpff-sample-app',
    version: '1.0.0',
    status: 'healthy',
    timestamp: new Date().toISOString()
  }));
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`Sample app running on port ${PORT}`);
});
