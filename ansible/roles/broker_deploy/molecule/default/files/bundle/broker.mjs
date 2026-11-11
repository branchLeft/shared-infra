// TEST STAND-IN for the broker bundle's entry point; never a broker artefact.
// It answers the one read the role waits on, GET /status/0, on the port the
// environment file names, and does nothing else. The container test uses it
// to prove the role starts the unit, waits for the answer and restarts on a
// changed release.
import { createServer } from 'node:http';

const port = Number(process.env.PORT);
const body = JSON.stringify({ slot: '0', phase: 'free', healthy: false });

createServer((request, response) => {
  if (request.method === 'GET' && request.url === '/status/0') {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(body);
    return;
  }
  response.writeHead(404);
  response.end();
}).listen(port, '127.0.0.1');
