import fs from 'node:fs';
import path from 'node:path';
import { RelayStore, VERSION } from './relay.js';
import { createRelayServer, RateLimiter } from './http.js';
import { ApnsClient, Pusher } from './apns.js';

const major = Number(process.versions.node.split('.')[0]);
if (major < 20) { console.error('ghost-relay needs Node.js 20 or newer'); process.exit(1); }

function fail(message) { console.error(`ghost-relay: ${message}`); process.exit(1); }

const origin = process.env.GHOST_ORIGIN;
if (!origin) fail('set GHOST_ORIGIN to the public https origin, for example https://relay.example.com');
const [host, portText] = (process.env.GHOST_LISTEN ?? '127.0.0.1:8080').split(/:(?=\d+$)/);
const port = Number(portText);
if (!host || !Number.isInteger(port) || port < 1 || port > 65_535) fail('GHOST_LISTEN must look like 127.0.0.1:8080');
const dataDir = path.resolve(process.env.GHOST_DATA_DIR ?? './data');
const memoryMb = Number(process.env.GHOST_MAX_MEMORY_MB ?? 1024);
if (!Number.isFinite(memoryMb) || memoryMb < 16) fail('GHOST_MAX_MEMORY_MB must be at least 16');

let store;
try {
  store = new RelayStore({ origin, limits: { maxMemoryBytes: Math.floor(memoryMb * 1024 * 1024) } });
} catch (error) { fail(error.message); }

const stateFile = path.join(dataDir, 'queues.json');
fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
if (fs.existsSync(stateFile)) {
  try { store.restore(JSON.parse(fs.readFileSync(stateFile, 'utf8'))); } catch (error) { fail(`cannot read ${stateFile}: ${error.message}`); }
}

// Atomic write: temp file, fsync, rename. Contains queue IDs and public keys only.
function persist() {
  if (!store.dirty) return;
  store.dirty = false;
  const temp = `${stateFile}.tmp`;
  try {
    const fd = fs.openSync(temp, 'w', 0o600);
    try { fs.writeSync(fd, JSON.stringify(store.snapshot())); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(temp, stateFile);
    try { const dir = fs.openSync(dataDir, 'r'); fs.fsyncSync(dir); fs.closeSync(dir); } catch { /* best effort */ }
  } catch (error) {
    store.dirty = true;
    console.error(`ghost-relay: state write failed: ${error.code ?? 'error'}`);
  }
}

// Push notifications are optional: enabled when an APNs key is configured (see deploy/install.sh --apns-key).
let pusher = null;
let apns = null;
const credentials = process.env.CREDENTIALS_DIRECTORY;
const keyFile = process.env.GHOST_APNS_KEY_FILE || (credentials ? path.join(credentials, 'apns.p8') : '');
if (keyFile && fs.existsSync(keyFile)) {
  try {
    apns = new ApnsClient({
      keyPem: fs.readFileSync(keyFile, 'utf8'),
      keyId: process.env.GHOST_APNS_KEY_ID,
      teamId: process.env.GHOST_APNS_TEAM_ID,
      topic: process.env.GHOST_APNS_TOPIC,
    });
    pusher = new Pusher({ store, send: (token, environment) => apns.send(token, environment), log: (message) => console.error(`ghost-relay: ${message}`) });
    store.onMessage = (recipientId) => pusher.messageArrived(recipientId);
  } catch (error) { fail(`APNs: ${error.message}`); }
}

const limiter = new RateLimiter();
const server = createRelayServer(store, {
  trustProxy: process.env.GHOST_TRUST_PROXY === '1',
  limiter,
  log: (message) => console.error(`ghost-relay: ${message}`),
});
const persistTimer = setInterval(persist, 2_000);
const maintenanceTimer = setInterval(() => { store.maintenance(); limiter.sweep(); pusher?.sweep(); }, 30_000);

function shutdown() {
  clearInterval(persistTimer);
  clearInterval(maintenanceTimer);
  server.close();
  apns?.close();
  persist();
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

server.listen(port, host, () => {
  console.log(`ghost-relay ${VERSION} listening on ${host}:${port} for ${store.origin}; ${store.queues.size} queues restored, messages are RAM-only, push ${pusher ? `on (${process.env.GHOST_APNS_TOPIC})` : 'off'}`);
});
