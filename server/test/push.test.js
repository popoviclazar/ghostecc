import test from 'node:test';
import assert from 'node:assert/strict';
import http2 from 'node:http2';
import { generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { RelayStore, RelayError, authMessage, sendDigestInput, notifyDigestInput, sha256hex } from '../src/relay.js';
import { ApnsClient, Pusher } from '../src/apns.js';

const ORIGIN = 'https://relay.example.com';
const TOKEN = 'ab'.repeat(32);

function keyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { privateKey, raw: Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url') };
}
function auth(store, key, op, queueId, input) {
  const timestamp = store.now();
  const nonce = randomBytes(16).toString('base64url');
  const signature = sign(null, authMessage(store.origin, op, queueId, timestamp, nonce, sha256hex(input)), key.privateKey);
  return { timestamp, nonce, signature: signature.toString('base64') };
}
function create(store) {
  const key = keyPair();
  return { key, ...store.createQueue({ recipientKey: key.raw.toString('base64'), auth: auth(store, key, 'create', '-', key.raw) }) };
}
function notifyBody(store, queues, token, environment = 'sandbox', signer) {
  const input = notifyDigestInput(token, environment);
  return { token, environment, queues: queues.map((q) => ({ recipientId: q.recipientId, auth: auth(store, signer ?? q.key, 'notify', q.recipientId, input) })) };
}
function send(store, queue, sender, message) {
  const expiresAt = store.now() + 60_000;
  return store.send(queue.senderId, { message: message.toString('base64'), expiresAt, senderKey: sender.raw.toString('base64'),
    auth: auth(store, sender, 'send', queue.senderId, sendDigestInput(message, expiresAt, sender.raw)) });
}

test('notify digest vector matches the Swift client', () => {
  assert.equal(notifyDigestInput('ab', 'sandbox').toString(), 'ab|sandbox');
  assert.equal(notifyDigestInput(null, 'production').toString(), '|production');
});

test('push registration is signed per queue, RAM-only and removable', () => {
  const store = new RelayStore({ origin: ORIGIN });
  const a = create(store), b = create(store);
  const stranger = keyPair();
  assert.deepEqual(store.notify(notifyBody(store, [a], TOKEN, 'sandbox', stranger)).queues[0].status, 'unauthorized');
  assert.equal(store.pushTarget(a.recipientId), null);
  assert.deepEqual(store.notify(notifyBody(store, [a, b], TOKEN)).queues.map((q) => q.status), ['ok', 'ok']);
  assert.deepEqual(store.pushTarget(a.recipientId), { token: TOKEN, environment: 'sandbox' });
  assert.ok(!JSON.stringify(store.snapshot()).includes(TOKEN), 'device token must not be persisted');
  store.notify(notifyBody(store, [b], null));
  assert.equal(store.pushTarget(b.recipientId), null);
  store.deleteQueue({ recipientId: a.recipientId, auth: auth(store, a.key, 'delete', a.recipientId, Buffer.alloc(0)) });
  assert.equal(store.pushTargets.size, 0);
  for (const bad of [{ token: 'XYZ' }, { environment: 'staging' }]) {
    const body = { ...notifyBody(store, [b], TOKEN), ...bad };
    assert.throws(() => store.notify(body), (error) => error instanceof RelayError && error.status === 400);
  }
});

test('onMessage fires once per new message, not for duplicates', () => {
  const store = new RelayStore({ origin: ORIGIN });
  const queue = create(store);
  const sender = keyPair();
  const seen = [];
  store.onMessage = (id) => seen.push(id);
  const message = randomBytes(20);
  send(store, queue, sender, message);
  send(store, queue, sender, message);
  assert.deepEqual(seen, [queue.recipientId]);
});

test('pusher coalesces bursts per device and respects the interval', async () => {
  let now = 1_000_000;
  const timers = [];
  const sent = [];
  const store = new RelayStore({ origin: ORIGIN, now: () => now });
  const a = create(store), b = create(store);
  store.notify(notifyBody(store, [a, b], TOKEN));
  const pusher = new Pusher({ store, now: () => now, intervalMs: 15_000, setTimer: (fn, ms) => { timers.push({ fn, ms }); return {}; },
    send: async (token, env) => { sent.push([token, env]); return { status: 200 }; } });
  for (let i = 0; i < 5; i += 1) { pusher.messageArrived(a.recipientId); pusher.messageArrived(b.recipientId); }
  assert.equal(timers.length, 1);
  assert.equal(timers[0].ms, 0);
  await timers[0].fn();
  assert.deepEqual(sent, [[TOKEN, 'sandbox']]);
  now += 1_000;
  pusher.messageArrived(a.recipientId);
  assert.equal(timers.length, 2);
  assert.equal(timers[1].ms, 14_000);
});

test('pusher tries the other environment on BadDeviceToken and drops dead tokens', async () => {
  const store = new RelayStore({ origin: ORIGIN });
  const a = create(store), b = create(store);
  store.notify(notifyBody(store, [a], TOKEN, 'production'));
  const other = 'cd'.repeat(32);
  store.notify(notifyBody(store, [b], other, 'sandbox'));
  const calls = [];
  const pusher = new Pusher({ store, setTimer: (fn) => { fn(); return {}; }, send: async (token, env) => {
    calls.push(`${token.slice(0, 2)}:${env}`);
    if (token === TOKEN) return env === 'sandbox' ? { status: 200 } : { status: 400, reason: 'BadDeviceToken' };
    return { status: 410, reason: 'Unregistered' };
  } });
  await pusher.deliver(TOKEN);
  assert.deepEqual(store.pushTarget(a.recipientId), { token: TOKEN, environment: 'sandbox' });
  await pusher.deliver(other);
  assert.equal(store.pushTarget(b.recipientId), null);
  assert.deepEqual(calls, ['ab:production', 'ab:sandbox', 'cd:sandbox']);
  assert.deepEqual(pusher.stats, { sent: 1, dropped: 1, failed: 0 });
});

test('APNs client: HTTP/2 request, headers, ES256 JWT and content-free payload', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const received = [];
  let reply = { status: 200, body: '' };
  const server = http2.createServer();
  server.on('stream', (stream, headers) => {
    let body = '';
    stream.on('data', (chunk) => { body += chunk; });
    stream.on('end', () => {
      received.push({ headers, body });
      stream.respond({ ':status': reply.status });
      stream.end(reply.body);
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const client = new ApnsClient({ keyPem: privateKey.export({ format: 'pem', type: 'pkcs8' }), keyId: 'ABC123DEFG', teamId: 'TEAM123456',
    topic: 'net.ghostecc.app', origins: { production: origin, sandbox: origin } });
  try {
    assert.deepEqual(await client.send(TOKEN, 'sandbox'), { status: 200, reason: '' });
    const { headers, body } = received[0];
    assert.equal(headers[':path'], `/3/device/${TOKEN}`);
    assert.equal(headers['apns-topic'], 'net.ghostecc.app');
    assert.equal(headers['apns-push-type'], 'alert');
    assert.equal(headers['apns-collapse-id'], 'ghost-new-message');
    assert.deepEqual(JSON.parse(body), { aps: { alert: { 'loc-key': 'PUSH_NEW_MESSAGE' }, sound: 'default' } });
    const [h, c, s] = headers.authorization.replace('bearer ', '').split('.');
    assert.deepEqual(JSON.parse(Buffer.from(h, 'base64url')), { alg: 'ES256', kid: 'ABC123DEFG' });
    assert.equal(JSON.parse(Buffer.from(c, 'base64url')).iss, 'TEAM123456');
    assert.ok(verify('sha256', Buffer.from(`${h}.${c}`), { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(s, 'base64url')));
    reply = { status: 410, body: JSON.stringify({ reason: 'Unregistered' }) };
    assert.deepEqual(await client.send(TOKEN, 'production'), { status: 410, reason: 'Unregistered' });
    const before = client.jwt();
    reply = { status: 403, body: JSON.stringify({ reason: 'ExpiredProviderToken' }) };
    await client.send(TOKEN, 'sandbox');
    assert.equal(client.cachedJwt, null);
    assert.ok(before);
  } finally {
    client.close();
    await new Promise((resolve) => server.close(resolve));
  }
});

test('APNs client rejects malformed configuration', () => {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const keyPem = privateKey.export({ format: 'pem', type: 'pkcs8' });
  assert.throws(() => new ApnsClient({ keyPem, keyId: 'short', teamId: 'TEAM123456', topic: 'net.ghostecc.app' }));
  assert.throws(() => new ApnsClient({ keyPem, keyId: 'ABC123DEFG', teamId: 'TEAM123456', topic: 'bad topic' }));
  const ed = generateKeyPairSync('ed25519').privateKey.export({ format: 'pem', type: 'pkcs8' });
  assert.throws(() => new ApnsClient({ keyPem: ed, keyId: 'ABC123DEFG', teamId: 'TEAM123456', topic: 'net.ghostecc.app' }));
});
