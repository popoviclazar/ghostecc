import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { RelayStore, RelayError, authMessage, sendDigestInput, sha256hex, EMPTY_DIGEST, normalizeOrigin } from '../src/relay.js';
import { createRelayServer, RateLimiter } from '../src/http.js';

const ORIGIN = 'https://relay.example.com';

function keyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { privateKey, raw: Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url') };
}

function auth(store, key, op, queueId, digestInput, overrides = {}) {
  const timestamp = overrides.timestamp ?? store.now();
  const nonce = overrides.nonce ?? randomBytes(16).toString('base64url');
  const digest = digestInput === null ? EMPTY_DIGEST : sha256hex(digestInput);
  const signature = sign(null, authMessage(overrides.origin ?? store.origin, op, queueId, timestamp, nonce, digest), key.privateKey);
  return { timestamp, nonce, signature: signature.toString('base64') };
}

function create(store, invitation = null) {
  const key = keyPair();
  const input = invitation ? Buffer.concat([key.raw, invitation]) : key.raw;
  const body = { recipientKey: key.raw.toString('base64'), auth: auth(store, key, 'create', '-', input) };
  if (invitation) body.invitation = invitation.toString('base64');
  return { key, ...store.createQueue(body) };
}

function sendBody(store, key, senderId, message, { expiresAt = store.now() + 60_000, includeKey = true, overrides } = {}) {
  const senderKey = includeKey ? key.raw : null;
  const body = { message: message.toString('base64'), expiresAt, auth: auth(store, key, 'send', senderId, sendDigestInput(message, expiresAt, senderKey), overrides) };
  if (senderKey) body.senderKey = senderKey.toString('base64');
  return body;
}

function fetchBody(store, queues) {
  return { queues: queues.map(({ recipientId, key }) => ({ recipientId, auth: auth(store, key, 'fetch', recipientId, null) })) };
}

function ackBody(store, queue, ids) {
  return { recipientId: queue.recipientId, ids, auth: auth(store, queue.key, 'ack', queue.recipientId, Buffer.from(ids.join(','), 'utf8')) };
}

function code(fn) {
  try { fn(); } catch (error) { if (error instanceof RelayError) return `${error.status}:${error.code}`; throw error; }
  return 'ok';
}

test('protocol vector matches the Swift client test', () => {
  const digest = sha256hex(Buffer.from('hello'));
  assert.equal(digest, '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  assert.equal(authMessage(ORIGIN, 'fetch', 'Q', 1_700_000_000_000, 'N', digest).toString('utf8'),
    `GHOST-RELAY-v1\n${ORIGIN}\nfetch\nQ\n1700000000000\nN\n${digest}`);
  assert.equal(sendDigestInput(Buffer.from('ab'), 5, null).toString('utf8'), 'ab|5|');
});

test('origin normalization mirrors the client', () => {
  assert.equal(normalizeOrigin('HTTPS://Relay.Example.com/'), ORIGIN);
  assert.equal(normalizeOrigin('https://relay.example.com:443'), ORIGIN);
  assert.equal(normalizeOrigin('https://relay.example.com:8443'), 'https://relay.example.com:8443');
  for (const bad of ['http://relay.example.com', 'https://u:p@relay.example.com', 'https://relay.example.com/x', 'https://relay.example.com?a=1']) {
    assert.throws(() => normalizeOrigin(bad));
  }
});

test('one-time invitation: first sender secures the queue, others are rejected', () => {
  const store = new RelayStore({ origin: ORIGIN });
  const invitation = randomBytes(300);
  const queue = create(store, invitation);
  assert.equal(store.getInvitation(queue.senderId).invitation, invitation.toString('base64'));
  const alice = keyPair();
  assert.equal(store.send(queue.senderId, sendBody(store, alice, queue.senderId, Buffer.from('hello-1'))).status, 'accepted');
  assert.equal(code(() => store.getInvitation(queue.senderId)), '404:not_found');
  const mallory = keyPair();
  assert.equal(code(() => store.send(queue.senderId, sendBody(store, mallory, queue.senderId, Buffer.from('xyz')))), '401:unauthorized');
  assert.equal(code(() => store.send(queue.senderId, sendBody(store, mallory, queue.senderId, Buffer.from('xyz'), { includeKey: false }))), '401:unauthorized');
  // Alice may keep sending with or without repeating her key.
  assert.equal(store.send(queue.senderId, sendBody(store, alice, queue.senderId, Buffer.from('hello-2'), { includeKey: false })).status, 'accepted');
  assert.equal(store.send(queue.senderId, sendBody(store, alice, queue.senderId, Buffer.from('hello-3'))).status, 'accepted');
});

test('unsecured queue without an offered key cannot be written', () => {
  const store = new RelayStore({ origin: ORIGIN });
  const queue = create(store);
  const alice = keyPair();
  assert.equal(code(() => store.send(queue.senderId, sendBody(store, alice, queue.senderId, Buffer.from('mmm'), { includeKey: false }))), '401:not_secured');
});

test('fetch, ack and delete require the recipient key; sender cannot read', () => {
  const store = new RelayStore({ origin: ORIGIN });
  const queue = create(store);
  const alice = keyPair();
  const accepted = store.send(queue.senderId, sendBody(store, alice, queue.senderId, Buffer.from('cipher')));
  const intruder = { recipientId: queue.recipientId, key: alice };
  assert.deepEqual(store.fetch(fetchBody(store, [intruder])), { queues: [{ recipientId: queue.recipientId, status: 'unauthorized' }], messages: [] });
  const result = store.fetch(fetchBody(store, [queue]));
  assert.equal(result.messages.length, 1);
  assert.equal(result.messages[0].id, accepted.id);
  assert.equal(Buffer.from(result.messages[0].message, 'base64').toString(), 'cipher');
  assert.equal(code(() => store.ack(ackBody(store, { ...queue, key: alice }, [accepted.id]))), '401:unauthorized');
  assert.deepEqual(store.ack(ackBody(store, queue, [accepted.id])), { removed: 1 });
  assert.deepEqual(store.ack(ackBody(store, queue, [accepted.id])), { removed: 0 });
  assert.equal(store.fetch(fetchBody(store, [queue])).messages.length, 0);
  store.deleteQueue({ recipientId: queue.recipientId, auth: auth(store, queue.key, 'delete', queue.recipientId, null) });
  assert.equal(store.fetch(fetchBody(store, [queue])).queues[0].status, 'not_found');
  assert.equal(code(() => store.send(queue.senderId, sendBody(store, alice, queue.senderId, Buffer.from('late')))), '404:not_found');
  assert.equal(store.totalBytes, 0);
});

test('replayed nonce, skewed clock, wrong origin and tampered body are rejected', () => {
  let now = 1_800_000_000_000;
  const store = new RelayStore({ origin: ORIGIN, now: () => now });
  const queue = create(store);
  const alice = keyPair();
  const body = sendBody(store, alice, queue.senderId, Buffer.from('once'));
  store.send(queue.senderId, body);
  assert.equal(code(() => store.send(queue.senderId, body)), '401:replay');
  const skewed = sendBody(store, alice, queue.senderId, Buffer.from('mmm'), { overrides: { timestamp: now - 200_000 } });
  assert.equal(code(() => store.send(queue.senderId, skewed)), '401:clock_skew');
  const otherServer = sendBody(store, alice, queue.senderId, Buffer.from('mmm'), { overrides: { origin: 'https://other.example.com' } });
  assert.equal(code(() => store.send(queue.senderId, otherServer)), '401:unauthorized');
  const tampered = sendBody(store, alice, queue.senderId, Buffer.from('original'));
  tampered.message = Buffer.from('modified').toString('base64');
  assert.equal(code(() => store.send(queue.senderId, tampered)), '401:unauthorized');
  const extended = sendBody(store, alice, queue.senderId, Buffer.from('mm2'));
  extended.expiresAt += 1000;
  assert.equal(code(() => store.send(queue.senderId, extended)), '401:unauthorized');
  now += 1;
});

test('messages expire in RAM and lifetime cannot exceed 24 hours', () => {
  let now = 1_800_000_000_000;
  const store = new RelayStore({ origin: ORIGIN, now: () => now });
  const queue = create(store);
  const alice = keyPair();
  store.send(queue.senderId, sendBody(store, alice, queue.senderId, Buffer.from('short'), { expiresAt: now + 5_000 }));
  assert.equal(code(() => store.send(queue.senderId, sendBody(store, alice, queue.senderId, Buffer.from('long'), { expiresAt: now + 2 * 86_400_000 }))), '400:bad_expiresAt');
  assert.equal(code(() => store.send(queue.senderId, sendBody(store, alice, queue.senderId, Buffer.from('past'), { expiresAt: now - 1 }))), '400:bad_expiresAt');
  now += 6_000;
  assert.equal(store.fetch(fetchBody(store, [queue])).messages.length, 0);
  assert.equal(store.totalBytes, 0);
});

test('size, queue and memory limits', () => {
  const store = new RelayStore({ origin: ORIGIN, limits: { maxMessageBytes: 100, maxQueueMessages: 2, maxMemoryBytes: 10_000 } });
  const queue = create(store);
  const alice = keyPair();
  assert.equal(code(() => store.send(queue.senderId, sendBody(store, alice, queue.senderId, randomBytes(200)))), '413:too_large');
  store.send(queue.senderId, sendBody(store, alice, queue.senderId, randomBytes(50)));
  store.send(queue.senderId, sendBody(store, alice, queue.senderId, randomBytes(50), { includeKey: false }));
  assert.equal(code(() => store.send(queue.senderId, sendBody(store, alice, queue.senderId, randomBytes(50), { includeKey: false }))), '429:queue_full');
  const small = new RelayStore({ origin: ORIGIN, limits: { maxMemoryBytes: 60 } });
  const q2 = create(small);
  small.send(q2.senderId, sendBody(small, alice, q2.senderId, randomBytes(50)));
  assert.equal(code(() => small.send(q2.senderId, sendBody(small, alice, q2.senderId, randomBytes(50), { includeKey: false }))), '503:capacity');
});

test('duplicate ciphertext is idempotent', () => {
  const store = new RelayStore({ origin: ORIGIN });
  const queue = create(store);
  const alice = keyPair();
  const message = randomBytes(40);
  const first = store.send(queue.senderId, sendBody(store, alice, queue.senderId, message));
  const retry = store.send(queue.senderId, sendBody(store, alice, queue.senderId, message));
  assert.equal(first.id, retry.id);
  assert.equal(store.stats().messages, 1);
});

test('fetch is round-robin so a flooded queue cannot starve others', () => {
  const store = new RelayStore({ origin: ORIGIN, limits: { maxFetchMessages: 4 } });
  const flooded = create(store);
  const quiet = create(store);
  const spammer = keyPair();
  const friend = keyPair();
  for (let i = 0; i < 20; i += 1) store.send(flooded.senderId, sendBody(store, spammer, flooded.senderId, randomBytes(20), { includeKey: i === 0 }));
  store.send(quiet.senderId, sendBody(store, friend, quiet.senderId, Buffer.from('important')));
  const result = store.fetch(fetchBody(store, [flooded, quiet]));
  assert.equal(result.messages.length, 4);
  assert.ok(result.messages.some((m) => m.recipientId === quiet.recipientId));
});

test('maintenance removes unused invitations and idle queues, persistence omits messages', () => {
  let now = 1_800_000_000_000;
  const store = new RelayStore({ origin: ORIGIN, now: () => now });
  const unused = create(store, randomBytes(64));
  const active = create(store);
  const alice = keyPair();
  const secret = Buffer.from('SECRET-CIPHERTEXT-SHOULD-NOT-PERSIST');
  store.send(active.senderId, sendBody(store, alice, active.senderId, secret));
  const snapshot = JSON.stringify(store.snapshot());
  assert.ok(!snapshot.includes(secret.toString('base64')));
  const restored = new RelayStore({ origin: ORIGIN, now: () => now });
  restored.restore(JSON.parse(snapshot));
  assert.equal(restored.queues.size, 2);
  assert.equal(restored.stats().messages, 0);
  assert.equal(restored.send(active.senderId, sendBody(restored, alice, active.senderId, Buffer.from('after restart'), { includeKey: false })).status, 'accepted');
  now += 8 * 86_400_000;
  store.fetch(fetchBody(store, [active]));
  assert.equal(store.maintenance().removedQueues, 1);
  assert.ok(!store.queues.has(unused.recipientId));
  now += 61 * 86_400_000;
  assert.equal(store.maintenance().removedQueues, 1);
  assert.equal(store.queues.size, 0);
});

test('strict base64 and identifiers', () => {
  const store = new RelayStore({ origin: ORIGIN });
  assert.equal(code(() => store.createQueue({ recipientKey: 'not base64!', auth: {} })), '400:bad_recipientKey');
  assert.equal(code(() => store.getInvitation('../../etc/passwd')), '404:not_found');
  assert.equal(code(() => store.fetch({ queues: [] })), '400:bad_queues');
  const queue = create(store);
  assert.equal(code(() => store.ack({ recipientId: queue.recipientId, ids: ['x'], auth: {} })), '400:bad_ids');
});

test('rate limiter refills over time', () => {
  let now = 0;
  const limiter = new RateLimiter({ now: () => now, perSecond: 1, burst: 2 });
  assert.ok(limiter.allow('a'));
  assert.ok(limiter.allow('a'));
  assert.ok(!limiter.allow('a'));
  assert.ok(limiter.allow('b'));
  now += 1000;
  assert.ok(limiter.allow('a'));
});

test('HTTP: complete two-party handshake and message exchange', async () => {
  const store = new RelayStore({ origin: ORIGIN });
  const server = createRelayServer(store, { limiter: new RateLimiter({ perSecond: 1000, burst: 1000 }) });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = async (path, body) => {
    const response = await fetch(base + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    return { status: response.status, body: await response.json() };
  };
  try {
    const health = await (await fetch(`${base}/v1/health`)).json();
    assert.equal(health.status, 'ok');
    assert.ok(Number.isSafeInteger(health.serverTime));

    // Inviter (Bob) creates a queue holding his encrypted bundle.
    const bob = keyPair();
    const bundle = randomBytes(2500);
    const created = await post('/v1/queues', { recipientKey: bob.raw.toString('base64'), invitation: bundle.toString('base64'), auth: auth(store, bob, 'create', '-', Buffer.concat([bob.raw, bundle])) });
    assert.equal(created.status, 200);
    const bobQueue = { ...created.body, key: bob };

    // Joiner (Alice) downloads the invitation, creates her own queue and sends hello, securing Bob's queue.
    const invitation = await (await fetch(`${base}/v1/invitations/${bobQueue.senderId}`)).json();
    assert.equal(invitation.invitation, bundle.toString('base64'));
    const alice = keyPair();
    const aliceCreated = await post('/v1/queues', { recipientKey: alice.raw.toString('base64'), auth: auth(store, alice, 'create', '-', alice.raw) });
    const aliceQueue = { ...aliceCreated.body, key: alice };
    const aliceSender = keyPair();
    const hello = randomBytes(1200);
    assert.equal((await post(`/v1/messages/${bobQueue.senderId}`, sendBody(store, aliceSender, bobQueue.senderId, hello))).status, 200);
    assert.equal((await fetch(`${base}/v1/invitations/${bobQueue.senderId}`)).status, 404);

    // Bob receives hello, replies "ready" into Alice's queue, securing it with his own sender key.
    const inbox = await post('/v1/fetch', fetchBody(store, [bobQueue]));
    assert.equal(inbox.body.messages.length, 1);
    assert.equal(inbox.body.messages[0].message, hello.toString('base64'));
    assert.deepEqual((await post('/v1/ack', ackBody(store, bobQueue, [inbox.body.messages[0].id]))).body.removed, 1);
    const bobSender = keyPair();
    const ready = randomBytes(1024);
    assert.equal((await post(`/v1/messages/${aliceQueue.senderId}`, sendBody(store, bobSender, aliceQueue.senderId, ready))).status, 200);
    const aliceInbox = await post('/v1/fetch', fetchBody(store, [aliceQueue]));
    assert.equal(aliceInbox.body.messages[0].message, ready.toString('base64'));

    // Error responses carry codes and serverTime; clock skew is reported so clients can correct.
    const skew = await post(`/v1/messages/${aliceQueue.senderId}`, sendBody(store, bobSender, aliceQueue.senderId, randomBytes(10), { includeKey: false, overrides: { timestamp: store.now() - 600_000 } }));
    assert.equal(skew.status, 401);
    assert.equal(skew.body.error, 'clock_skew');
    assert.ok(Number.isSafeInteger(skew.body.serverTime));
    const notJson = await fetch(`${base}/v1/fetch`, { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: '{}' });
    assert.equal(notJson.status, 415);
    const huge = await fetch(`${base}/v1/fetch`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: 'x'.repeat(70 * 1024) });
    assert.equal(huge.status, 413);
    assert.equal((await fetch(`${base}/v1/unknown`)).status, 404);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
