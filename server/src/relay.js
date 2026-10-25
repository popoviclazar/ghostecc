// Ghost ECC relay core. No accounts, no identities: only random one-way queues.
// Message bodies are opaque ciphertext and live in RAM only.
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';

export const PROTOCOL = 'GHOST-RELAY-v1';
export const VERSION = '1.0.0';
const DAY_MS = 86_400_000;
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const QUEUE_ID = /^[A-Za-z0-9_-]{32}$/;
const MESSAGE_ID = /^[A-Za-z0-9_-]{22}$/;
const NONCE = /^[A-Za-z0-9_-]{22}$/;
const PUSH_TOKEN = /^[0-9a-f]{64,200}$/;
export const PUSH_ENVIRONMENTS = ['production', 'sandbox'];
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;
export const EMPTY_DIGEST = createHash('sha256').update(Buffer.alloc(0)).digest('hex');

export const DEFAULT_LIMITS = Object.freeze({
  maxMessageBytes: 6_000_000,
  maxInvitationBytes: 16_384,
  maxQueueMessages: 100,
  maxQueueBytes: 24_000_000,
  maxFetchQueues: 64,
  maxFetchMessages: 50,
  maxFetchBytes: 9_000_000,
  maxLifetimeMs: DAY_MS,
  lifetimeGraceMs: 120_000,
  clockSkewMs: 120_000,
  nonceTtlMs: 300_000,
  maxNonces: 2_000_000,
  unsecuredQueueDays: 7,
  idleQueueDays: 60,
  maxAckIds: 100,
  maxQueues: 1_000_000,
  maxMemoryBytes: 1024 * 1024 * 1024,
});

export class RelayError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

export const sha256hex = (buffer) => createHash('sha256').update(buffer).digest('hex');
export const dayOf = (ms) => Math.floor(ms / DAY_MS);

export function normalizeOrigin(input) {
  let url;
  try { url = new URL(String(input ?? '').trim()); } catch { throw new Error('origin must look like https://relay.example.com'); }
  const host = url.hostname.toLowerCase();
  if (url.protocol !== 'https:' || !host || host.includes(':') || host.startsWith('[') || url.username || url.password ||
      url.search || url.hash || !(url.pathname === '/' || url.pathname === '')) {
    throw new Error('origin must look like https://relay.example.com (https, no path, query or credentials)');
  }
  return url.port && url.port !== '443' ? `https://${host}:${url.port}` : `https://${host}`;
}

export function authMessage(origin, op, queueId, timestamp, nonce, digest) {
  return Buffer.from([PROTOCOL, origin, op, queueId, String(timestamp), nonce, digest].join('\n'), 'utf8');
}

export function notifyDigestInput(token, environment) {
  return Buffer.from(`${token ?? ''}|${environment}`, 'utf8');
}

export function sendDigestInput(message, expiresAt, senderKey) {
  return Buffer.concat([message, Buffer.from(`|${expiresAt}|`, 'utf8'), senderKey ?? Buffer.alloc(0)]);
}

export function decodeBase64(value, field, { min = 0, max = Infinity, exact, status = 400 } = {}) {
  if (typeof value !== 'string' || value.length % 4 !== 0 || !BASE64.test(value)) throw new RelayError(status, `bad_${field}`);
  const buffer = Buffer.from(value, 'base64');
  // Reject non-canonical encodings so one byte string has exactly one accepted spelling.
  if (buffer.toString('base64') !== value) throw new RelayError(status, `bad_${field}`);
  if ((exact !== undefined && buffer.length !== exact) || buffer.length < min || buffer.length > max) throw new RelayError(status, `bad_${field}`);
  return buffer;
}

function importKey(raw, field) {
  try {
    return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
  } catch {
    throw new RelayError(400, `bad_${field}`);
  }
}

export class RelayStore {
  constructor({ origin, limits = {}, now = () => Date.now() } = {}) {
    this.origin = normalizeOrigin(origin);
    this.limits = { ...DEFAULT_LIMITS, ...limits };
    this.now = now;
    this.queues = new Map();   // recipientId -> record
    this.senders = new Map();  // senderId -> recipientId
    this.inbox = new Map();    // recipientId -> { items, bytes }
    this.nonces = new Map();   // op:queue:nonce -> expiry
    this.pushTargets = new Map(); // recipientId -> { token, environment }; RAM only, never persisted
    this.onMessage = null;      // called with recipientId for every newly stored message
    this.totalBytes = 0;
    this.dirty = false;
  }

  newId(bytes) { return randomBytes(bytes).toString('base64url'); }

  freshQueueId() {
    let id;
    do { id = this.newId(24); } while (this.queues.has(id) || this.senders.has(id));
    return id;
  }

  recordByRecipient(recipientId) {
    const record = typeof recipientId === 'string' && QUEUE_ID.test(recipientId) ? this.queues.get(recipientId) : undefined;
    if (!record) throw new RelayError(404, 'not_found');
    return record;
  }

  recordBySender(senderId) {
    const recipientId = typeof senderId === 'string' && QUEUE_ID.test(senderId) ? this.senders.get(senderId) : undefined;
    const record = recipientId ? this.queues.get(recipientId) : undefined;
    if (!record) throw new RelayError(404, 'not_found');
    return record;
  }

  recipientKeyObject(record) {
    record.recipientKeyObject ??= importKey(record.recipientKey, 'recipientKey');
    return record.recipientKeyObject;
  }

  senderKeyObject(record) {
    record.senderKeyObject ??= importKey(record.senderKey, 'senderKey');
    return record.senderKeyObject;
  }

  verifyAuth(auth, { op, queueId, digest, keyObject }) {
    if (!auth || typeof auth !== 'object') throw new RelayError(401, 'unauthorized');
    const { timestamp, nonce, signature } = auth;
    if (!Number.isSafeInteger(timestamp) || typeof nonce !== 'string' || !NONCE.test(nonce)) throw new RelayError(401, 'unauthorized');
    const now = this.now();
    if (Math.abs(now - timestamp) > this.limits.clockSkewMs) throw new RelayError(401, 'clock_skew');
    const sig = decodeBase64(signature, 'signature', { exact: 64, status: 401 });
    if (!verify(null, authMessage(this.origin, op, queueId, timestamp, nonce, digest), keyObject, sig)) {
      throw new RelayError(401, 'unauthorized');
    }
    const key = `${op}:${queueId}:${nonce}`;
    if (this.nonces.has(key)) throw new RelayError(401, 'replay');
    if (this.nonces.size >= this.limits.maxNonces) throw new RelayError(503, 'capacity');
    this.nonces.set(key, now + this.limits.nonceTtlMs);
  }

  createQueue(body) {
    const recipientKey = decodeBase64(body?.recipientKey, 'recipientKey', { exact: 32 });
    const invitation = body?.invitation == null ? null
      : decodeBase64(body.invitation, 'invitation', { min: 1, max: this.limits.maxInvitationBytes });
    if (this.queues.size >= this.limits.maxQueues) throw new RelayError(503, 'capacity');
    const keyObject = importKey(recipientKey, 'recipientKey');
    const digest = sha256hex(invitation ? Buffer.concat([recipientKey, invitation]) : recipientKey);
    this.verifyAuth(body.auth, { op: 'create', queueId: '-', digest, keyObject });
    const recipientId = this.freshQueueId();
    let senderId = this.freshQueueId();
    while (senderId === recipientId) senderId = this.freshQueueId();
    const today = dayOf(this.now());
    this.queues.set(recipientId, {
      recipientId, senderId, recipientKey, senderKey: null, invitation,
      createdDay: today, activeDay: today, recipientKeyObject: keyObject,
    });
    this.senders.set(senderId, recipientId);
    this.dirty = true;
    return { recipientId, senderId };
  }

  getInvitation(senderId) {
    const record = this.recordBySender(senderId);
    if (record.senderKey || !record.invitation) throw new RelayError(404, 'not_found');
    return { invitation: record.invitation.toString('base64') };
  }

  send(senderId, body) {
    const record = this.recordBySender(senderId);
    const maxEncoded = Math.ceil(this.limits.maxMessageBytes / 3) * 4;
    if (typeof body?.message !== 'string' || body.message.length > maxEncoded) throw new RelayError(413, 'too_large');
    const message = decodeBase64(body.message, 'message', { min: 3, max: this.limits.maxMessageBytes });
    const now = this.now();
    const { expiresAt } = body;
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= now ||
        expiresAt > now + this.limits.maxLifetimeMs + this.limits.lifetimeGraceMs) {
      throw new RelayError(400, 'bad_expiresAt');
    }
    const offeredKey = body.senderKey == null ? null : decodeBase64(body.senderKey, 'senderKey', { exact: 32 });
    let keyObject;
    if (record.senderKey) {
      if (offeredKey && !offeredKey.equals(record.senderKey)) throw new RelayError(401, 'unauthorized');
      keyObject = this.senderKeyObject(record);
    } else {
      if (!offeredKey) throw new RelayError(401, 'not_secured');
      keyObject = importKey(offeredKey, 'senderKey');
    }
    const digest = sha256hex(sendDigestInput(message, expiresAt, offeredKey));
    this.verifyAuth(body.auth, { op: 'send', queueId: senderId, digest, keyObject });
    if (!record.senderKey) {
      // The first valid sender secures the queue; the invitation is one-time and disappears.
      record.senderKey = offeredKey;
      record.senderKeyObject = keyObject;
      record.invitation = null;
      record.createdDay = null;
      this.dirty = true;
    }
    const box = this.inbox.get(record.recipientId) ?? { items: [], bytes: 0 };
    const hash = sha256hex(message);
    const existing = box.items.find((item) => item.hash === hash);
    if (existing) return { id: existing.id, status: 'accepted' };
    if (box.items.length >= this.limits.maxQueueMessages || box.bytes + message.length > this.limits.maxQueueBytes) {
      throw new RelayError(429, 'queue_full');
    }
    if (this.totalBytes + message.length > this.limits.maxMemoryBytes) throw new RelayError(503, 'capacity');
    const id = this.newId(16);
    box.items.push({ id, data: message, hash, expiresAt: Math.min(expiresAt, now + this.limits.maxLifetimeMs) });
    box.bytes += message.length;
    this.totalBytes += message.length;
    this.inbox.set(record.recipientId, box);
    this.onMessage?.(record.recipientId);
    return { id, status: 'accepted' };
  }

  fetch(body) {
    const entries = body?.queues;
    if (!Array.isArray(entries) || entries.length === 0 || entries.length > this.limits.maxFetchQueues) {
      throw new RelayError(400, 'bad_queues');
    }
    this.purgeExpired();
    const today = dayOf(this.now());
    const statuses = [];
    const boxes = [];
    const requested = new Set();
    for (const entry of entries) {
      const recipientId = entry?.recipientId;
      if (typeof recipientId !== 'string' || !QUEUE_ID.test(recipientId) || requested.has(recipientId)) {
        throw new RelayError(400, 'bad_queues');
      }
      requested.add(recipientId);
      const record = this.queues.get(recipientId);
      if (!record) { statuses.push({ recipientId, status: 'not_found' }); continue; }
      try {
        this.verifyAuth(entry.auth, { op: 'fetch', queueId: recipientId, digest: EMPTY_DIGEST, keyObject: this.recipientKeyObject(record) });
      } catch (error) {
        if (!(error instanceof RelayError)) throw error;
        statuses.push({ recipientId, status: error.code === 'clock_skew' ? 'clock_skew' : 'unauthorized' });
        continue;
      }
      if (record.activeDay !== today) { record.activeDay = today; this.dirty = true; }
      statuses.push({ recipientId, status: 'ok' });
      const box = this.inbox.get(recipientId);
      if (box?.items.length) boxes.push({ recipientId, items: box.items, index: 0 });
    }
    // Round-robin across queues so one flooded queue cannot starve the others.
    const messages = [];
    let bytes = 0;
    let active = boxes;
    while (active.length && messages.length < this.limits.maxFetchMessages) {
      const next = [];
      for (const box of active) {
        if (messages.length >= this.limits.maxFetchMessages) break;
        const item = box.items[box.index];
        if (messages.length > 0 && bytes + item.data.length > this.limits.maxFetchBytes) continue;
        messages.push({ recipientId: box.recipientId, id: item.id, message: item.data.toString('base64'), expiresAt: item.expiresAt });
        bytes += item.data.length;
        box.index += 1;
        if (box.index < box.items.length) next.push(box);
      }
      active = next;
    }
    return { queues: statuses, messages };
  }

  ack(body) {
    const record = this.recordByRecipient(body?.recipientId);
    const ids = body?.ids;
    if (!Array.isArray(ids) || ids.length === 0 || ids.length > this.limits.maxAckIds ||
        !ids.every((id) => typeof id === 'string' && MESSAGE_ID.test(id))) {
      throw new RelayError(400, 'bad_ids');
    }
    const digest = sha256hex(Buffer.from(ids.join(','), 'utf8'));
    this.verifyAuth(body.auth, { op: 'ack', queueId: record.recipientId, digest, keyObject: this.recipientKeyObject(record) });
    const wanted = new Set(ids);
    const box = this.inbox.get(record.recipientId);
    let removed = 0;
    if (box) {
      box.items = box.items.filter((item) => {
        if (!wanted.has(item.id)) return true;
        removed += 1;
        box.bytes -= item.data.length;
        this.totalBytes -= item.data.length;
        return false;
      });
      if (!box.items.length) this.inbox.delete(record.recipientId);
    }
    return { removed };
  }

  // Registers (or with token null removes) an APNs device token for up to 64 own queues.
  notify(body) {
    const token = body?.token ?? null;
    const environment = body?.environment;
    const entries = body?.queues;
    if (token !== null && (typeof token !== 'string' || !PUSH_TOKEN.test(token))) throw new RelayError(400, 'bad_token');
    if (!PUSH_ENVIRONMENTS.includes(environment)) throw new RelayError(400, 'bad_environment');
    if (!Array.isArray(entries) || entries.length === 0 || entries.length > this.limits.maxFetchQueues) throw new RelayError(400, 'bad_queues');
    const digest = sha256hex(notifyDigestInput(token, environment));
    const statuses = [];
    const seen = new Set();
    for (const entry of entries) {
      const recipientId = entry?.recipientId;
      if (typeof recipientId !== 'string' || !QUEUE_ID.test(recipientId) || seen.has(recipientId)) throw new RelayError(400, 'bad_queues');
      seen.add(recipientId);
      const record = this.queues.get(recipientId);
      if (!record) { statuses.push({ recipientId, status: 'not_found' }); continue; }
      try {
        this.verifyAuth(entry.auth, { op: 'notify', queueId: recipientId, digest, keyObject: this.recipientKeyObject(record) });
      } catch (error) {
        if (!(error instanceof RelayError)) throw error;
        statuses.push({ recipientId, status: error.code === 'clock_skew' ? 'clock_skew' : 'unauthorized' });
        continue;
      }
      if (token) this.pushTargets.set(recipientId, { token, environment });
      else this.pushTargets.delete(recipientId);
      statuses.push({ recipientId, status: 'ok' });
    }
    return { queues: statuses };
  }

  pushTarget(recipientId) { return this.pushTargets.get(recipientId) ?? null; }

  // APNs said the token is dead (or valid in the other environment): update every queue using it.
  updatePushToken(token, environment) {
    for (const [recipientId, target] of this.pushTargets) {
      if (target.token !== token) continue;
      if (environment) target.environment = environment;
      else this.pushTargets.delete(recipientId);
    }
  }

  deleteQueue(body) {
    const record = this.recordByRecipient(body?.recipientId);
    this.verifyAuth(body.auth, { op: 'delete', queueId: record.recipientId, digest: EMPTY_DIGEST, keyObject: this.recipientKeyObject(record) });
    this.removeQueue(record);
    return {};
  }

  removeQueue(record) {
    const box = this.inbox.get(record.recipientId);
    if (box) this.totalBytes -= box.bytes;
    this.inbox.delete(record.recipientId);
    this.senders.delete(record.senderId);
    this.pushTargets.delete(record.recipientId);
    this.queues.delete(record.recipientId);
    this.dirty = true;
  }

  purgeExpired() {
    const now = this.now();
    let removed = 0;
    for (const [recipientId, box] of this.inbox) {
      if (!box.items.some((item) => item.expiresAt <= now)) continue;
      box.items = box.items.filter((item) => {
        if (item.expiresAt > now) return true;
        removed += 1;
        box.bytes -= item.data.length;
        this.totalBytes -= item.data.length;
        return false;
      });
      if (!box.items.length) this.inbox.delete(recipientId);
    }
    return removed;
  }

  maintenance() {
    const now = this.now();
    const today = dayOf(now);
    const expiredMessages = this.purgeExpired();
    for (const [key, expiry] of this.nonces) if (expiry <= now) this.nonces.delete(key);
    let removedQueues = 0;
    for (const record of [...this.queues.values()]) {
      const unusedInvite = !record.senderKey && record.createdDay !== null && today - record.createdDay >= this.limits.unsecuredQueueDays;
      const idle = today - record.activeDay >= this.limits.idleQueueDays;
      if (unusedInvite || idle) { this.removeQueue(record); removedQueues += 1; }
    }
    return { expiredMessages, removedQueues };
  }

  stats() {
    let messages = 0;
    for (const box of this.inbox.values()) messages += box.items.length;
    return { queues: this.queues.size, messages, bytes: this.totalBytes, pushTargets: this.pushTargets.size };
  }

  // Only queue routing data is persisted. Message bodies never leave RAM.
  snapshot() {
    return {
      version: 1,
      queues: [...this.queues.values()].map((record) => ({
        recipientId: record.recipientId,
        senderId: record.senderId,
        recipientKey: record.recipientKey.toString('base64'),
        senderKey: record.senderKey ? record.senderKey.toString('base64') : null,
        invitation: record.invitation ? record.invitation.toString('base64') : null,
        createdDay: record.createdDay,
        activeDay: record.activeDay,
      })),
    };
  }

  restore(data) {
    if (!data || data.version !== 1 || !Array.isArray(data.queues)) throw new Error('unsupported state file');
    for (const item of data.queues) {
      if (!QUEUE_ID.test(item.recipientId) || !QUEUE_ID.test(item.senderId)) throw new Error('corrupt state file');
      const record = {
        recipientId: item.recipientId,
        senderId: item.senderId,
        recipientKey: decodeBase64(item.recipientKey, 'recipientKey', { exact: 32 }),
        senderKey: item.senderKey ? decodeBase64(item.senderKey, 'senderKey', { exact: 32 }) : null,
        invitation: item.invitation ? decodeBase64(item.invitation, 'invitation', { max: this.limits.maxInvitationBytes }) : null,
        createdDay: Number.isSafeInteger(item.createdDay) ? item.createdDay : null,
        activeDay: Number.isSafeInteger(item.activeDay) ? item.activeDay : dayOf(this.now()),
      };
      this.queues.set(record.recipientId, record);
      this.senders.set(record.senderId, record.recipientId);
    }
    this.dirty = false;
  }
}
