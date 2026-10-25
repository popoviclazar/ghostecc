import http from 'node:http';
import { RelayError, VERSION } from './relay.js';

const SMALL_BODY = 64 * 1024;
const LARGE_BODY = 9 * 1024 * 1024;
const QUEUE_PATH = /^\/v1\/(invitations|messages)\/([A-Za-z0-9_-]{32})$/;

// In-memory token buckets keyed by client IP. Nothing is written to disk or logs.
export class RateLimiter {
  constructor({ now = () => Date.now(), perSecond = 20, burst = 60, createsPerHour = 60, createBurst = 20 } = {}) {
    this.now = now;
    this.rules = {
      request: { rate: perSecond / 1000, burst },
      create: { rate: createsPerHour / 3_600_000, burst: createBurst },
    };
    this.buckets = new Map();
  }

  allow(client, kind = 'request') {
    const rule = this.rules[kind];
    const key = `${kind}:${client}`;
    const now = this.now();
    const bucket = this.buckets.get(key) ?? { tokens: rule.burst, at: now };
    bucket.tokens = Math.min(rule.burst, bucket.tokens + (now - bucket.at) * rule.rate);
    bucket.at = now;
    this.buckets.set(key, bucket);
    if (bucket.tokens < 1) return false;
    bucket.tokens -= 1;
    return true;
  }

  sweep() {
    const now = this.now();
    for (const [key, bucket] of this.buckets) if (now - bucket.at > 3_600_000) this.buckets.delete(key);
  }
}

function clientAddress(req, trustProxy) {
  if (trustProxy) {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.trim()) return forwarded.split(',').pop().trim();
  }
  return req.socket.remoteAddress ?? 'unknown';
}

function readJson(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const type = String(req.headers['content-type'] ?? '').toLowerCase();
    if (!type.startsWith('application/json')) { reject(new RelayError(415, 'unsupported_media_type')); return; }
    const declared = Number(req.headers['content-length'] ?? 0);
    if (declared > maxBytes) { reject(new RelayError(413, 'too_large')); return; }
    const chunks = [];
    let size = 0;
    let done = false;
    req.on('data', (chunk) => {
      if (done) return;
      size += chunk.length;
      if (size > maxBytes) { done = true; reject(new RelayError(413, 'too_large')); return; }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (done) return;
      done = true;
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(new RelayError(400, 'bad_json')); }
    });
    req.on('error', () => { if (!done) { done = true; reject(new RelayError(400, 'bad_request')); } });
  });
}

function respond(res, store, status, body, close = false) {
  const payload = JSON.stringify({ ...body, serverTime: store.now() });
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  };
  if (close) headers.Connection = 'close';
  res.writeHead(status, headers);
  res.end(payload);
}

export function createRelayServer(store, { trustProxy = false, limiter = new RateLimiter({ now: store.now }), log = () => {} } = {}) {
  const server = http.createServer(async (req, res) => {
    const client = clientAddress(req, trustProxy);
    try {
      if (!limiter.allow(client)) throw new RelayError(429, 'rate_limited');
      const { pathname } = new URL(req.url ?? '/', 'http://relay.invalid');
      if (req.method === 'GET' && pathname === '/v1/health') {
        respond(res, store, 200, { status: 'ok', version: VERSION });
        return;
      }
      const queuePath = QUEUE_PATH.exec(pathname);
      if (req.method === 'GET' && queuePath?.[1] === 'invitations') {
        respond(res, store, 200, store.getInvitation(queuePath[2]));
        return;
      }
      if (req.method !== 'POST') throw new RelayError(404, 'not_found');
      if (queuePath?.[1] === 'messages') {
        respond(res, store, 200, store.send(queuePath[2], await readJson(req, LARGE_BODY)));
        return;
      }
      switch (pathname) {
        case '/v1/queues':
          if (!limiter.allow(client, 'create')) throw new RelayError(429, 'rate_limited');
          respond(res, store, 200, store.createQueue(await readJson(req, SMALL_BODY)));
          return;
        case '/v1/fetch':
          respond(res, store, 200, store.fetch(await readJson(req, SMALL_BODY)));
          return;
        case '/v1/ack':
          respond(res, store, 200, store.ack(await readJson(req, SMALL_BODY)));
          return;
        case '/v1/notify':
          respond(res, store, 200, store.notify(await readJson(req, SMALL_BODY)));
          return;
        case '/v1/delete':
          respond(res, store, 200, store.deleteQueue(await readJson(req, SMALL_BODY)));
          return;
        default:
          throw new RelayError(404, 'not_found');
      }
    } catch (error) {
      if (error instanceof RelayError) {
        const close = error.status === 413 || error.status === 415;
        respond(res, store, error.status, { error: error.code }, close);
        if (close) res.on('finish', () => req.destroy());
        return;
      }
      log('internal error');
      respond(res, store, 500, { error: 'internal' }, true);
    }
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 50;
  return server;
}
