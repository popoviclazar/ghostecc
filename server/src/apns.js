// Apple Push Notification service, Node.js standard library only (HTTP/2 + ES256 JWT).
// The push never carries a sender, queue ID or content: only a localization key that the app
// turns into "Nova poruka" / "New message" in the user's language.
import http2 from 'node:http2';
import { createPrivateKey, sign } from 'node:crypto';

export const APNS_ORIGINS = Object.freeze({
  production: 'https://api.push.apple.com',
  sandbox: 'https://api.sandbox.push.apple.com',
});
const JWT_LIFETIME_MS = 40 * 60 * 1000; // Apple: refresh no more often than every 20 min, valid up to 60 min.

const b64url = (value) => Buffer.from(value).toString('base64url');

export class ApnsClient {
  constructor({ keyPem, keyId, teamId, topic, locKey = 'PUSH_NEW_MESSAGE', origins = APNS_ORIGINS, now = () => Date.now(), timeoutMs = 10_000 }) {
    if (!/^[A-Z0-9]{10}$/.test(keyId ?? '')) throw new Error('APNs key ID must be 10 characters (from AuthKey_XXXXXXXXXX.p8)');
    if (!/^[A-Z0-9]{10}$/.test(teamId ?? '')) throw new Error('Apple Team ID must be 10 characters');
    if (!/^[A-Za-z0-9.-]+$/.test(topic ?? '')) throw new Error('APNs topic must be the app bundle ID');
    this.key = createPrivateKey(keyPem);
    if (this.key.asymmetricKeyType !== 'ec') throw new Error('APNs key must be the .p8 EC key from Apple');
    Object.assign(this, { keyId, teamId, topic, origins, now, timeoutMs });
    this.payload = JSON.stringify({ aps: { alert: { 'loc-key': locKey }, sound: 'default' } });
    this.sessions = new Map();
    this.cachedJwt = null;
  }

  jwt(force = false) {
    const now = this.now();
    if (!force && this.cachedJwt && now - this.cachedJwt.at < JWT_LIFETIME_MS) return this.cachedJwt.value;
    const input = `${b64url(JSON.stringify({ alg: 'ES256', kid: this.keyId }))}.${b64url(JSON.stringify({ iss: this.teamId, iat: Math.floor(now / 1000) }))}`;
    const signature = sign('sha256', Buffer.from(input), { key: this.key, dsaEncoding: 'ieee-p1363' });
    this.cachedJwt = { value: `${input}.${b64url(signature)}`, at: now };
    return this.cachedJwt.value;
  }

  session(environment) {
    const existing = this.sessions.get(environment);
    if (existing && !existing.closed && !existing.destroyed) return existing;
    const session = http2.connect(this.origins[environment]);
    session.on('error', () => {});
    session.on('close', () => { if (this.sessions.get(environment) === session) this.sessions.delete(environment); });
    session.setTimeout(10 * 60 * 1000, () => session.close());
    this.sessions.set(environment, session);
    return session;
  }

  // Resolves { status, reason }. status 0 means a network failure.
  send(token, environment) {
    return new Promise((resolve) => {
      let done = false;
      const finish = (result) => { if (!done) { done = true; resolve(result); } };
      let request;
      try {
        request = this.session(environment).request({
          ':method': 'POST',
          ':path': `/3/device/${token}`,
          authorization: `bearer ${this.jwt()}`,
          'apns-topic': this.topic,
          'apns-push-type': 'alert',
          'apns-priority': '10',
          'apns-expiration': String(Math.floor(this.now() / 1000) + 86_400),
          'apns-collapse-id': 'ghost-new-message',
          'content-type': 'application/json',
        });
      } catch {
        finish({ status: 0, reason: 'connect' });
        return;
      }
      let status = 0;
      let body = '';
      request.setEncoding('utf8');
      request.on('response', (headers) => { status = Number(headers[':status']); });
      request.on('data', (chunk) => { if (body.length < 4096) body += chunk; });
      request.on('end', () => {
        let reason = '';
        try { reason = body ? JSON.parse(body).reason ?? '' : ''; } catch { /* ignore */ }
        if (status === 403 && reason === 'ExpiredProviderToken') this.cachedJwt = null;
        finish({ status, reason });
      });
      request.on('error', () => finish({ status: 0, reason: 'network' }));
      request.setTimeout(this.timeoutMs, () => { request.close(http2.constants.NGHTTP2_CANCEL); finish({ status: 0, reason: 'timeout' }); });
      request.end(this.payload);
    });
  }

  close() { for (const session of this.sessions.values()) session.close(); this.sessions.clear(); }
}

// Coalesces pushes per device: at most one per interval, however many messages or queues are involved.
export class Pusher {
  constructor({ store, send, intervalMs = 15_000, now = () => Date.now(), setTimer = setTimeout, log = () => {} }) {
    Object.assign(this, { store, send, intervalMs, now, setTimer, log });
    this.devices = new Map(); // token -> { last, timer }
    this.stats = { sent: 0, dropped: 0, failed: 0 };
  }

  messageArrived(recipientId) {
    const target = this.store.pushTarget(recipientId);
    if (!target) return;
    const state = this.devices.get(target.token) ?? { last: 0, timer: null };
    this.devices.set(target.token, state);
    if (state.timer) return;
    const wait = Math.max(0, state.last + this.intervalMs - this.now());
    state.timer = this.setTimer(() => { state.timer = null; this.deliver(target.token); }, wait);
    state.timer?.unref?.();
  }

  async deliver(token) {
    const target = [...this.store.pushTargets.values()].find((item) => item.token === token);
    if (!target) { this.devices.delete(token); return; }
    const state = this.devices.get(token) ?? { last: 0, timer: null };
    this.devices.set(token, state);
    state.last = this.now();
    let result = await this.send(token, target.environment);
    if (result.status === 400 && result.reason === 'BadDeviceToken') {
      // Development builds get sandbox tokens; a Release build run from Xcode may report the wrong environment.
      const other = target.environment === 'production' ? 'sandbox' : 'production';
      result = await this.send(token, other);
      if (result.status === 200) this.store.updatePushToken(token, other);
    }
    if (result.status === 200) { this.stats.sent += 1; return; }
    if (result.status === 410 || (result.status === 400 && ['BadDeviceToken', 'DeviceTokenNotForTopic', 'Unregistered'].includes(result.reason))) {
      this.store.updatePushToken(token, null);
      this.devices.delete(token);
      this.stats.dropped += 1;
      return;
    }
    this.stats.failed += 1;
    if (result.status === 403) this.log(`APNs rejected the provider token (${result.reason || 403}); check key ID, team ID and topic`);
  }

  sweep() {
    const cutoff = this.now() - 3_600_000;
    for (const [token, state] of this.devices) if (!state.timer && state.last < cutoff) this.devices.delete(token);
  }
}
