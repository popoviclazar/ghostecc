#!/usr/bin/env python3
"""Independent client (Python + cryptography) against the real server process.

It follows docs/RELAY-PROTOCOL.md exactly, like the Swift client does, so a pass
shows the wire format does not depend on Node's own crypto or JSON quirks.
Run from server/: python3 test/crosscheck.py
"""
import base64, hashlib, json, os, secrets, socket, stat, subprocess, sys, tempfile, time, urllib.error, urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ORIGIN = "https://relay.crosscheck.test"
HERE = os.path.dirname(os.path.abspath(__file__))


def b64(data): return base64.b64encode(data).decode()
def raw(key): return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
def now_ms(): return int(time.time() * 1000)


def auth(key, op, queue_id, digest_input, timestamp=None, nonce=None):
    timestamp = now_ms() if timestamp is None else timestamp
    nonce = nonce or base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("=")
    digest = hashlib.sha256(digest_input).hexdigest()
    message = "\n".join(["GHOST-RELAY-v1", ORIGIN, op, queue_id, str(timestamp), nonce, digest]).encode()
    return {"timestamp": timestamp, "nonce": nonce, "signature": b64(key.sign(message))}


class Relay:
    def __init__(self, port): self.base = f"http://127.0.0.1:{port}"

    def call(self, method, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, data=data, method=method, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def create(self, invitation=None):
        key = Ed25519PrivateKey.generate()
        body = {"recipientKey": b64(raw(key)), "auth": auth(key, "create", "-", raw(key) + (invitation or b""))}
        if invitation: body["invitation"] = b64(invitation)
        status, result = self.call("POST", "/v1/queues", body)
        assert status == 200, result
        return {"key": key, **result}

    def send(self, sender_key, sender_id, message, include_key=True, timestamp=None):
        expires = now_ms() + 3_600_000
        offered = raw(sender_key) if include_key else b""
        body = {"message": b64(message), "expiresAt": expires,
                "auth": auth(sender_key, "send", sender_id, message + f"|{expires}|".encode() + offered, timestamp)}
        if include_key: body["senderKey"] = b64(offered)
        return self.call("POST", f"/v1/messages/{sender_id}", body)

    def fetch(self, *queues):
        items = [{"recipientId": q["recipientId"], "auth": auth(q["key"], "fetch", q["recipientId"], b"")} for q in queues]
        return self.call("POST", "/v1/fetch", {"queues": items})

    def ack(self, queue, ids):
        return self.call("POST", "/v1/ack", {"recipientId": queue["recipientId"], "ids": ids,
                                             "auth": auth(queue["key"], "ack", queue["recipientId"], ",".join(ids).encode())})


def start(port, data_dir):
    env = dict(os.environ, GHOST_ORIGIN=ORIGIN, GHOST_LISTEN=f"127.0.0.1:{port}", GHOST_DATA_DIR=data_dir)
    process = subprocess.Popen(["node", os.path.join(HERE, "..", "src", "main.js")], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.1).close(); return process
        except OSError: time.sleep(0.05)
    process.kill(); raise RuntimeError(process.stdout.read().decode())


def stop(process):
    process.terminate(); process.wait(timeout=10)


def main():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]
    data_dir = tempfile.mkdtemp()
    server = start(port, data_dir)
    relay = Relay(port)
    checks = 0
    try:
        bundle = secrets.token_bytes(2600)
        bob = relay.create(bundle)
        status, result = relay.call("GET", f"/v1/invitations/{bob['senderId']}")
        assert status == 200 and base64.b64decode(result["invitation"]) == bundle; checks += 1
        alice_sender = Ed25519PrivateKey.generate()
        hello = secrets.token_bytes(1500)
        status, result = relay.send(alice_sender, bob["senderId"], hello)
        assert status == 200 and result["status"] == "accepted", result; checks += 1
        status, _ = relay.send(Ed25519PrivateKey.generate(), bob["senderId"], b"intruder")
        assert status == 401; checks += 1
        status, result = relay.send(alice_sender, bob["senderId"], b"skewed!", include_key=False, timestamp=now_ms() - 3_600_000)
        assert status == 401 and result["error"] == "clock_skew" and isinstance(result["serverTime"], int); checks += 1
        secret = b"CROSSCHECK-SECRET-" + secrets.token_bytes(16)
        relay.send(alice_sender, bob["senderId"], secret, include_key=False)
        status, result = relay.fetch(bob)
        assert status == 200 and [m["message"] for m in result["messages"]] == [b64(hello), b64(secret)]; checks += 1
        stop(server)
        state_path = os.path.join(data_dir, "queues.json")
        state = open(state_path, "rb").read()
        assert b64(secret).encode() not in state and b64(hello).encode() not in state; checks += 1
        assert stat.S_IMODE(os.stat(state_path).st_mode) == 0o600; checks += 1
        server = start(port, data_dir)
        status, result = relay.fetch(bob)
        assert status == 200 and result["queues"][0]["status"] == "ok" and result["messages"] == []; checks += 1
        status, result = relay.send(alice_sender, bob["senderId"], b"after restart", include_key=False)
        assert status == 200; checks += 1
        status, result = relay.fetch(bob)
        status, removed = relay.ack(bob, [m["id"] for m in result["messages"]])
        assert status == 200 and removed["removed"] == 1; checks += 1
        status, result = relay.call("POST", "/v1/delete", {"recipientId": bob["recipientId"], "auth": auth(bob["key"], "delete", bob["recipientId"], b"")})
        assert status == 200; checks += 1
        status, result = relay.fetch(bob)
        assert result["queues"][0]["status"] == "not_found"; checks += 1
    finally:
        stop(server)
    print(f"crosscheck: {checks} checks passed against the real server process")


if __name__ == "__main__":
    sys.exit(main())
