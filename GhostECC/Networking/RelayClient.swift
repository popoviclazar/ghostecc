import Foundation
import CryptoKit

enum RelayOrigin {
    /// https://host[:port] in lowercase, no path, query, fragment or credentials. Mirrors normalizeOrigin on the server.
    static func normalize(_ input: String) throws -> String {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: trimmed), components.scheme?.lowercased() == "https",
              let host = components.host?.lowercased(), !host.isEmpty, !host.contains(":"),
              components.user == nil, components.password == nil, components.query == nil, components.fragment == nil,
              components.path.isEmpty || components.path == "/" else { throw GhostError.invalidURL }
        if let port = components.port, port != 443 {
            guard (1...65_535).contains(port) else { throw GhostError.invalidURL }
            return "https://\(host):\(port)"
        }
        return "https://\(host)"
    }
}

enum RelayQueueID {
    static func isValid(_ value: String) -> Bool { value.range(of: "^[A-Za-z0-9_-]{32}$", options: .regularExpression) != nil }
    static func isValidMessage(_ value: String) -> Bool { value.range(of: "^[A-Za-z0-9_-]{22}$", options: .regularExpression) != nil }
}

/// Canonical request signature, see docs/RELAY-PROTOCOL.md. Must stay byte-identical to server/src/relay.js.
enum RelaySigning {
    static let domain = "GHOST-RELAY-v1"
    static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    static func message(origin: String, op: String, queueID: String, timestamp: Int64, nonce: String, digest: String) -> Data {
        Data([domain, origin, op, queueID, String(timestamp), nonce, digest].joined(separator: "\n").utf8)
    }
}

struct RelayAuth: Codable { let timestamp: Int64; let nonce: String; let signature: Data }
struct RelayQueueStatus: Decodable { let recipientId: String; let status: String }
struct RelayMessage: Decodable { let recipientId: String; let id: String; let message: Data; let expiresAt: Int64 }
struct FetchResult: Decodable { let queues: [RelayQueueStatus]; let messages: [RelayMessage]; let serverTime: Int64 }

private struct CreateQueueRequest: Encodable { let recipientKey: Data; let invitation: Data?; let auth: RelayAuth }
private struct CreateQueueResponse: Decodable { let recipientId: String; let senderId: String }
private struct InvitationResponse: Decodable { let invitation: Data }
private struct SendRequest: Encodable { let message: Data; let expiresAt: Int64; let senderKey: Data?; let auth: RelayAuth }
private struct SendResponse: Decodable { let id: String; let status: String }
private struct FetchItem: Encodable { let recipientId: String; let auth: RelayAuth }
private struct FetchRequest: Encodable { let queues: [FetchItem] }
private struct AckRequest: Encodable { let recipientId: String; let ids: [String]; let auth: RelayAuth }
private struct DeleteRequest: Encodable { let recipientId: String; let auth: RelayAuth }
private struct NotifyRequest: Encodable { let token: String?; let environment: String; let queues: [FetchItem] }
private struct NotifyResponse: Decodable { let queues: [RelayQueueStatus] }
private struct HealthResponse: Decodable { let status: String }
private struct ServerTime: Decodable { let serverTime: Int64 }
private struct ErrorResponse: Decodable { let error: String }
private struct Empty: Decodable {}
private enum RelayFailure: Error { case clockSkew }

final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}

/// One relay server. Every queue operation is signed with that queue's own Ed25519 key, so the
/// server can authorize requests without accounts and without learning any Ghost ID.
actor RelayClient {
    static let maxFetchQueues = 64
    let origin: String
    private let session: URLSession
    private var clockOffsetMs: Int64 = 0

    init(origin: String) throws {
        self.origin = try RelayOrigin.normalize(origin)
        let config = URLSessionConfiguration.ephemeral
        config.urlCache = nil; config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.httpCookieStorage = nil; config.httpShouldSetCookies = false
        config.timeoutIntervalForRequest = 25; config.timeoutIntervalForResource = 60
        config.waitsForConnectivity = false
        session = URLSession(configuration: config, delegate: NoRedirectDelegate(), delegateQueue: nil)
    }

    var clockOffset: TimeInterval { TimeInterval(clockOffsetMs) / 1000 }

    func health() async throws {
        let response: HealthResponse = try await perform(try makeRequest("v1/health", method: "GET"))
        guard response.status == "ok" else { throw GhostError.unavailable }
    }

    func createQueue(invitation: Data?) async throws -> InboundQueue {
        let key = Curve25519.Signing.PrivateKey()
        let publicKey = key.publicKey.rawRepresentation
        var digestInput = publicKey
        if let invitation { digestInput.append(invitation) }
        let response: CreateQueueResponse = try await post("v1/queues") {
            CreateQueueRequest(recipientKey: publicKey, invitation: invitation,
                               auth: try makeAuth(key: key, op: "create", queueID: "-", digestInput: digestInput))
        }
        guard RelayQueueID.isValid(response.recipientId), RelayQueueID.isValid(response.senderId),
              response.recipientId != response.senderId else { throw GhostError.invalidPayload }
        return InboundQueue(server: origin, recipientID: response.recipientId, senderID: response.senderId, recipientKey: key.rawRepresentation)
    }

    func invitation(senderID: String) async throws -> Data {
        guard RelayQueueID.isValid(senderID) else { throw GhostError.invalidInvite }
        do {
            let response: InvitationResponse = try await perform(try makeRequest("v1/invitations/" + senderID, method: "GET"))
            guard !response.invitation.isEmpty, response.invitation.count <= 16_384 else { throw GhostError.invalidInvite }
            return response.invitation
        } catch GhostError.queueGone {
            throw GhostError.invitationUsed
        }
    }

    func send(_ message: Data, to queue: OutboundQueue, expiresAt: Date) async throws {
        guard queue.server == origin, RelayQueueID.isValid(queue.senderID) else { throw GhostError.invalidPayload }
        guard !message.isEmpty, message.count <= Limits.maxWireBytes else { throw GhostError.tooLarge }
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: queue.senderKey)
        let expires = Int64((expiresAt.timeIntervalSince1970 * 1000).rounded(.down))
        // Until the queue is secured, the sender key travels with the request; the first valid sender owns the queue.
        let offeredKey: Data? = queue.secured ? nil : key.publicKey.rawRepresentation
        var digestInput = message
        digestInput.append(Data("|\(expires)|".utf8))
        if let offeredKey { digestInput.append(offeredKey) }
        let response: SendResponse = try await post("v1/messages/" + queue.senderID) {
            SendRequest(message: message, expiresAt: expires, senderKey: offeredKey,
                        auth: try makeAuth(key: key, op: "send", queueID: queue.senderID, digestInput: digestInput))
        }
        guard response.status == "accepted", RelayQueueID.isValidMessage(response.id) else { throw GhostError.invalidPayload }
    }

    /// Fetches up to 64 own queues in one request. Per-queue failures come back as statuses.
    func fetch(_ queues: [InboundQueue]) async throws -> FetchResult {
        guard !queues.isEmpty, queues.count <= Self.maxFetchQueues, queues.allSatisfy({ $0.server == origin }) else { throw GhostError.invalidPayload }
        let keys = try queues.map { try Curve25519.Signing.PrivateKey(rawRepresentation: $0.recipientKey) }
        let result: FetchResult = try await post("v1/fetch") {
            FetchRequest(queues: try zip(queues, keys).map { queue, key in
                FetchItem(recipientId: queue.recipientID, auth: try makeAuth(key: key, op: "fetch", queueID: queue.recipientID, digestInput: Data()))
            })
        }
        let requested = Set(queues.map(\.recipientID))
        guard result.messages.allSatisfy({ requested.contains($0.recipientId) && RelayQueueID.isValidMessage($0.id) && $0.message.count <= Limits.maxWireBytes }),
              result.queues.allSatisfy({ requested.contains($0.recipientId) }) else { throw GhostError.invalidPayload }
        return result
    }

    func ack(_ queue: InboundQueue, ids: [String]) async throws {
        guard queue.server == origin else { throw GhostError.invalidPayload }
        let valid = ids.filter(RelayQueueID.isValidMessage)
        guard !valid.isEmpty else { return }
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: queue.recipientKey)
        for start in stride(from: 0, to: valid.count, by: 100) {
            let chunk = Array(valid[start..<min(start + 100, valid.count)])
            let _: ServerTime = try await post("v1/ack") {
                AckRequest(recipientId: queue.recipientID, ids: chunk,
                           auth: try makeAuth(key: key, op: "ack", queueID: queue.recipientID, digestInput: Data(chunk.joined(separator: ",").utf8)))
            }
        }
    }

    func delete(_ queue: InboundQueue) async throws {
        guard queue.server == origin else { throw GhostError.invalidPayload }
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: queue.recipientKey)
        do {
            let _: ServerTime = try await post("v1/delete") {
                DeleteRequest(recipientId: queue.recipientID, auth: try makeAuth(key: key, op: "delete", queueID: queue.recipientID, digestInput: Data()))
            }
        } catch GhostError.queueGone { /* already gone */ }
    }

    /// Registers this device's APNs token for own queues, or removes it when token is nil.
    /// The server keeps the mapping in RAM only and pushes a fixed "new message" text, nothing else.
    static func notifyDigestInput(token: String?, environment: String) -> Data { Data("\(token ?? "")|\(environment)".utf8) }

    func notify(_ queues: [InboundQueue], token: String?, environment: String) async throws -> [RelayQueueStatus] {
        guard !queues.isEmpty, queues.count <= Self.maxFetchQueues, queues.allSatisfy({ $0.server == origin }) else { throw GhostError.invalidPayload }
        let keys = try queues.map { try Curve25519.Signing.PrivateKey(rawRepresentation: $0.recipientKey) }
        let input = Self.notifyDigestInput(token: token, environment: environment)
        let response: NotifyResponse = try await post("v1/notify") {
            NotifyRequest(token: token, environment: environment, queues: try zip(queues, keys).map { queue, key in
                FetchItem(recipientId: queue.recipientID, auth: try makeAuth(key: key, op: "notify", queueID: queue.recipientID, digestInput: input))
            })
        }
        return response.queues
    }

    func close() { session.invalidateAndCancel() }

    // MARK: - Transport

    private func makeAuth(key: Curve25519.Signing.PrivateKey, op: String, queueID: String, digestInput: Data) throws -> RelayAuth {
        let timestamp = Int64((Date().timeIntervalSince1970 * 1000).rounded(.down)) + clockOffsetMs
        let nonce = SecureRandom.bytes(16).base64URLEncoded
        let message = RelaySigning.message(origin: origin, op: op, queueID: queueID, timestamp: timestamp, nonce: nonce,
                                           digest: RelaySigning.digest(digestInput))
        return RelayAuth(timestamp: timestamp, nonce: nonce, signature: try key.signature(for: message))
    }

    /// Builds the body twice at most: a clock_skew answer corrects the offset, then the request is re-signed once.
    private func post<Body: Encodable, Response: Decodable>(_ path: String, build: () throws -> Body) async throws -> Response {
        do {
            return try await perform(try makeRequest(path, method: "POST", body: try build()))
        } catch RelayFailure.clockSkew {
            do { return try await perform(try makeRequest(path, method: "POST", body: try build())) }
            catch RelayFailure.clockSkew { throw GhostError.clockSkew }
        }
    }

    private func makeRequest(_ path: String, method: String) throws -> URLRequest {
        guard let url = URL(string: origin + "/" + path) else { throw GhostError.invalidURL }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        return request
    }

    private func makeRequest<Body: Encodable>(_ path: String, method: String, body: Body) throws -> URLRequest {
        var request = try makeRequest(path, method: method)
        request.httpBody = try JSONEncoder().encode(body)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        return request
    }

    private func perform<Response: Decodable>(_ request: URLRequest) async throws -> Response {
        let result: (Data, URLResponse)
        do { result = try await session.data(for: request) }
        catch is CancellationError { throw CancellationError() }
        catch let error as URLError where error.code == .cancelled { throw CancellationError() }
        catch { throw GhostError.unavailable }
        try Task.checkCancellation()
        let (data, response) = result
        guard let http = response as? HTTPURLResponse, data.count <= 13_000_000 else { throw GhostError.tooLarge }
        if let time = try? JSONDecoder().decode(ServerTime.self, from: data) { noteServerTime(time.serverTime) }
        if (200...299).contains(http.statusCode) {
            do { return try JSONDecoder().decode(Response.self, from: data) }
            catch { throw GhostError.invalidPayload }
        }
        let code = (try? JSONDecoder().decode(ErrorResponse.self, from: data))?.error
        switch http.statusCode {
        case 401 where code == "clock_skew": throw RelayFailure.clockSkew
        case 401, 409: throw GhostError.unauthorized
        case 404: throw GhostError.queueGone
        case 413: throw GhostError.tooLarge
        case 429: throw GhostError.rateLimited
        case 503: throw GhostError.unavailable
        default: throw GhostError.server(http.statusCode)
        }
    }

    private func noteServerTime(_ serverTime: Int64) {
        guard serverTime > 0 else { return }
        clockOffsetMs = serverTime - Int64((Date().timeIntervalSince1970 * 1000).rounded(.down))
    }
}
