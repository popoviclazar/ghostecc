import Foundation
import CryptoKit
import UIKit

struct GhostID: Hashable, Codable, CustomStringConvertible {
    let rawValue: String
    init(_ input: String) throws {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard value.range(of: "^GHOST-[0-9A-F]{64}$", options: .regularExpression) != nil else { throw GhostError.invalidID }
        rawValue = value
    }
    init(identityKey: Data) { rawValue = "GHOST-" + SHA256.hash(data: identityKey).map { String(format: "%02X", $0) }.joined() }
    init(from decoder: Decoder) throws { try self.init(decoder.singleValueContainer().decode(String.self)) }
    func encode(to encoder: Encoder) throws { var c = encoder.singleValueContainer(); try c.encode(rawValue) }
    var description: String { rawValue }
    var short: String { String(rawValue.prefix(14)) + "…" + String(rawValue.suffix(6)) }
}

enum GhostError: LocalizedError {
    case invalidID, ownID, duplicateContact, blocked, unavailable, unverified, keyChanged
    case invalidPayload, expired, tooLarge, notConfigured, cryptoUnavailable, storage(Int32), limit
    case server(Int), invalidURL, unknownContact, clockSkew
    case invalidInvite, invitationUsed, queueGone, unauthorized, rateLimited, disconnected
    var errorDescription: String? {
        switch self {
        case .invalidID: return String(localized: "Ghost ID mora sadržati GHOST- i 64 heksadecimalna znaka.")
        case .ownID: return String(localized: "Ovo je tvoja sopstvena pozivnica.")
        case .duplicateContact: return String(localized: "Ovaj kontakt već postoji.")
        case .blocked: return String(localized: "Kontakt je blokiran.")
        case .unavailable: return String(localized: "Server nije dostupan. Provjeri internet vezu i pokušaj ponovo.")
        case .unverified: return String(localized: "Prvo uporedi sigurnosni broj sa sagovornikom.")
        case .keyChanged: return String(localized: "Sigurnosni ključ se ne podudara sa kontaktom. Radnja je zaustavljena.")
        case .invalidPayload: return String(localized: "Poruka nije važeća.")
        case .expired: return String(localized: "Poruka je istekla.")
        case .tooLarge: return String(localized: "Prekoračena dozvoljena veličina sadržaja.")
        case .notConfigured: return String(localized: "Veza sa serverom nije podešena. Pokušaj ponovo kasnije.")
        case .cryptoUnavailable: return String(localized: "Potrebna je instalacija LibSignalClient biblioteke. Nema slanja bez enkripcije.")
        case .storage: return String(localized: "Zaštićeno čuvanje nije dostupno. Otključaj uređaj i pokušaj ponovo.")
        case .limit: return String(localized: "Dostignut je limit ove verzije.")
        case .server(let status): return String(localized: "Server je odbio zahtjev (\(String(status))).")
        case .invalidURL: return String(localized: "Unesi HTTPS adresu servera bez putanje, kredencijala ili parametara.")
        case .unknownContact: return String(localized: "Kontakt ne postoji.")
        case .clockSkew: return String(localized: "Vrijeme servera i uređaja se razlikuje. Uključi automatsko vrijeme na iPhone-u.")
        case .invalidInvite: return String(localized: "Pozivnica nije važeća. Provjeri da li je kopirana cijela.")
        case .invitationUsed: return String(localized: "Pozivnica je već iskorišćena, otkazana ili je istekla. Zatraži novu.")
        case .queueGone: return String(localized: "Sandučić na serveru više ne postoji.")
        case .unauthorized: return String(localized: "Server je odbio potpis zahtjeva.")
        case .rateLimited: return String(localized: "Server je zauzet ili je dostignut limit. Pokušaj malo kasnije.")
        case .disconnected: return String(localized: "Veza sa ovim kontaktom je prekinuta. Povežite se ponovo novom pozivnicom.")
        }
    }
}

enum Limits {
    static let maxWireBytes = 6_000_000
    static let maxTextBytes = 16_384
    static let maxPhotoBytes = 4_000_000
    static let maxVoiceBytes = 3_000_000
    static let maxFileBytes = 4_000_000
    static let maxContacts = 50
    static let maxInvites = 20
    static let maxMessagesPerContact = 500
    /// RAM budget for photos, voice messages and files across all chats.
    static let maxPhotoMemory = 32_000_000
}

enum SecureRandom {
    static func bytes(_ count: Int) -> Data {
        SymmetricKey(size: SymmetricKeySize(bitCount: count * 8)).withUnsafeBytes { Data($0) }
    }
}

// MARK: - Contacts and relay queues

enum ConnectionState: String, Codable { case connecting, connected, disconnected }

/// A queue where this device receives. The recipient key never leaves the Keychain.
struct InboundQueue: Codable, Equatable {
    let server: String
    let recipientID: String
    let senderID: String
    let recipientKey: Data
}

/// A queue owned by the contact, where this device sends. The sender key secures it on first use.
struct OutboundQueue: Codable, Equatable {
    let server: String
    let senderID: String
    let senderKey: Data
    var secured: Bool
}

struct Contact: Identifiable, Codable, Equatable {
    var id: String { ghostID.rawValue }
    let ghostID: GhostID
    var name: String
    let identityKey: Data
    var verified = false
    var blocked = false
    var isDemo = false
    var state: ConnectionState = .connected
    var inbound: InboundQueue?
    var outbound: OutboundQueue?
    var title: String { name.isEmpty ? ghostID.short : name }
}

struct PendingInvite: Codable, Identifiable, Equatable {
    static let lifetime: TimeInterval = 7 * 86_400
    let id: UUID
    var name: String
    let inbound: InboundQueue
    let link: String
    let preKeyID: UInt32
    let createdAt: Date
    var title: String { name.isEmpty ? "Pozivnica" : name }
    var expiresAt: Date { createdAt.addingTimeInterval(Self.lifetime) }
    func isExpired(now: Date = Date()) -> Bool { now >= expiresAt }
}

// MARK: - Messages in RAM

enum MessageStatus: String { case local, sending, accepted, delivered, failed }
struct ChatMessage: Identifiable {
    let id: UUID
    let sender: GhostID
    let recipient: GhostID
    let text: String?
    let photo: Data?
    let voice: Data?
    let file: FileAttachment?
    let preview: UIImage?
    let sentAt: Date
    let expiresAt: Date
    let receivedUptime: TimeInterval
    let remainingAtReceipt: TimeInterval
    var outgoing: Bool
    var status: MessageStatus
    /// Ciphertext kept in RAM only while a send can still be retried.
    var wire: Data?
    var attachmentBytes: Int { (photo?.count ?? 0) + (voice?.count ?? 0) + (file?.data.count ?? 0) }
    // A wall-clock rollback cannot extend an already loaded message's lifetime.
    func remaining(now: Date = Date(), uptime: TimeInterval = ProcessInfo.processInfo.systemUptime) -> TimeInterval {
        max(0, min(expiresAt.timeIntervalSince(now), remainingAtReceipt - max(0, uptime - receivedUptime)))
    }
}

// MARK: - Encrypted payload

enum PayloadKind: String, Codable { case text, photo, hello, ready, voice, file }

/// A file sent as encrypted message content. The name is shown to the recipient and used when they
/// save or share it; the type is a UTType identifier.
struct FileAttachment: Codable, Equatable {
    static let maxNameLength = 120
    let name: String
    let type: String
    let data: Data
    static func cleanName(_ raw: String) -> String {
        var name = raw.components(separatedBy: CharacterSet(charactersIn: "/\\:").union(.controlCharacters)).joined(separator: "_")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        while name.hasPrefix(".") { name.removeFirst() }
        name = String(name.prefix(maxNameLength))
        return name.isEmpty ? "file" : name
    }
    var isWellFormed: Bool {
        !data.isEmpty && Self.cleanName(name) == name && !type.isEmpty && type.count <= 128
            && type.range(of: "^[A-Za-z0-9.+-]+$", options: .regularExpression) != nil
    }
}
struct ReplyAddress: Codable, Equatable {
    let server: String
    let senderID: String
}

struct PrivatePayload: Codable, Equatable {
    static let maxLifetime: TimeInterval = 86_400
    let version: Int
    let kind: PayloadKind
    let id: UUID
    let sender: GhostID
    let recipient: GhostID
    let sentAt: Date
    let expiresAt: Date
    let text: String?
    let photo: Data?
    let voice: Data?
    let file: FileAttachment?
    let reply: ReplyAddress?

    enum Content: Equatable { case text(String), photo(Data), voice(Data), file(FileAttachment) }

    init(sender: GhostID, recipient: GhostID, content: Content, lifetime: TimeInterval = 86_400, now: Date = Date()) throws {
        guard lifetime > 0 && lifetime <= Self.maxLifetime else { throw GhostError.invalidPayload }
        var text: String?, photo: Data?, voice: Data?, file: FileAttachment?
        switch content {
        case .text(let value): text = value; kind = .text
        case .photo(let value): photo = value; kind = .photo
        case .voice(let value): voice = value; kind = .voice
        case .file(let value): file = value; kind = .file
        }
        try Self.checkContent(text: text, photo: photo, voice: voice, file: file)
        version = 2; id = UUID()
        self.sender = sender; self.recipient = recipient
        sentAt = now; expiresAt = now.addingTimeInterval(lifetime)
        self.text = text; self.photo = photo; self.voice = voice; self.file = file; reply = nil
    }
    init(sender: GhostID, recipient: GhostID, text: String? = nil, photo: Data? = nil, lifetime: TimeInterval = 86_400, now: Date = Date()) throws {
        if let text, photo == nil { try self.init(sender: sender, recipient: recipient, content: .text(text), lifetime: lifetime, now: now) }
        else if let photo, text == nil { try self.init(sender: sender, recipient: recipient, content: .photo(photo), lifetime: lifetime, now: now) }
        else { throw GhostError.invalidPayload }
    }
    var content: Content? {
        switch kind {
        case .text: return text.map(Content.text)
        case .photo: return photo.map(Content.photo)
        case .voice: return voice.map(Content.voice)
        case .file: return file.map(Content.file)
        case .hello, .ready: return nil
        }
    }
    private init(control: PayloadKind, sender: GhostID, recipient: GhostID, reply: ReplyAddress?, now: Date) {
        version = 2; kind = control; id = UUID()
        self.sender = sender; self.recipient = recipient
        sentAt = now; expiresAt = now.addingTimeInterval(Self.maxLifetime)
        text = nil; photo = nil; voice = nil; file = nil; self.reply = reply
    }
    /// First message on a one-time invitation: tells the inviter where to answer.
    static func hello(sender: GhostID, recipient: GhostID, reply: ReplyAddress, now: Date = Date()) -> PrivatePayload {
        PrivatePayload(control: .hello, sender: sender, recipient: recipient, reply: reply, now: now)
    }
    /// The inviter's answer: confirms the connection and secures the joiner's queue.
    static func ready(sender: GhostID, recipient: GhostID, now: Date = Date()) -> PrivatePayload {
        PrivatePayload(control: .ready, sender: sender, recipient: recipient, reply: nil, now: now)
    }
    static func checkContent(text: String? = nil, photo: Data? = nil, voice: Data? = nil, file: FileAttachment? = nil) throws {
        if let text { guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, text.utf8.count <= Limits.maxTextBytes else { throw GhostError.tooLarge } }
        if let photo { guard !photo.isEmpty, photo.count <= Limits.maxPhotoBytes else { throw GhostError.tooLarge } }
        if let voice {
            guard voice.count <= Limits.maxVoiceBytes else { throw GhostError.tooLarge }
            guard WAV.isValid(voice) else { throw GhostError.invalidPayload }
        }
        if let file {
            guard file.data.count <= Limits.maxFileBytes else { throw GhostError.tooLarge }
            guard file.isWellFormed else { throw GhostError.invalidPayload }
        }
    }
    func validate(sender expectedSender: GhostID, recipient expectedRecipient: GhostID, now: Date = Date()) throws {
        guard version == 2, sender == expectedSender, recipient == expectedRecipient,
              expiresAt > sentAt, expiresAt.timeIntervalSince(sentAt) <= Self.maxLifetime,
              sentAt.timeIntervalSince(now) <= 120 else { throw GhostError.invalidPayload }
        // Exactly one kind of content per message, matching the declared kind.
        let present = [text != nil, photo != nil, voice != nil, file != nil].filter { $0 }.count
        switch kind {
        case .text: guard text != nil, present == 1, reply == nil else { throw GhostError.invalidPayload }
        case .photo: guard photo != nil, present == 1, reply == nil else { throw GhostError.invalidPayload }
        case .voice: guard voice != nil, present == 1, reply == nil else { throw GhostError.invalidPayload }
        case .file: guard file != nil, present == 1, reply == nil else { throw GhostError.invalidPayload }
        case .hello:
            guard present == 0, let reply, RelayQueueID.isValid(reply.senderID),
                  (try? RelayOrigin.normalize(reply.server)) == reply.server else { throw GhostError.invalidPayload }
        case .ready:
            guard present == 0, reply == nil else { throw GhostError.invalidPayload }
        }
        guard expiresAt > now else { throw GhostError.expired }
        try Self.checkContent(text: text, photo: photo, voice: voice, file: file)
    }
    func display(outgoing: Bool, status: MessageStatus, now: Date = Date()) -> ChatMessage {
        ChatMessage(id: id, sender: sender, recipient: recipient, text: text, photo: photo, voice: voice, file: file,
                    preview: photo.flatMap { PhotoTools.thumbnail($0, maxPixel: 720) },
                    sentAt: sentAt, expiresAt: expiresAt, receivedUptime: ProcessInfo.processInfo.systemUptime,
                    remainingAtReceipt: max(0, expiresAt.timeIntervalSince(now)), outgoing: outgoing, status: status, wire: nil)
    }
}

/// Fixed-size buckets so the ciphertext length does not reveal the message length.
enum WirePadding {
    static func bucket(for length: Int) -> Int {
        let framed = length + 4
        for size in [1_024, 4_096, 16_384, 65_536] where framed <= size { return size }
        let step = 262_144
        return (framed + step - 1) / step * step
    }
    static func pad(_ data: Data) -> Data {
        let size = bucket(for: data.count)
        var out = Data(capacity: size)
        var length = UInt32(data.count).bigEndian
        withUnsafeBytes(of: &length) { out.append(contentsOf: $0) }
        out.append(data)
        out.append(Data(repeating: 0, count: size - out.count))
        return out
    }
    static func unpad(_ data: Data) throws -> Data {
        guard data.count >= 4 else { throw GhostError.invalidPayload }
        let length = data.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
        guard length <= data.count - 4 else { throw GhostError.invalidPayload }
        let start = data.startIndex + 4
        return Data(data[start..<(start + length)])
    }
}

/// Binary frame stored on the relay: version, libsignal message type, ciphertext. No IDs, no sender.
struct WireEnvelope: Equatable {
    static let version: UInt8 = 2
    let messageType: UInt8
    let ciphertext: Data
    init(messageType: UInt8, ciphertext: Data) { self.messageType = messageType; self.ciphertext = ciphertext }
    init(bytes: Data) throws {
        guard bytes.count > 2, bytes.count <= Limits.maxWireBytes, bytes[bytes.startIndex] == Self.version else { throw GhostError.invalidPayload }
        messageType = bytes[bytes.startIndex + 1]
        ciphertext = Data(bytes.dropFirst(2))
    }
    var bytes: Data { var data = Data([Self.version, messageType]); data.append(ciphertext); return data }
}

enum WireCodec {
    static func encoder() -> JSONEncoder { let e = JSONEncoder(); e.dateEncodingStrategy = .millisecondsSince1970; e.outputFormatting = .sortedKeys; return e }
    static func decoder() -> JSONDecoder { let d = JSONDecoder(); d.dateDecodingStrategy = .millisecondsSince1970; return d }
}

// MARK: - Safety number QR

/// QR form of the 60-digit safety number. Both people see the same number, so scanning the other
/// phone's code and getting an exact match proves nobody is between them.
enum SafetyCode {
    static let prefix = "ghost-ecc://verify/"
    static func link(_ number: String) -> String { prefix + number.filter(\.isNumber) }
    static func matches(_ scanned: String, _ number: String) -> Bool {
        let digits = number.filter(\.isNumber)
        return digits.count == 60 && scanned == link(number)
    }
}

// MARK: - One-time invitation link

/// ghost-ecc://invite/<base64url JSON>: relay origin, the inviter's queue, identity key and the key
/// that decrypts the prekey bundle stored on the relay. The relay never sees the link key.
struct InviteLink: Codable, Equatable {
    static let prefix = "ghost-ecc://invite/"
    let v: Int
    let s: String
    let q: String
    let k: Data
    let x: Data
    var ghostID: GhostID { GhostID(identityKey: k) }
    func string() throws -> String { Self.prefix + (try WireCodec.encoder().encode(self)).base64URLEncoded }
    static func parse(_ input: String) throws -> InviteLink {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.count < 2048, value.hasPrefix(prefix),
              let bytes = Data(base64URL: String(value.dropFirst(prefix.count))),
              let link = try? WireCodec.decoder().decode(InviteLink.self, from: bytes) else { throw GhostError.invalidInvite }
        guard link.v == 1, link.k.count == 33, link.x.count == 32, RelayQueueID.isValid(link.q),
              (try? RelayOrigin.normalize(link.s)) == link.s else { throw GhostError.invalidInvite }
        return link
    }
}

enum InviteCrypto {
    static func associatedData(identityKey: Data) -> Data { Data(("GHOST-INVITE-v1|" + identityKey.base64EncodedString()).utf8) }
    static func seal(_ bundle: KeyBundleDTO, key: Data) throws -> Data {
        let plaintext = try WireCodec.encoder().encode(bundle)
        let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key), authenticating: associatedData(identityKey: bundle.identityKey))
        guard let combined = box.combined else { throw GhostError.invalidPayload }
        return combined
    }
    static func open(_ blob: Data, link: InviteLink) throws -> KeyBundleDTO {
        guard blob.count <= 16_384 else { throw GhostError.invalidInvite }
        let plaintext: Data
        do {
            let box = try AES.GCM.SealedBox(combined: blob)
            plaintext = try AES.GCM.open(box, using: SymmetricKey(data: link.x), authenticating: associatedData(identityKey: link.k))
        } catch { throw GhostError.invalidInvite }
        let bundle = try WireCodec.decoder().decode(KeyBundleDTO.self, from: plaintext)
        guard bundle.identityKey == link.k, bundle.id == link.ghostID, bundle.deviceID == 1 else { throw GhostError.keyChanged }
        return bundle
    }
}

extension Data {
    var base64URLEncoded: String { base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
    init?(base64URL: String) {
        var value = base64URL.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        value += String(repeating: "=", count: (4 - value.count % 4) % 4)
        self.init(base64Encoded: value)
    }
}
