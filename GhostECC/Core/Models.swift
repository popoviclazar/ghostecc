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
    case invalidInvite, invitationUsed, queueGone, unauthorized, rateLimited, disconnected, groupNotConnected
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
        case .groupNotConnected: return String(localized: "Članovi grupe još nisu povezani. Slanje će raditi čim se povežu.")
        }
    }
}

enum Limits {
    static let maxWireBytes = 6_000_000
    static let maxTextBytes = 16_384
    static let maxPhotoBytes = 4_000_000
    static let maxVoiceBytes = 3_000_000
    static let maxFileBytes = 4_000_000
    /// Includes contacts created automatically inside groups.
    static let maxContacts = 200
    static let maxInvites = 20
    static let maxGroups = 30
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
    /// Set for connections the app made automatically between members of the listed groups ("introduced").
    /// They carry group messages only and stay out of the chat list until verified with the safety number.
    var introducedIn: [String]? = nil
    /// Message lifetime for this chat; nil follows the global setting.
    var lifetime: TimeInterval? = nil
    /// Muted: this contact's mailbox is left out of push registration, so the relay never notifies for it.
    var muted: Bool? = nil
    var title: String { name.isEmpty ? ghostID.short : name }
    var isIntroduced: Bool { introducedIn != nil }
}

struct PendingInvite: Codable, Identifiable, Equatable {
    static let lifetime: TimeInterval = 7 * 86_400
    let id: UUID
    var name: String
    let inbound: InboundQueue
    let link: String
    let preKeyID: UInt32
    let createdAt: Date
    /// Hidden one-time invitation made for exactly one member of a group; any other user is refused.
    var introduction: IntroductionTag? = nil
    var title: String { name.isEmpty ? "Pozivnica" : name }
    var expiresAt: Date { createdAt.addingTimeInterval(Self.lifetime) }
    func isExpired(now: Date = Date()) -> Bool { now >= expiresAt }
}

/// A chat a message can go to: a contact or a group.
struct ChatTarget: Identifiable, Hashable {
    let id: String
    let title: String
    let isGroup: Bool
}

struct IntroductionTag: Codable, Equatable {
    let groupID: String
    let member: GhostID
}

// MARK: - Groups

/// A group member as the admin lists it. The identity key lets members check the introductions.
struct GroupMember: Codable, Equatable {
    let ghostID: GhostID
    var name: String
    let identityKey: Data
}

enum GroupState: String, Codable { case invited, joined }

/// A group exists only on the members' phones. Every group message is encrypted separately for each member
/// over the pairwise Signal sessions; the relay never learns that a group exists.
struct GhostGroup: Codable, Identifiable, Equatable {
    static let maxMembers = 20
    static let chatPrefix = "group:"
    let id: String
    var name: String
    let admin: GhostID
    var members: [GroupMember]
    var state: GroupState
    let createdAt: Date
    /// Introduction links received before this device accepted the group, keyed by the inviting member.
    var pendingIntros: [String: String]? = nil
    /// The Ghost Lab group: local only, never saved, so groups can be tried on a single device.
    var isDemo: Bool? = nil
    /// Message lifetime for this group; nil follows the global setting.
    var lifetime: TimeInterval? = nil
    var chatID: String { Self.chatPrefix + id }
    var title: String { name.isEmpty ? String(localized: "Grupa") : name }
    func member(_ id: GhostID) -> GroupMember? { members.first { $0.ghostID == id } }
    static func isValidID(_ id: String) -> Bool { id.range(of: "^[A-Za-z0-9_-]{22}$", options: .regularExpression) != nil }
    static func newID() -> String { String(SecureRandom.bytes(16).base64URLEncoded.prefix(22)) }
}

/// Group context of a payload: content carries only the id, control messages carry what they change.
struct GroupInfo: Codable, Equatable {
    let id: String
    var name: String? = nil
    var admin: GhostID? = nil
    /// groupUpdate: the complete member list after the change.
    var members: [GroupMember]? = nil
    /// groupUpdate: the admin deleted the group.
    var dissolved: Bool? = nil
    /// groupIntro: the member the link is for (to the admin) or from (from the admin).
    var introFor: GhostID? = nil
    var link: String? = nil

    var isReferenceOnly: Bool { name == nil && admin == nil && members == nil && dissolved == nil && introFor == nil && link == nil }
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
    let forwarded: Bool
    let quote: Quote?
    let sentAt: Date
    let expiresAt: Date
    let receivedUptime: TimeInterval
    let remainingAtReceipt: TimeInterval
    var outgoing: Bool
    var status: MessageStatus
    /// Ciphertext kept in RAM only while a send can still be retried.
    var wire: Data?
    /// Reactions by sender; the empty string never stays (it removes a reaction).
    var reactions: [GhostID: String] = [:]
    var attachmentBytes: Int { (photo?.count ?? 0) + (voice?.count ?? 0) + (file?.data.count ?? 0) }
    /// The content again, for forwarding.
    var content: PrivatePayload.Content? {
        if let text { return .text(text) }
        if let photo { return .photo(photo) }
        if let voice { return .voice(voice) }
        if let file { return .file(file) }
        return nil
    }
    // A wall-clock rollback cannot extend an already loaded message's lifetime.
    func remaining(now: Date = Date(), uptime: TimeInterval = ProcessInfo.processInfo.systemUptime) -> TimeInterval {
        max(0, min(expiresAt.timeIntervalSince(now), remainingAtReceipt - max(0, uptime - receivedUptime)))
    }
}

// MARK: - Encrypted payload

enum PayloadKind: String, Codable { case text, photo, hello, ready, voice, file, groupUpdate, groupLeave, groupIntro, reaction, retract }

/// The message a reply refers to. The preview travels with the reply, so it still reads well after the original expired.
struct Quote: Codable, Equatable {
    static let maxPreviewCharacters = 120
    let id: UUID
    let sender: GhostID
    let preview: String
    var isWellFormed: Bool { preview.count <= Self.maxPreviewCharacters && preview.utf8.count <= 600 }
    /// Short text for a quote: the start of the text, or what kind of attachment it was.
    static func previewText(for message: ChatMessage) -> String {
        if let text = message.text { return String(text.prefix(maxPreviewCharacters)) }
        if message.voice != nil { return String(localized: "Glasovna poruka") }
        if let file = message.file { return String(String(localized: "Fajl: \(file.name)").prefix(maxPreviewCharacters)) }
        return String(localized: "Fotografija")
    }
}

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
    let group: GroupInfo?
    let forwarded: Bool?
    /// Content kinds: the message this one answers.
    let quote: Quote?
    /// reaction / retract: the message they refer to.
    let target: UUID?
    /// reaction: one emoji, or empty to remove the sender's reaction.
    let emoji: String?

    enum Content: Equatable { case text(String), photo(Data), voice(Data), file(FileAttachment) }

    init(sender: GhostID, recipient: GhostID, content: Content, lifetime: TimeInterval = 86_400, now: Date = Date(),
         id: UUID = UUID(), group: String? = nil, forwarded: Bool = false, quote: Quote? = nil) throws {
        guard lifetime > 0 && lifetime <= Self.maxLifetime else { throw GhostError.invalidPayload }
        var text: String?, photo: Data?, voice: Data?, file: FileAttachment?
        switch content {
        case .text(let value): text = value; kind = .text
        case .photo(let value): photo = value; kind = .photo
        case .voice(let value): voice = value; kind = .voice
        case .file(let value): file = value; kind = .file
        }
        try Self.checkContent(text: text, photo: photo, voice: voice, file: file)
        if let group { guard GhostGroup.isValidID(group) else { throw GhostError.invalidPayload } }
        version = 2; self.id = id
        self.sender = sender; self.recipient = recipient
        sentAt = now; expiresAt = now.addingTimeInterval(lifetime)
        self.text = text; self.photo = photo; self.voice = voice; self.file = file; reply = nil
        self.group = group.map { GroupInfo(id: $0) }
        self.forwarded = forwarded ? true : nil
        if let quote { guard quote.isWellFormed else { throw GhostError.invalidPayload } }
        self.quote = quote; target = nil; emoji = nil
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
        case .hello, .ready, .groupUpdate, .groupLeave, .groupIntro, .reaction, .retract: return nil
        }
    }
    private init(control: PayloadKind, sender: GhostID, recipient: GhostID, reply: ReplyAddress?, group: GroupInfo? = nil, now: Date) {
        version = 2; kind = control; id = UUID()
        self.sender = sender; self.recipient = recipient
        sentAt = now; expiresAt = now.addingTimeInterval(Self.maxLifetime)
        text = nil; photo = nil; voice = nil; file = nil; self.reply = reply
        self.group = group; forwarded = nil; quote = nil; target = nil; emoji = nil
    }
    private init(signal kind: PayloadKind, sender: GhostID, recipient: GhostID, target: UUID, emoji: String?, group: String?, now: Date) {
        version = 2; self.kind = kind; id = UUID()
        self.sender = sender; self.recipient = recipient
        sentAt = now; expiresAt = now.addingTimeInterval(Self.maxLifetime)
        text = nil; photo = nil; voice = nil; file = nil; reply = nil
        self.group = group.map { GroupInfo(id: $0) }; forwarded = nil; quote = nil
        self.target = target; self.emoji = emoji
    }
    /// A reaction to message `target`; an empty emoji removes the sender's reaction.
    static func reaction(sender: GhostID, recipient: GhostID, target: UUID, emoji: String, group: String? = nil, now: Date = Date()) -> PrivatePayload {
        PrivatePayload(signal: .reaction, sender: sender, recipient: recipient, target: target, emoji: emoji, group: group, now: now)
    }
    /// The sender takes back one of their own messages.
    static func retraction(sender: GhostID, recipient: GhostID, target: UUID, group: String? = nil, now: Date = Date()) -> PrivatePayload {
        PrivatePayload(signal: .retract, sender: sender, recipient: recipient, target: target, emoji: nil, group: group, now: now)
    }
    static func isValidEmoji(_ value: String) -> Bool { value.count <= 1 && value.utf8.count <= 32 }
    /// Group control messages: membership (admin to members), leaving (member to admin), introductions (via the admin).
    static func groupControl(_ kind: PayloadKind, sender: GhostID, recipient: GhostID, info: GroupInfo, now: Date = Date()) -> PrivatePayload {
        PrivatePayload(control: kind, sender: sender, recipient: recipient, reply: nil, group: info, now: now)
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
        if let group { guard GhostGroup.isValidID(group.id) else { throw GhostError.invalidPayload } }
        let noSignal = target == nil && emoji == nil
        let plainContent = reply == nil && (group?.isReferenceOnly ?? true) && noSignal && (quote?.isWellFormed ?? true)
        let control = present == 0 && reply == nil && forwarded == nil && quote == nil && noSignal
        let signal = present == 0 && reply == nil && forwarded == nil && quote == nil && target != nil && (group?.isReferenceOnly ?? true)
        switch kind {
        case .text: guard text != nil, present == 1, plainContent else { throw GhostError.invalidPayload }
        case .photo: guard photo != nil, present == 1, plainContent else { throw GhostError.invalidPayload }
        case .voice: guard voice != nil, present == 1, plainContent else { throw GhostError.invalidPayload }
        case .file: guard file != nil, present == 1, plainContent else { throw GhostError.invalidPayload }
        case .reaction:
            guard signal, let emoji, Self.isValidEmoji(emoji) else { throw GhostError.invalidPayload }
        case .retract:
            guard signal, emoji == nil else { throw GhostError.invalidPayload }
        case .hello:
            guard present == 0, group == nil, forwarded == nil, quote == nil, noSignal, let reply, RelayQueueID.isValid(reply.senderID),
                  (try? RelayOrigin.normalize(reply.server)) == reply.server else { throw GhostError.invalidPayload }
        case .ready:
            guard control, group == nil else { throw GhostError.invalidPayload }
        case .groupUpdate:
            guard control, let group, group.introFor == nil, group.link == nil, group.admin == sender else { throw GhostError.invalidPayload }
            if group.dissolved != true {
                guard let name = group.name, name.count <= 80, let members = group.members,
                      (2...GhostGroup.maxMembers).contains(members.count),
                      Set(members.map(\.ghostID)).count == members.count,
                      members.contains(where: { $0.ghostID == sender }),
                      members.allSatisfy({ $0.name.count <= 80 && $0.identityKey.count == 33 && GhostID(identityKey: $0.identityKey) == $0.ghostID })
                else { throw GhostError.invalidPayload }
            }
        case .groupLeave:
            guard control, let group, group.isReferenceOnly else { throw GhostError.invalidPayload }
        case .groupIntro:
            guard control, let group, group.introFor != nil, let link = group.link, (try? InviteLink.parse(link)) != nil,
                  group.name == nil, group.admin == nil, group.members == nil, group.dissolved == nil else { throw GhostError.invalidPayload }
        }
        guard expiresAt > now else { throw GhostError.expired }
        try Self.checkContent(text: text, photo: photo, voice: voice, file: file)
    }
    func display(outgoing: Bool, status: MessageStatus, now: Date = Date()) -> ChatMessage {
        ChatMessage(id: id, sender: sender, recipient: recipient, text: text, photo: photo, voice: voice, file: file,
                    preview: photo.flatMap { PhotoTools.thumbnail($0, maxPixel: 720) }, forwarded: forwarded == true, quote: quote,
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
