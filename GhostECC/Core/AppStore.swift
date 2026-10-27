import SwiftUI
import LocalAuthentication
import UIKit
import CryptoKit
import UserNotifications
import AudioToolbox

@MainActor
final class AppStore: ObservableObject {
    @Published private(set) var identity: GhostID?
    @Published private(set) var publicKey: Data?
    @Published private(set) var contacts: [Contact] = []
    @Published private(set) var invites: [PendingInvite] = []
    @Published private(set) var messages: [String: [ChatMessage]] = [:]
    /// Unread counts per contact, RAM only like the messages themselves.
    @Published private(set) var unread: [String: Int] = [:]
    @Published private(set) var settings = AppSettings()
    @Published var locked = true
    @Published var covered = false
    @Published var captured = false
    @Published private(set) var loading = true
    @Published private(set) var busy = false
    @Published private(set) var networkStatus = String(localized: "Nema aktivnih veza")
    @Published private(set) var networkHealthy = false
    @Published var pendingLink: String?
    /// Verifier of the optional app passcode; nil means the device's own authentication is used.
    @Published private(set) var pinRecord: PinRecord?
    var pinEnabled: Bool { pinRecord != nil }
    @Published var error: String?
    @Published var notice: String?

    private let engine = SignalEngine()
    private let vault = KeychainVault()
    private var relays: [String: RelayClient] = [:]
    private var demo: LocalPeer?
    private var demoEngine: SignalEngine?
    private var syncTask: Task<Void, Never>?
    private var syncing = false
    private var timer: Timer?
    private var seen: [UUID: Date] = [:]
    private var lastProtocolRetry = Date.distantPast
    private var helloSentAt: [String: Date] = [:]
    private var generation = UUID()
    private var unlocking = false
    private var foreground = true
    private var deviceToken: String?
    private var registeredPush = Set<String>()
    private var tokenObserver: NSObjectProtocol?
    private var lastIncomingFeedback = Date.distantPast
    private var awaitingSystemSettings = false
    private var activeChatID: String?

    var cryptoAvailable: Bool { SignalEngine.available }
    var shouldCover: Bool { covered || locked || (settings.hideDuringCapture && captured) }
    static var screenCaptured: Bool {
        UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.contains { $0.screen.isCaptured }
    }

    init() {
        captured = Self.screenCaptured
        // .common keeps expiry running while the user scrolls.
        let timer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.purge() }
        }
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
        tokenObserver = NotificationCenter.default.addObserver(forName: .ghostDeviceToken, object: nil, queue: .main) { [weak self] note in
            let token = note.object as? String
            Task { @MainActor in await self?.deviceTokenChanged(token) }
        }
    }

    // MARK: - Lifecycle

    func boot() async {
        loading = true
        do {
            loadPin()
            if let local = try await engine.loadIdentity() {
                identity = local.0; publicKey = local.1
                if let metadata = try vault.load("metadata") {
                    let decoded = try WireCodec.decoder().decode(LocalMetadata.self, from: metadata)
                    contacts = decoded.contacts.filter { !$0.isDemo }; invites = decoded.invites; settings = decoded.settings
                }
                locked = settings.lockEnabled
                if settings.notificationsEnabled { UIApplication.shared.registerForRemoteNotifications() }
            } else { locked = false }
        } catch { self.error = error.localizedDescription; locked = true }
        loading = false
        refreshNetworkStatus()
        if !locked { startSync(); await promptForNotificationsIfNeeded() }
    }

    func createIdentity() async {
        guard !busy else { return }; busy = true; defer { busy = false }
        do {
            guard let local = try await engine.loadIdentity(create: true) else { throw GhostError.cryptoUnavailable }
            identity = local.0; publicKey = local.1; locked = false
            try persistMetadata()
            notice = String(localized: "Ghost ID je napravljen. Ključevi se ne izvoze i nema oporavka preko bekapa.")
        } catch { self.error = error.localizedDescription; return }
        await promptForNotificationsIfNeeded()
    }

    /// Without an app passcode: Face ID / Touch ID with the device passcode as fallback.
    /// With an app passcode: optionally Face ID only (no device passcode fallback); otherwise the passcode screen.
    func unlock() async {
        guard !unlocking else { return }; unlocking = true; defer { unlocking = false }
        if var record = pinRecord {
            guard settings.pinWithBiometrics else { return }
            let context = LAContext()
            context.localizedFallbackTitle = ""
            var unavailable: NSError?
            guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &unavailable) else { return }
            guard (try? await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: String(localized: "Otključaj Ghost ECC"))) == true else { return }
            if let saved = record.biometryState, saved != context.evaluatedPolicyDomainState {
                notice = String(localized: "Face ID ili Touch ID podaci na telefonu su promijenjeni. Unesi šifru aplikacije.")
                return
            }
            if record.failedAttempts > 0 || record.lockedUntil != nil {
                record.failedAttempts = 0; record.lockedUntil = nil
                try? savePin(record)
            }
            await finishUnlock()
            return
        }
        do {
            let context = LAContext()
            let accepted = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: String(localized: "Otključaj Ghost ECC"))
            guard accepted else { return }
            await finishUnlock()
        } catch { self.error = String(localized: "Otključavanje nije uspjelo.") }
    }

    private func finishUnlock() async {
        if identity == nil { await boot() }
        locked = false; purge(); startSync()
        await promptForNotificationsIfNeeded()
    }

    // MARK: - App passcode

    private func loadPin() {
        guard let data = try? vault.load("pin") else { pinRecord = nil; return }
        pinRecord = try? WireCodec.decoder().decode(PinRecord.self, from: data)
    }

    private func savePin(_ record: PinRecord?) throws {
        if let record { try vault.save(WireCodec.encoder().encode(record), account: "pin") }
        else { try vault.delete("pin") }
        pinRecord = record
    }

    /// Current Face ID / Touch ID enrollment fingerprint, or nil when biometrics are unavailable.
    static func biometryState() -> Data? {
        let context = LAContext()
        var unavailable: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &unavailable) else { return nil }
        return context.evaluatedPolicyDomainState
    }

    /// Checking is deliberately slow (PBKDF2), so it runs off the main thread.
    private func pinMatches(_ pin: String, _ record: PinRecord) async -> Bool {
        await Task.detached(priority: .userInitiated) { AppPIN.matches(pin, record) }.value
    }

    func unlock(pin: String) async {
        guard !unlocking, var record = pinRecord else { return }
        if let until = record.lockedUntil, until > Date() { return }
        unlocking = true; defer { unlocking = false }
        if await pinMatches(pin, record) {
            record.failedAttempts = 0; record.lockedUntil = nil
            record.biometryState = Self.biometryState()
            try? savePin(record)
            await finishUnlock()
            return
        }
        record.failedAttempts += 1
        let wait = AppPIN.delay(afterFailures: record.failedAttempts)
        record.lockedUntil = wait > 0 ? Date().addingTimeInterval(wait) : nil
        try? savePin(record)
        if settings.pinWipeAfterFailures && record.failedAttempts >= AppPIN.wipeAfter {
            unlocking = false
            await eraseAccount()
            notice = String(localized: "Previše pogrešnih šifri: identitet, ključevi i kontakti su obrisani sa ovog uređaja.")
        }
    }

    /// Setting a passcode turns the lock on; changing it needs the current one.
    func setPIN(_ pin: String, current: String?) async -> Bool {
        guard !busy else { return false }
        busy = true; defer { busy = false }
        if let record = pinRecord {
            guard let current, await pinMatches(current, record) else { error = String(localized: "Trenutna šifra nije tačna."); return false }
        }
        guard AppPIN.isValidFormat(pin) else { error = String(localized: "Šifra mora imati od 6 do 16 cifara."); return false }
        do {
            var record = try await Task.detached(priority: .userInitiated) { try AppPIN.makeRecord(pin) }.value
            record.biometryState = Self.biometryState()
            try savePin(record)
            if !settings.lockEnabled { var value = settings; value.lockEnabled = true; updateSettings(value) }
            notice = String(localized: "Šifra aplikacije je sačuvana. Šifra telefona više ne otključava Ghost ECC.")
            return true
        } catch { self.error = error.localizedDescription; return false }
    }

    func removePIN(current: String) async -> Bool {
        guard !busy, let record = pinRecord else { return false }
        busy = true; defer { busy = false }
        guard await pinMatches(current, record) else { error = String(localized: "Trenutna šifra nije tačna."); return false }
        do { try savePin(nil); return true } catch { self.error = error.localizedDescription; return false }
    }

    /// Inactive (Control Center, app switcher) only covers the screen; background locks and stops networking.
    func sceneChanged(_ phase: ScenePhase) {
        purge()
        switch phase {
        case .active:
            foreground = true; covered = false; captured = Self.screenCaptured
            // New messages are shown in the app; re-register push in case the relay restarted (its mapping is RAM-only).
            UNUserNotificationCenter.current().removeAllDeliveredNotifications()
            registeredPush = []
            Task { await refreshNotificationAuthorization() }
            if !locked { startSync() }
        case .inactive:
            covered = true
        case .background:
            foreground = false; covered = true; stopSync()
            if settings.lockEnabled && identity != nil { locked = true }
            // Optional: nothing readable stays in memory once the app is left, not even unread messages.
            if settings.wipeOnLeave { messages = [:]; unread = [:] }
        @unknown default:
            covered = true
        }
    }

    func openLink(_ url: URL) {
        let value = url.absoluteString
        guard value.hasPrefix(InviteLink.prefix) else { return }
        pendingLink = value
    }

    // MARK: - Settings

    private func persistMetadata() throws {
        let metadata = LocalMetadata(contacts: contacts.filter { !$0.isDemo }, invites: invites, settings: settings)
        try vault.save(WireCodec.encoder().encode(metadata), account: "metadata")
    }

    func updateSettings(_ value: AppSettings) {
        guard [300.0, 3600.0, 86_400.0].contains(value.lifetime) else { return }
        let previous = settings; settings = value
        do { try persistMetadata() } catch { settings = previous; self.error = error.localizedDescription }
    }

    private func relay(for origin: String) throws -> RelayClient {
        if let existing = relays[origin] { return existing }
        let client = try RelayClient(origin: origin)
        relays[origin] = client
        return client
    }

    // MARK: - Invitations

    /// Inviter: one-time queue on the own relay, holding a prekey bundle encrypted with a key that exists only in the link.
    func createInvite(name: String) async -> PendingInvite? {
        guard !busy, identity != nil, let key = publicKey else { return nil }
        busy = true; defer { busy = false }
        var bundleID: UInt32?
        do {
            guard invites.count < Limits.maxInvites, contacts.count < Limits.maxContacts else { throw GhostError.limit }
            let bundle = try await engine.invitationBundle()
            bundleID = bundle.preKey.id
            let linkKey = SecureRandom.bytes(32)
            let sealed = try InviteCrypto.seal(bundle, key: linkKey)
            let client = try relay(for: AppConfig.defaultServer)
            let inbound = try await client.createQueue(invitation: sealed)
            let link = try InviteLink(v: 1, s: inbound.server, q: inbound.senderID, k: key, x: linkKey).string()
            let invite = PendingInvite(id: UUID(), name: String(name.trimmingCharacters(in: .whitespacesAndNewlines).prefix(80)),
                                       inbound: inbound, link: link, preKeyID: bundle.preKey.id, createdAt: Date())
            invites.append(invite)
            do { try persistMetadata() } catch {
                invites.removeAll { $0.id == invite.id }
                try? await client.delete(inbound)
                throw error
            }
            refreshNetworkStatus()
            startSync()
            return invite
        } catch {
            if let bundleID { try? await engine.discardBundle(id: bundleID) }
            self.error = error.localizedDescription
            return nil
        }
    }

    func cancelInvite(_ id: UUID) async {
        guard let invite = invites.first(where: { $0.id == id }) else { return }
        invites.removeAll { $0.id == id }
        do { try persistMetadata() } catch { invites.append(invite); self.error = error.localizedDescription; return }
        try? await engine.discardBundle(id: invite.preKeyID)
        if let client = try? relay(for: invite.inbound.server) { try? await client.delete(invite.inbound) }
        refreshNetworkStatus()
    }

    /// Joiner: opens the sealed bundle, starts the Signal session, creates an own queue and sends hello.
    func acceptInvite(_ input: String, name: String) async -> Bool {
        guard !busy, let me = identity else { return false }
        busy = true; defer { busy = false }
        do {
            let link = try InviteLink.parse(input)
            let peer = link.ghostID
            guard peer != me else { throw GhostError.ownID }
            guard !contacts.contains(where: { $0.ghostID == peer }) else { throw GhostError.duplicateContact }
            guard contacts.count < Limits.maxContacts else { throw GhostError.limit }
            let sealed = try await relay(for: link.s).invitation(senderID: link.q)
            let bundle = try InviteCrypto.open(sealed, link: link)
            try await engine.prepareSession(bundle)
            let home = AppConfig.defaultServer
            let inbound = try await relay(for: home).createQueue(invitation: nil)
            let outbound = OutboundQueue(server: link.s, senderID: link.q, senderKey: Curve25519.Signing.PrivateKey().rawRepresentation, secured: false)
            let contact = Contact(ghostID: peer, name: String(name.trimmingCharacters(in: .whitespacesAndNewlines).prefix(80)),
                                  identityKey: link.k, state: .connecting, inbound: inbound, outbound: outbound)
            contacts.append(contact)
            do { try persistMetadata() } catch {
                contacts.removeAll { $0.ghostID == peer }
                if let client = try? relay(for: home) { try? await client.delete(inbound) }
                throw error
            }
            pendingLink = nil
            startSync()
            await sendProtocol(.hello, to: contact.id)
            if self.contact(contact.id)?.outbound?.secured != true {
                notice = String(localized: "Kontakt je dodat. Povezivanje će se završiti automatski kada server bude dostupan.")
            }
            return true
        } catch {
            self.error = error.localizedDescription
            return false
        }
    }

    /// Inviter: hello arrived on the one-time queue. The queue becomes this contact's inbound queue.
    private func completeInvite(_ invite: PendingInvite, payload: PrivatePayload, senderKey: Data) async {
        guard let me = identity, payload.kind == .hello, let reply = payload.reply,
              invites.contains(where: { $0.id == invite.id }) else { return }
        let peer = GhostID(identityKey: senderKey)
        guard peer != me, !contacts.contains(where: { $0.ghostID == peer }), contacts.count < Limits.maxContacts else {
            notice = String(localized: "Pozivnicu je iskoristio postojeći kontakt ili je dostignut limit kontakata.")
            invites.removeAll { $0.id == invite.id }
            try? persistMetadata()
            return
        }
        let outbound = OutboundQueue(server: reply.server, senderID: reply.senderID, senderKey: Curve25519.Signing.PrivateKey().rawRepresentation, secured: false)
        let contact = Contact(ghostID: peer, name: invite.name, identityKey: senderKey, state: .connected, inbound: invite.inbound, outbound: outbound)
        let previousInvites = invites, previousContacts = contacts
        invites.removeAll { $0.id == invite.id }
        contacts.append(contact)
        do { try persistMetadata() } catch {
            invites = previousInvites; contacts = previousContacts; self.error = error.localizedDescription; return
        }
        notice = String(localized: "\(contact.title) se povezao preko pozivnice. Uporedi sigurnosni broj prije slanja poruka.")
        await sendProtocol(.ready, to: contact.id)
    }

    /// hello (joiner) and ready (inviter) secure the other side's queue. Unsecured queues are retried by sync.
    private func sendProtocol(_ kind: PayloadKind, to contactID: String) async {
        guard let me = identity, let contact = self.contact(contactID), !contact.isDemo, var outbound = contact.outbound else { return }
        let wasSecured = outbound.secured
        do {
            let payload: PrivatePayload
            switch kind {
            case .hello:
                guard let inbound = contact.inbound else { return }
                payload = PrivatePayload.hello(sender: me, recipient: contact.ghostID, reply: ReplyAddress(server: inbound.server, senderID: inbound.senderID))
            case .ready:
                payload = PrivatePayload.ready(sender: me, recipient: contact.ghostID)
            case .text, .photo, .voice, .file:
                return
            }
            let wire = try await engine.encrypt(payload)
            try await relay(for: outbound.server).send(wire, to: outbound, expiresAt: payload.expiresAt)
            outbound.secured = true
            let secured = outbound
            updateContact(contactID) { $0.outbound = secured }
            if kind == .hello { helloSentAt[contactID] = Date() }
        } catch GhostError.queueGone {
            updateContact(contactID) { $0.state = .disconnected }
        } catch GhostError.unauthorized where !wasSecured {
            // Someone else used the invitation first.
            updateContact(contactID) { $0.state = .disconnected }
            notice = GhostError.invitationUsed.localizedDescription
        } catch {
            // Network or server busy: sync retries while the queue is unsecured.
        }
    }

    /// Unsecured queues get hello/ready again. A hello lives 24 h on the relay while an invitation is valid 7 days,
    /// so a joiner still waiting for ready repeats hello every 6 h; the inviter ignores duplicates.
    private func retryProtocolMessages(now: Date = Date()) async {
        for contact in contacts where !contact.isDemo && contact.state != .disconnected {
            guard let outbound = contact.outbound else { continue }
            if !outbound.secured {
                await sendProtocol(contact.state == .connecting ? .hello : .ready, to: contact.id)
            } else if contact.state == .connecting, now.timeIntervalSince(helloSentAt[contact.id] ?? .distantPast) > 6 * 3600 {
                await sendProtocol(.hello, to: contact.id)
            }
        }
    }

    private func dropExpiredInvites(now: Date = Date()) {
        let expired = invites.filter { $0.isExpired(now: now) }
        guard !expired.isEmpty else { return }
        invites.removeAll { $0.isExpired(now: now) }
        try? persistMetadata()
        for invite in expired {
            let client = try? relay(for: invite.inbound.server)
            Task {
                try? await self.engine.discardBundle(id: invite.preKeyID)
                try? await client?.delete(invite.inbound)
            }
        }
    }

    // MARK: - Contacts

    func contact(_ id: String) -> Contact? { contacts.first { $0.id == id } }

    private func updateContact(_ id: String, _ change: (inout Contact) -> Void) {
        guard let i = contacts.firstIndex(where: { $0.id == id }) else { return }
        let old = contacts[i]
        change(&contacts[i])
        guard contacts[i] != old, !old.isDemo else { return }
        do { try persistMetadata() } catch { contacts[i] = old; self.error = error.localizedDescription }
    }

    func addDemo() async {
        guard !busy, identity != nil, demo == nil else { return }; busy = true; defer { busy = false }
        do {
            let peer = LocalPeer(); let contact = try await peer.contact()
            let bundle = try await peer.bundle()
            let sender = try await engine.localTestClone()
            try await sender.prepareSession(bundle)
            demoEngine = sender; demo = peer; contacts.append(contact)
            notice = String(localized: "Ghost Lab je lokalni test. Nijedna poruka ne ide na drugi uređaj.")
        } catch { self.error = error.localizedDescription }
    }

    func safetyNumber(for id: String) async throws -> String {
        guard let contact = self.contact(id) else { throw GhostError.unknownContact }
        return try await engine.safetyNumber(remoteID: contact.ghostID, remoteKey: contact.identityKey)
    }

    func setVerified(_ id: String, value: Bool) { updateContact(id) { $0.verified = value } }

    func setBlocked(_ id: String, value: Bool) {
        updateContact(id) { $0.blocked = value }
        if value { messages[id] = [] }
    }

    func deleteContact(_ id: String) {
        guard let contact = self.contact(id) else { return }
        let old = contacts
        contacts.removeAll { $0.id == id }
        do { try persistMetadata() } catch { contacts = old; self.error = error.localizedDescription; return }
        messages[id] = nil; unread[id] = nil
        if contact.isDemo { demo = nil; demoEngine = nil; return }
        // Deleting the own inbound queue tells the contact's app that the connection is gone (their sends get 404).
        let client = contact.inbound.flatMap { try? relay(for: $0.server) }
        Task {
            try? await self.engine.forget(contact.ghostID)
            if let client, let inbound = contact.inbound { try? await client.delete(inbound) }
        }
        refreshNetworkStatus()
    }

    func clearChat(_ id: String) { messages[id] = []; unread[id] = nil }

    /// The open chat counts as read; everything else collects an unread badge.
    func chatOpened(_ id: String) {
        activeChatID = id
        if unread[id] != nil { unread[id] = nil }
    }
    func chatClosed(_ id: String) { if activeChatID == id { activeChatID = nil } }

    func renameContact(_ id: String, to name: String) {
        updateContact(id) { $0.name = String(name.trimmingCharacters(in: .whitespacesAndNewlines).prefix(80)) }
    }

    // MARK: - Messages

    func purge(now: Date = Date()) {
        // Only touch @Published state when something actually expired, so SwiftUI does not redraw every second.
        for id in Array(messages.keys) {
            guard let list = messages[id], list.contains(where: { $0.remaining(now: now) <= 0 }) else { continue }
            messages[id] = list.filter { $0.remaining(now: now) > 0 }
        }
        if seen.contains(where: { $0.value <= now }) { seen = seen.filter { $0.value > now } }
    }

    private var attachmentBytes: Int { messages.values.flatMap { $0 }.reduce(0) { $0 + $1.attachmentBytes } }

    func send(text: String? = nil, photo: Data? = nil, to id: String) async -> Bool {
        if let text { return await send(.text(text), to: id) }
        if let photo { return await send(.photo(photo), to: id) }
        return false
    }

    func send(_ content: PrivatePayload.Content, to id: String) async -> Bool {
        guard !shouldCover, let me = identity, let key = publicKey else { return false }
        var appended: UUID?
        do {
            guard let contact = self.contact(id) else { throw GhostError.unknownContact }
            guard !contact.blocked else { throw GhostError.blocked }
            guard contact.verified else { throw GhostError.unverified }
            guard contact.state != .disconnected else { throw GhostError.disconnected }
            let payload = try PrivatePayload(sender: me, recipient: contact.ghostID, content: content, lifetime: settings.lifetime)
            guard (messages[id]?.count ?? 0) < Limits.maxMessagesPerContact,
                  attachmentBytes + (payload.photo?.count ?? 0) + (payload.voice?.count ?? 0) + (payload.file?.data.count ?? 0) < Limits.maxPhotoMemory else { throw GhostError.limit }
            if contact.isDemo {
                guard let demo, let demoEngine else { throw GhostError.unavailable }
                let wire = try await demoEngine.encrypt(payload)
                messages[id, default: []].append(payload.display(outgoing: true, status: .sending)); appended = payload.id
                let echo = try await demo.respond(to: wire, senderKey: key)
                let opened = try await demoEngine.decrypt(echo, expectedKey: contact.identityKey)
                accept(opened.payload, from: id)
                updateStatus(payload.id, in: id, status: .local)
                return true
            }
            guard let outbound = contact.outbound else { throw GhostError.disconnected }
            let wire = try await engine.encrypt(payload)
            var message = payload.display(outgoing: true, status: .sending)
            message.wire = wire
            messages[id, default: []].append(message); appended = payload.id
            await deliver(payload.id, wire: wire, expiresAt: payload.expiresAt, contactID: id, outbound: outbound)
            return true
        } catch {
            if let appended { updateStatus(appended, in: id, status: .failed) }
            self.error = error.localizedDescription
            return false
        }
    }

    /// Delivery problems are shown on the bubble, with a retry that resends the same ciphertext.
    private func deliver(_ messageID: UUID, wire: Data, expiresAt: Date, contactID: String, outbound: OutboundQueue) async {
        updateStatus(messageID, in: contactID, status: .sending)
        do {
            try await relay(for: outbound.server).send(wire, to: outbound, expiresAt: expiresAt)
            if !outbound.secured { updateContact(contactID) { $0.outbound?.secured = true } }
            updateStatus(messageID, in: contactID, status: .accepted, clearWire: true)
        } catch GhostError.queueGone {
            updateContact(contactID) { $0.state = .disconnected }
            updateStatus(messageID, in: contactID, status: .failed, clearWire: true)
            self.error = GhostError.disconnected.localizedDescription
        } catch {
            updateStatus(messageID, in: contactID, status: .failed)
        }
    }

    func retry(_ messageID: UUID, in contactID: String) async {
        guard let message = messages[contactID]?.first(where: { $0.id == messageID }), message.status == .failed,
              let wire = message.wire, message.remaining() > 0, let contact = self.contact(contactID),
              contact.state != .disconnected, let outbound = contact.outbound else { return }
        await deliver(messageID, wire: wire, expiresAt: message.expiresAt, contactID: contactID, outbound: outbound)
    }

    private func updateStatus(_ messageID: UUID, in id: String, status: MessageStatus, clearWire: Bool = false) {
        guard let i = messages[id]?.firstIndex(where: { $0.id == messageID }) else { return }
        messages[id]?[i].status = status
        if clearWire { messages[id]?[i].wire = nil }
    }

    private func accept(_ payload: PrivatePayload, from contactID: String) {
        guard seen[payload.id] == nil else { return }
        seen[payload.id] = payload.expiresAt
        updateContact(contactID) { if $0.state == .connecting { $0.state = .connected } }
        if payload.kind == .hello {
            // A repeated hello means the joiner never saw our ready (it expired or was lost): answer again.
            Task { await self.sendProtocol(.ready, to: contactID) }
        }
        if payload.content != nil {
            messages[contactID, default: []].append(payload.display(outgoing: false, status: .delivered))
            if activeChatID != contactID || shouldCover { unread[contactID, default: 0] += 1 }
            incomingFeedback()
        }
    }

    /// Short sound (the silent switch is respected) and a light tap when a message arrives while the app is open.
    /// Push banners stay suppressed in the foreground; one sound per burst of messages.
    private func incomingFeedback() {
        guard settings.inAppSound, foreground, !shouldCover, Date().timeIntervalSince(lastIncomingFeedback) > 1.5 else { return }
        lastIncomingFeedback = Date()
        AudioServicesPlaySystemSound(1003)
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
    }

    // MARK: - Sync

    private func startSync() {
        guard syncTask == nil, !locked, foreground, identity != nil else { return }
        syncTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                await self.syncOnce()
                do { try await Task.sleep(nanoseconds: 3_000_000_000) } catch { return }
            }
        }
    }

    private func stopSync() { syncTask?.cancel(); syncTask = nil }

    private func refreshNetworkStatus() {
        let hasQueues = contacts.contains { $0.inbound != nil && $0.state != .disconnected } || !invites.isEmpty
        if !hasQueues {
            networkHealthy = false
            networkStatus = String(localized: "Nema aktivnih veza")
        }
    }

    private func syncOnce() async {
        guard !syncing, !locked, foreground, identity != nil else { return }
        syncing = true; defer { syncing = false }
        let epoch = generation
        dropExpiredInvites()
        var byServer: [String: [InboundQueue]] = [:]
        for contact in contacts where !contact.isDemo && contact.state != .disconnected {
            if let inbound = contact.inbound { byServer[inbound.server, default: []].append(inbound) }
        }
        for invite in invites { byServer[invite.inbound.server, default: []].append(invite.inbound) }
        guard !byServer.isEmpty else { refreshNetworkStatus(); return }
        var reachable = 0, failed = 0, skewed = false
        for (server, queues) in byServer {
            for start in stride(from: 0, to: queues.count, by: RelayClient.maxFetchQueues) {
                let chunk = Array(queues[start..<min(start + RelayClient.maxFetchQueues, queues.count)])
                do {
                    let client = try relay(for: server)
                    let result = try await client.fetch(chunk)
                    guard generation == epoch, !Task.isCancelled else { return }
                    reachable += 1
                    if result.queues.contains(where: { $0.status == "clock_skew" }) { skewed = true }
                    await process(result, queues: chunk, client: client)
                } catch is CancellationError {
                    return
                } catch {
                    failed += 1
                }
            }
        }
        guard generation == epoch else { return }
        if Date().timeIntervalSince(lastProtocolRetry) > 30 {
            lastProtocolRetry = Date()
            await retryProtocolMessages()
        }
        await syncPush()
        networkHealthy = !skewed && failed == 0
        if skewed { networkStatus = String(localized: "Vrijeme uređaja odstupa od servera") }
        else if failed == 0 { networkStatus = String(localized: "Povezano · HTTPS") }
        else { networkStatus = reachable > 0 ? String(localized: "Djelimično povezano") : String(localized: "Server nije dostupan") }
    }

    private enum Disposition { case ack, keep }

    private func process(_ result: FetchResult, queues: [InboundQueue], client: RelayClient) async {
        for status in result.queues where status.status == "not_found" { queueVanished(status.recipientId) }
        var acks: [String: [String]] = [:]
        var held = Set<String>()
        for item in result.messages where !held.contains(item.recipientId) {
            switch await handle(item) {
            case .ack: acks[item.recipientId, default: []].append(item.id)
            case .keep: held.insert(item.recipientId)
            }
        }
        for queue in queues {
            guard let ids = acks[queue.recipientID], !ids.isEmpty else { continue }
            try? await client.ack(queue, ids: ids)
        }
    }

    /// Decrypted content is always kept in RAM and acknowledged, even if the screen got covered meanwhile:
    /// the ratchet has already advanced, so dropping it would lose the message for good.
    private func handle(_ item: RelayMessage) async -> Disposition {
        if let contact = contacts.first(where: { $0.inbound?.recipientID == item.recipientId }) {
            if contact.blocked { return .ack }
            // Out of memory budget: leave it on the server (up to 24 h) instead of decrypting and losing it.
            guard (messages[contact.id]?.count ?? 0) < Limits.maxMessagesPerContact,
                  attachmentBytes + item.message.count < Limits.maxPhotoMemory + 8_000_000 else { return .keep }
            do {
                let opened = try await engine.decrypt(item.message, expectedKey: contact.identityKey)
                accept(opened.payload, from: contact.id)
            } catch GhostError.storage(_) {
                return .keep
            } catch {
                notice = String(localized: "Jedna poruka nije mogla biti provjerena i nije prikazana.")
            }
            return .ack
        }
        if let invite = invites.first(where: { $0.inbound.recipientID == item.recipientId }) {
            do {
                let opened = try await engine.decrypt(item.message, expectedKey: nil)
                await completeInvite(invite, payload: opened.payload, senderKey: opened.senderKey)
            } catch GhostError.storage(_) {
                return .keep
            } catch {
                notice = String(localized: "Neispravan odgovor na pozivnicu je odbačen.")
            }
            return .ack
        }
        return .ack
    }

    private func queueVanished(_ recipientID: String) {
        if let invite = invites.first(where: { $0.inbound.recipientID == recipientID }) {
            invites.removeAll { $0.id == invite.id }
            try? persistMetadata()
            Task { try? await self.engine.discardBundle(id: invite.preKeyID) }
            return
        }
        if let contact = contacts.first(where: { $0.inbound?.recipientID == recipientID }), contact.state != .disconnected {
            updateContact(contact.id) { $0.state = .disconnected }
            notice = String(localized: "Veza sa kontaktom \(contact.title) je prekinuta na serveru.")
        }
    }

    // MARK: - Push notifications

    /// Debug builds from Xcode get APNs sandbox tokens; TestFlight and App Store builds get production tokens.
    /// The relay retries the other environment if a build reports the wrong one.
    static var pushEnvironment: String {
        #if DEBUG
        return "sandbox"
        #else
        return "production"
        #endif
    }

    /// quiet: used for the automatic first-run prompt, where declining is a normal answer and needs no message.
    func setNotifications(_ enabled: Bool, quiet: Bool = false) async {
        if enabled {
            let center = UNUserNotificationCenter.current()
            if await center.notificationSettings().authorizationStatus == .denied {
                // iOS never asks twice; send the user to this app's notification settings and pick it up on return.
                if !quiet, let url = URL(string: UIApplication.openNotificationSettingsURLString) {
                    awaitingSystemSettings = true
                    _ = await UIApplication.shared.open(url)
                }
                return
            }
            do {
                guard try await center.requestAuthorization(options: [.alert, .sound]) else { return }
            } catch { if !quiet { self.error = error.localizedDescription }; return }
            var value = settings; value.notificationsEnabled = true; updateSettings(value)
            registeredPush = []
            UIApplication.shared.registerForRemoteNotifications()
            await syncPush()
        } else {
            var value = settings; value.notificationsEnabled = false; updateSettings(value)
            await unregisterPush()
        }
    }

    /// Asked once, as soon as a Ghost ID exists and the app is unlocked. Allowing in the iOS dialog
    /// turns notifications on right away; declining leaves them off without any further message.
    private func promptForNotificationsIfNeeded() async {
        guard identity != nil, !locked, !settings.notificationsPrompted else { return }
        var value = settings; value.notificationsPrompted = true; updateSettings(value)
        let status = await UNUserNotificationCenter.current().notificationSettings().authorizationStatus
        // Only a real first answer turns them on; an earlier "off" in the app is respected.
        guard status == .notDetermined else { return }
        await setNotifications(true, quiet: true)
    }

    /// Keeps the in-app switch in step with iOS Settings.
    private func refreshNotificationAuthorization() async {
        let status = await UNUserNotificationCenter.current().notificationSettings().authorizationStatus
        let allowed = status == .authorized || status == .provisional || status == .ephemeral
        if awaitingSystemSettings {
            awaitingSystemSettings = false
            if allowed && !settings.notificationsEnabled { await setNotifications(true, quiet: true); return }
        }
        if settings.notificationsEnabled && !allowed {
            var value = settings; value.notificationsEnabled = false; updateSettings(value)
            await unregisterPush()
        }
    }

    private func deviceTokenChanged(_ token: String?) async {
        guard let token else {
            if settings.notificationsEnabled { notice = String(localized: "iOS trenutno nije izdao token za obavještenja. Pokušaće ponovo pri sljedećem pokretanju.") }
            return
        }
        if token != deviceToken { deviceToken = token; registeredPush = [] }
        await syncPush()
    }

    private var pushQueues: [InboundQueue] {
        contacts.filter { !$0.isDemo && $0.state != .disconnected }.compactMap(\.inbound) + invites.map(\.inbound)
    }

    private func pushKey(_ queue: InboundQueue, _ token: String) -> String {
        [queue.server, queue.recipientID, token, Self.pushEnvironment].joined(separator: "|")
    }

    /// Registers only queues not yet registered in this foreground session: usually nothing to do.
    private func syncPush() async {
        guard settings.notificationsEnabled, let token = deviceToken, !locked, identity != nil else { return }
        var byServer: [String: [InboundQueue]] = [:]
        for queue in pushQueues where !registeredPush.contains(pushKey(queue, token)) {
            byServer[queue.server, default: []].append(queue)
        }
        for (server, queues) in byServer {
            for start in stride(from: 0, to: queues.count, by: RelayClient.maxFetchQueues) {
                let chunk = Array(queues[start..<min(start + RelayClient.maxFetchQueues, queues.count)])
                guard let client = try? relay(for: server),
                      let statuses = try? await client.notify(chunk, token: token, environment: Self.pushEnvironment) else { continue }
                for status in statuses where status.status == "ok" {
                    if let queue = chunk.first(where: { $0.recipientID == status.recipientId }) { registeredPush.insert(pushKey(queue, token)) }
                }
            }
        }
    }

    private func unregisterPush() async {
        registeredPush = []
        var byServer: [String: [InboundQueue]] = [:]
        for queue in pushQueues { byServer[queue.server, default: []].append(queue) }
        for (server, queues) in byServer {
            for start in stride(from: 0, to: queues.count, by: RelayClient.maxFetchQueues) {
                let chunk = Array(queues[start..<min(start + RelayClient.maxFetchQueues, queues.count)])
                if let client = try? relay(for: server) { _ = try? await client.notify(chunk, token: nil, environment: Self.pushEnvironment) }
            }
        }
    }

    // MARK: - Erase

    /// Remote queues are deleted best-effort with a time limit; the local wipe never depends on the network.
    func eraseAccount() async {
        guard !busy else { return }; busy = true; defer { busy = false }
        stopSync(); generation = UUID()
        let queues = contacts.compactMap(\.inbound) + invites.map(\.inbound)
        let jobs: [(RelayClient, InboundQueue)] = queues.compactMap { queue in
            guard let client = try? relay(for: queue.server) else { return nil }
            return (client, queue)
        }
        var deleted = 0
        if !jobs.isEmpty {
            deleted = await withTaskGroup(of: Bool?.self, returning: Int.self) { group in
                for (client, queue) in jobs {
                    group.addTask { (try? await client.delete(queue)) != nil }
                }
                group.addTask { try? await Task.sleep(nanoseconds: 8_000_000_000); return nil }
                var count = 0, finished = 0
                for await result in group {
                    guard let ok = result else { group.cancelAll(); break }
                    finished += 1
                    if ok { count += 1 }
                    if finished == jobs.count { group.cancelAll(); break }
                }
                return count
            }
        }
        do {
            try await engine.deleteIdentity()
            try vault.delete("metadata")
            try vault.delete("pin")
            pinRecord = nil
        } catch {
            self.error = error.localizedDescription
            startSync()
            return
        }
        for client in relays.values { await client.close() }
        relays = [:]; demo = nil; demoEngine = nil
        identity = nil; publicKey = nil; contacts = []; invites = []; messages = [:]; unread = [:]; seen = [:]; registeredPush = []
        settings = AppSettings(); locked = false; pendingLink = nil
        refreshNetworkStatus()
        if deleted < jobs.count {
            notice = String(localized: "Identitet je obrisan sa uređaja. Neki sandučići na serveru nisu obrisani; bez ključeva su neupotrebljivi, a server ih uklanja nakon perioda neaktivnosti.")
        }
    }
}
