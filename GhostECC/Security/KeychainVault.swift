import Foundation
import Security

// Keychain entries contain keys, queue credentials, contact metadata and settings; never message bodies or attachments.
struct KeychainVault {
    let service: String
    init(service: String = "com.ghost.ecc.v3") { self.service = service }
    func load(_ account: String) throws -> Data? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                   kSecAttrAccount as String: account, kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw GhostError.storage(status) }
        return result as? Data
    }
    func save(_ data: Data, account: String) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
        let attributes: [String: Any] = [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                       kSecAttrSynchronizable as String: false]
        let update = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if update == errSecItemNotFound {
            let status = SecItemAdd(query.merging(attributes) { _, new in new } as CFDictionary, nil)
            guard status == errSecSuccess else { throw GhostError.storage(status) }
        } else if update != errSecSuccess { throw GhostError.storage(update) }
    }
    func delete(_ account: String) throws {
        let status = SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account] as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw GhostError.storage(status) }
    }
}

struct AppSettings: Codable, Equatable {
    var lockEnabled = true
    var hideDuringCapture = true
    var lifetime: TimeInterval = 86_400
    var serverURL = AppConfig.defaultServer
    var notificationsEnabled = false
    var notificationsPrompted = false
    var inAppSound = true
    var wipeOnLeave = false
    var pinWithBiometrics = true
    var pinWipeAfterFailures = false
}
extension AppSettings {
    // Missing keys fall back to defaults, so settings saved by an older version still load.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init()
        lockEnabled = try container.decodeIfPresent(Bool.self, forKey: .lockEnabled) ?? lockEnabled
        hideDuringCapture = try container.decodeIfPresent(Bool.self, forKey: .hideDuringCapture) ?? hideDuringCapture
        lifetime = try container.decodeIfPresent(TimeInterval.self, forKey: .lifetime) ?? lifetime
        // The relay is no longer user-selectable: new invitations always use AppConfig.defaultServer.
        // Existing contacts keep working, because each queue stores its own server.
        _ = try container.decodeIfPresent(String.self, forKey: .serverURL)
        notificationsEnabled = try container.decodeIfPresent(Bool.self, forKey: .notificationsEnabled) ?? notificationsEnabled
        notificationsPrompted = try container.decodeIfPresent(Bool.self, forKey: .notificationsPrompted) ?? notificationsPrompted
        inAppSound = try container.decodeIfPresent(Bool.self, forKey: .inAppSound) ?? inAppSound
        wipeOnLeave = try container.decodeIfPresent(Bool.self, forKey: .wipeOnLeave) ?? wipeOnLeave
        pinWithBiometrics = try container.decodeIfPresent(Bool.self, forKey: .pinWithBiometrics) ?? pinWithBiometrics
        pinWipeAfterFailures = try container.decodeIfPresent(Bool.self, forKey: .pinWipeAfterFailures) ?? pinWipeAfterFailures
    }
}
struct LocalMetadata: Codable {
    var contacts: [Contact] = []
    var invites: [PendingInvite] = []
    var settings = AppSettings()
}
