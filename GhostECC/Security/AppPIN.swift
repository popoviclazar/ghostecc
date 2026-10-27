import Foundation
import CryptoKit
import CommonCrypto

/// Stored verifier for the app passcode. The passcode itself is never stored.
/// hash = HMAC(pepper, PBKDF2-SHA256(passcode, salt)), where the pepper comes from a Secure Enclave key
/// agreement when the device has one: the verifier is then useless off this device, so guessing has to
/// happen on the phone, behind the attempt limits below.
struct PinRecord: Codable, Equatable {
    var salt: Data
    var hash: Data
    var iterations: Int
    var enclaveKey: Data?
    var peerKey: Data?
    var failedAttempts = 0
    var lockedUntil: Date?
    /// Face ID / Touch ID enrollment when the passcode was last confirmed. If someone adds a face or finger,
    /// this changes and biometrics stop unlocking the app until the passcode is entered again.
    var biometryState: Data?
}

enum AppPIN {
    static let minLength = 6
    static let maxLength = 16
    static let wipeAfter = 10
    static let iterations = 400_000

    static func isValidFormat(_ pin: String) -> Bool {
        (minLength...maxLength).contains(pin.count) && pin.allSatisfy { $0.isASCII && $0.isNumber }
    }

    /// Waiting time after a given number of consecutive wrong attempts.
    static func delay(afterFailures failures: Int) -> TimeInterval {
        switch failures {
        case ..<5: return 0
        case 5: return 30
        case 6: return 60
        case 7: return 5 * 60
        case 8: return 15 * 60
        default: return 60 * 60
        }
    }

    static func makeRecord(_ pin: String) throws -> PinRecord {
        guard isValidFormat(pin) else { throw GhostError.invalidPayload }
        let salt = SecureRandom.bytes(16)
        var enclaveKey: Data?
        var peerKey: Data?
        if SecureEnclave.isAvailable {
            enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey().dataRepresentation
            peerKey = P256.KeyAgreement.PrivateKey().publicKey.rawRepresentation
        }
        var record = PinRecord(salt: salt, hash: Data(), iterations: iterations, enclaveKey: enclaveKey, peerKey: peerKey)
        record.hash = try verifier(pin, record)
        return record
    }

    static func matches(_ pin: String, _ record: PinRecord) -> Bool {
        guard isValidFormat(pin), let candidate = try? verifier(pin, record), candidate.count == record.hash.count else { return false }
        var difference: UInt8 = 0
        for (a, b) in zip(candidate, record.hash) { difference |= a ^ b }
        return difference == 0
    }

    private static func verifier(_ pin: String, _ record: PinRecord) throws -> Data {
        let stretched = try pbkdf2(pin, salt: record.salt, iterations: record.iterations)
        guard let enclaveKey = record.enclaveKey, let peerKey = record.peerKey else { return stretched }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: enclaveKey)
        let secret = try key.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(rawRepresentation: peerKey))
        let pepper = secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: record.salt, sharedInfo: Data("GHOST-PIN-v1".utf8), outputByteCount: 32)
        return Data(HMAC<SHA256>.authenticationCode(for: stretched, using: pepper))
    }

    private static func pbkdf2(_ pin: String, salt: Data, iterations: Int) throws -> Data {
        var output = Data(count: 32)
        let status = output.withUnsafeMutableBytes { outputBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pin, pin.utf8.count,
                                     saltBytes.bindMemory(to: UInt8.self).baseAddress, salt.count,
                                     CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(iterations),
                                     outputBytes.bindMemory(to: UInt8.self).baseAddress, 32)
            }
        }
        guard status == Int32(kCCSuccess) else { throw GhostError.invalidPayload }
        return output
    }
}
