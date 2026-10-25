import Foundation

// Public half of a one-time libsignal prekey bundle. It travels only inside an invitation,
// encrypted with the link key, never as a public directory entry.
struct PublicPreKey: Codable, Equatable { let id: UInt32; let key: Data }
struct PublicSignedPreKey: Codable, Equatable { let id: UInt32; let key: Data; let signature: Data }
struct KeyBundleDTO: Codable, Equatable {
    let id: GhostID
    let registrationID: UInt32
    let deviceID: UInt32
    let identityKey: Data
    let preKey: PublicPreKey
    let signedPreKey: PublicSignedPreKey
    let kyberPreKey: PublicSignedPreKey
}
