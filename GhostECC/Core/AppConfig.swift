import Foundation

/// Production endpoints and links. Forks of the open-source code change them here.
enum AppConfig {
    static let defaultServer = "https://relay.relayghostecc.net"
    static let sourceCode = URL(string: "https://github.com/popoviclazar/ghostecc")!
    static let privacyPolicy = URL(string: "https://popoviclazar.github.io/ghostecc/privacy.html")!
    static let support = URL(string: "https://popoviclazar.github.io/ghostecc/support.html")!
    static var version: String {
        let info = Bundle.main.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "\(short) (\(build))"
    }
}
