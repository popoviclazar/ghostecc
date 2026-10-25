import SwiftUI

// SwiftUI sheets are above the root view: every sensitive modal needs its own cover.
struct PrivacyShield: ViewModifier {
    @EnvironmentObject private var store: AppStore
    func body(content: Content) -> some View {
        ZStack {
            content.accessibilityHidden(store.shouldCover).allowsHitTesting(!store.shouldCover)
            if store.shouldCover {
                GhostTheme.background.ignoresSafeArea()
                VStack(spacing: 24) {
                    GhostMark()
                    Text("GHOST ECC").font(.title2.bold())
                    if !store.covered && !(store.captured && store.settings.hideDuringCapture) {
                        Button("Otključaj") { Task { await store.unlock() } }.buttonStyle(.borderedProminent)
                    }
                }
            }
        }
    }
}
extension View { func privacyShield() -> some View { modifier(PrivacyShield()) } }
