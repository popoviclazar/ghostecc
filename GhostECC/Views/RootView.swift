import SwiftUI

struct RootView: View {
    @EnvironmentObject private var store: AppStore
    var body: some View {
        ZStack {
            GhostTheme.background.ignoresSafeArea()
            Group {
                if store.loading { ProgressView("Otvaranje privatnog prostora…") }
                else if store.identity == nil { WelcomeView() }
                else {
                    TabView {
                        InboxView().tabItem { Label("Razgovori", systemImage: "bubble.left.and.bubble.right") }
                        IdentityView().tabItem { Label("Ghost ID", systemImage: "qrcode") }
                        PrivacyView().tabItem { Label("Zaštita", systemImage: "shield.lefthalf.filled") }
                    }.tint(GhostTheme.blue)
                }
            }.accessibilityHidden(store.shouldCover)
            if store.shouldCover && !store.loading {
                GhostTheme.background.ignoresSafeArea()
                VStack(spacing: 26) {
                    GhostMark(size: 116)
                    Text("GHOST ECC").font(.system(.title, design: .rounded).weight(.black)).tracking(3)
                    if store.captured && store.settings.hideDuringCapture {
                        Text("Zaustavi snimanje ili dijeljenje ekrana.").foregroundStyle(.secondary).multilineTextAlignment(.center)
                    } else if !store.covered {
                        if store.pinEnabled {
                            PinUnlockView()
                        } else {
                            Text("Tvoj privatni prostor je zaključan.").foregroundStyle(.secondary)
                            PrimaryButton(title: "Otključaj") { Task { await store.unlock() } }.padding(.horizontal, 48)
                        }
                    }
                }.padding()
            }
        }
        .alert("Ghost ECC", isPresented: Binding(get: { store.error != nil }, set: { if !$0 { store.error = nil } })) {
            Button("U redu") { store.error = nil }
        } message: { Text(store.error ?? "") }
        .alert("Obavještenje", isPresented: Binding(get: { store.notice != nil && store.error == nil && !store.shouldCover }, set: { if !$0 { store.notice = nil } })) {
            Button("U redu") { store.notice = nil }
        } message: { Text(store.notice ?? "") }
    }
}
/// First launch: three short pages explaining the model, then the Ghost ID is created.
struct WelcomeView: View {
    @EnvironmentObject private var store: AppStore
    @State private var page = 0
    private let lastPage = 3
    var body: some View {
        VStack(spacing: 0) {
            TabView(selection: $page) {
                VStack(spacing: 22) {
                    GhostMark(size: 128)
                    VStack(spacing: 10) {
                        Text(verbatim: "GHOST ECC").font(.system(size: 34, weight: .black, design: .rounded)).tracking(3)
                        Text("Manje tragova. Više kontrole.").font(.title3).foregroundStyle(.secondary)
                    }
                    VStack(alignment: .leading, spacing: 16) {
                        Label("Identitet bez broja i emaila", systemImage: "person.crop.square")
                        Label("Poruke, glas, fotografije i fajlovi", systemImage: "bubble.left.and.bubble.right")
                        Label("Šifrovano s kraja na kraj", systemImage: "lock.fill")
                    }.font(.body).padding(.top, 10)
                }.padding(32).tag(0)
                OnboardingPage(symbol: "qrcode", title: "Kontakti samo pozivnicom",
                               text: "Napravi jednokratnu pozivnicu i pokaži QR kod. Niko ti ne može pisati bez pozivnice koju si mu dao.").tag(1)
                OnboardingPage(symbol: "checkmark.shield.fill", title: "Provjeri uživo",
                               text: "Skenirajte jedno drugom sigurnosni kod. Tek kad se kodovi poklope, aplikacija šalje poruke, pa niko ne može da stane između vas.").tag(2)
                VStack(spacing: 24) {
                    OnboardingPage(symbol: "timer", title: "Poruke nestaju",
                                   text: "Najduže 24 sata i samo u memoriji telefona. Nema bekapa: ako izgubiš telefon ili obrišeš identitet, ključevi se ne mogu vratiti.")
                    if !store.cryptoAvailable {
                        Label("Kriptografska biblioteka nije instalirana. Otvori uputstvo u projektu prije pokretanja.", systemImage: "exclamationmark.shield")
                            .font(.footnote).foregroundStyle(.orange).padding(.horizontal, 32)
                    }
                }.tag(3)
            }
            .tabViewStyle(.page(indexDisplayMode: .always))
            .indexViewStyle(.page(backgroundDisplayMode: .always))
            Group {
                if page < lastPage {
                    PrimaryButton(title: "Dalje") { withAnimation { page += 1 } }
                } else {
                    PrimaryButton(title: store.busy ? LocalizedStringKey("Kreiranje…") : LocalizedStringKey("Kreiraj Ghost ID"), disabled: store.busy || !store.cryptoAvailable) {
                        Task { await store.createIdentity() }
                    }
                }
            }.padding(.horizontal, 28).padding(.bottom, 24).padding(.top, 8)
        }.background(GhostTheme.background)
    }
}

struct OnboardingPage: View {
    let symbol: String
    let title: LocalizedStringKey
    let text: LocalizedStringKey
    var body: some View {
        VStack(spacing: 22) {
            Image(systemName: symbol).font(.system(size: 54, weight: .semibold)).foregroundStyle(GhostTheme.blue)
                .frame(width: 112, height: 112).background(GhostTheme.panel, in: RoundedRectangle(cornerRadius: 30, style: .continuous))
            Text(title).font(.title2.bold()).multilineTextAlignment(.center)
            Text(text).font(.body).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }.padding(32)
    }
}
