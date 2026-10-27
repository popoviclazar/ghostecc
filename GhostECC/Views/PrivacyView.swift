import SwiftUI
import UIKit

struct PrivacyView: View {
    @EnvironmentObject private var store: AppStore
    @State private var deleting = false
    @State private var pinSheet: PinSheet?
    @Environment(\.openURL) private var openURL
    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Toggle(isOn: setting(\.lockEnabled)) { Label("Zaključavanje pri povratku", systemImage: "faceid") }
                        .disabled(store.pinEnabled)
                    if store.pinEnabled {
                        Toggle(isOn: setting(\.pinWithBiometrics)) { Label("Face ID uz šifru aplikacije", systemImage: "faceid") }
                        Toggle(isOn: setting(\.pinWipeAfterFailures)) { Label("Obriši sve nakon 10 pogrešnih šifri", systemImage: "exclamationmark.triangle") }
                        Button { pinSheet = .change } label: { Label("Promijeni šifru aplikacije", systemImage: "key") }
                        Button(role: .destructive) { pinSheet = .remove } label: { Label("Ukloni šifru aplikacije", systemImage: "lock.open") }
                    } else {
                        Button { pinSheet = .set } label: { Label("Postavi šifru aplikacije", systemImage: "key") }
                    }
                    Toggle(isOn: setting(\.hideDuringCapture)) { Label("Sakrij pri snimanju ekrana", systemImage: "eye.slash") }
                } header: { Text("Uređaj") } footer: {
                    Text(store.pinEnabled
                         ? String(localized: "Ghost ECC otključava samo šifra aplikacije, a Face ID ako je uključen; šifra telefona ne. iOS ne omogućava pouzdanu zabranu svih snimaka ekrana.")
                         : String(localized: "Face ID, Touch ID ili šifra uređaja. Sa šifrom aplikacije, šifra telefona više ne otključava Ghost ECC. iOS ne omogućava pouzdanu zabranu svih snimaka ekrana."))
                }
                Section {
                    // iOS keeps a per-app language in the app's own Settings page once the app has several localizations.
                    Button {
                        if let url = URL(string: UIApplication.openSettingsURLString) { openURL(url) }
                    } label: { Label("Jezik aplikacije", systemImage: "globe") }
                } header: { Text("Jezik") } footer: {
                    Text("Jezik biraš u iOS podešavanjima aplikacije (Language). Bez izbora aplikacija prati jezik telefona.")
                }
                Section {
                    Picker(selection: setting(\.lifetime)) {
                        Text("5 minuta").tag(300.0); Text("1 sat").tag(3600.0); Text("24 sata").tag(86_400.0)
                    } label: { Label("Trajanje novih poruka", systemImage: "timer") }
                    Toggle(isOn: setting(\.wipeOnLeave)) { Label("Obriši razgovore pri izlasku iz aplikacije", systemImage: "trash") }
                } header: { Text("Poruke") } footer: {
                    Text("Promjena važi za nove poruke. Istek se računa od slanja. Gašenje procesa briše lokalni sadržaj ranije; suspendovana aplikacija provjerava istek pri povratku.")
                        + Text(verbatim: "\n\n")
                        + Text("Brisanje pri izlasku uklanja sve razgovore iz memorije čim aplikacija ode u pozadinu, uključujući i nepročitane poruke.")
                }
                Section {
                    Toggle(isOn: Binding(get: { store.settings.notificationsEnabled }, set: { value in Task { await store.setNotifications(value) } })) {
                        Label("Obavještenja o novim porukama", systemImage: "bell.badge")
                    }
                    Toggle(isOn: setting(\.inAppSound)) { Label("Zvuk u otvorenoj aplikaciji", systemImage: "speaker.wave.2") }
                } header: { Text("Obavještenja") } footer: {
                    Text("Obavještenje uvijek glasi samo „Nova poruka“: bez imena, Ghost ID-a i sadržaja. Da bi ga poslao, server zna koji sandučići pripadaju ovom uređaju; tu vezu drži samo u memoriji, a Apple vidi da je stiglo obavještenje.")
                }
                Section {
                    HStack {
                        Label("Status", systemImage: "network")
                        Spacer()
                        Circle().fill(store.networkHealthy ? Color.green : Color.orange).frame(width: 8, height: 8)
                        Text(store.networkStatus).foregroundStyle(.secondary).lineLimit(1)
                    }
                } header: { Text("Veza") } footer: {
                    Text("Server vidi samo nasumične ID-eve sandučića, IP adresu, vrijeme i veličinu šifrovanih paketa; ne vidi Ghost ID-eve ni ko kome piše po imenu. Onion routing nije ugrađen.")
                }
                Section {
                    Button { Task { await store.addDemo() } } label: { Label("Dodaj Ghost Lab kontakt", systemImage: "testtube.2") }
                        .disabled(store.busy || store.contacts.contains(where: \.isDemo))
                } header: { Text("Ghost Lab") } footer: {
                    Text("Lokalni sagovornik za probu šifrovanih poruka, bez interneta i bez druge osobe.")
                }
                Section {
                    Button {
                        if let url = URL(string: UIApplication.openSettingsURLString) { openURL(url) }
                    } label: { Label("Jezik aplikacije", systemImage: "globe") }
                } footer: {
                    Text("Jezik biraš u iOS podešavanjima aplikacije, pod Language. Ako te opcije nema, u iOS-u dodaj još jedan jezik u General → Language & Region.")
                }
                Section {
                    NavigationLink { AboutView() } label: { Label("O aplikaciji", systemImage: "info.circle") }
                } footer: {
                    Text("Sačuvani su samo identitet, kriptografsko stanje, kontakti, ključevi sandučića i podešavanja u nesinhronizovanom Keychain-u. Prepiske, fotografije, glasovne poruke i fajlovi se ne upisuju na disk; fajl napušta aplikaciju samo kad ga ti sačuvaš ili podijeliš.")
                        + Text(verbatim: "\n\n")
                        + Text("Sadržaj mora postojati u RAM-u dok se prikazuje. Brisanje iz aplikacije ne garantuje fizičko brisanje svih kopija u sistemu. Sagovornik može sačuvati sadržaj izvan aplikacije.")
                }
                Section {
                    Button(role: .destructive) { deleting = true } label: { Label("Obriši moj identitet", systemImage: "person.crop.circle.badge.xmark") }
                        .disabled(store.busy)
                }
            }.scrollContentBackground(.hidden).background(GhostTheme.background).navigationTitle("Zaštita")
                .sheet(item: $pinSheet) { mode in PinSetupView(mode: mode) }
                .confirmationDialog("Trajno obrisati Ghost ID, ključeve, kontakte i lokalne razgovore? Sandučići na serverima se brišu ako su dostupni. Oporavak nije moguć.", isPresented: $deleting, titleVisibility: .visible) {
                    Button("Trajno obriši", role: .destructive) { Task { await store.eraseAccount() } }
                }
        }
    }
    private func setting<Value>(_ key: WritableKeyPath<AppSettings, Value>) -> Binding<Value> {
        Binding(get: { store.settings[keyPath: key] }, set: { value in var settings = store.settings; settings[keyPath: key] = value; store.updateSettings(settings) })
    }
}
