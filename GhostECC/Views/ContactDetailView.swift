import SwiftUI

struct ContactDetailView: View {
    @EnvironmentObject private var store: AppStore
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL
    let contactID: String
    @State private var number: String?
    @State private var loadError: String?
    @State private var confirmingTrust = false
    @State private var confirmingDelete = false
    @State private var confirmingClear = false
    @State private var confirmingReport = false
    @State private var verifyQR: UIImage?
    @State private var scanning = false
    @State private var scanResult: Bool?
    @State private var renaming = false
    @State private var newName = ""
    private var contact: Contact? { store.contact(contactID) }
    var body: some View {
        NavigationStack {
            Form {
                if let contact {
                    Section {
                        HStack { Spacer(); VStack(spacing: 12) { ContactAvatar(contact: contact); Text(contact.title).font(.title3.bold()) }; Spacer() }.padding()
                        if !contact.isDemo {
                            Button { newName = contact.name; renaming = true } label: { Label("Promijeni ime", systemImage: "pencil") }
                        }
                        Text(verbatim: IdentityView.grouped(contact.ghostID)).font(.system(.caption, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity)
                    }
                    Section("Veza") {
                        LabeledContent("Stanje", value: stateText(contact))
                    }
                    Section("Sigurnosni broj") {
                        if let number {
                            Text(group(number)).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                            Text("Uporedi svih 60 cifara sa sagovornikom uživo ili drugim pouzdanim putem. Pozivnica sama po sebi nije dokaz ko je osoba.").font(.footnote).foregroundStyle(.secondary)
                            if !contact.isDemo {
                                if let verifyQR {
                                    Image(uiImage: verifyQR).interpolation(.none).resizable().scaledToFit().frame(width: 170, height: 170).padding(10)
                                        .background(Color.white, in: RoundedRectangle(cornerRadius: 16)).frame(maxWidth: .infinity)
                                        .accessibilityLabel("QR kod sigurnosnog broja")
                                }
                                Button { scanning = true } label: { Label("Skeniraj kod sagovornika", systemImage: "qrcode.viewfinder") }
                                Text("Najsigurnije je da se vidite uživo i skenirate jedno drugom ovaj kod. Ako se kodovi podudaraju, kontakt se potvrđuje automatski.").font(.footnote).foregroundStyle(.secondary)
                            }
                            if contact.isDemo { Label("Automatski provjeren lokalni test", systemImage: "testtube.2") }
                            else {
                                Button(contact.verified ? String(localized: "Ukloni potvrdu kontakta") : String(localized: "Brojevi se podudaraju")) {
                                    if contact.verified { store.setVerified(contactID, value: false) }
                                    else { confirmingTrust = true }
                                }
                            }
                        } else if let loadError { Text(loadError).foregroundStyle(.orange); Button("Pokušaj ponovo") { Task { await loadNumber() } } }
                        else { ProgressView("Priprema broja…") }
                    }
                    Section {
                        Button(contact.blocked ? String(localized: "Odblokiraj kontakt") : String(localized: "Blokiraj kontakt"), role: contact.blocked ? nil : .destructive) {
                            store.setBlocked(contactID, value: !contact.blocked)
                        }
                        if !contact.isDemo {
                            Button("Prijavi zloupotrebu", role: .destructive) { confirmingReport = true }
                        }
                        Button("Obriši poruke sa ovog uređaja", role: .destructive) { confirmingClear = true }
                        Button("Ukloni kontakt", role: .destructive) { confirmingDelete = true }
                    }
                } else { Text("Kontakt više nije dostupan.") }
            }.navigationTitle("Zaštita razgovora").navigationBarTitleDisplayMode(.inline).toolbar { Button("Zatvori") { dismiss() } }
                .task { await loadNumber() }
                .alert("Ime kontakta", isPresented: $renaming) {
                    TextField("Ime na ovom uređaju", text: $newName)
                    Button("Sačuvaj") { store.renameContact(contactID, to: newName) }
                    Button("Otkaži", role: .cancel) { }
                } message: { Text("Ime vidiš samo ti, na ovom uređaju.") }
                .sheet(isPresented: $scanning) {
                    QRScanView(prefix: SafetyCode.prefix, title: LocalizedStringKey("Skeniraj sigurnosni kod")) { value in scanning = false; scanned(value) }
                }
                .alert(scanResult == true ? String(localized: "Kontakt je potvrđen") : String(localized: "Kodovi se ne podudaraju"),
                       isPresented: Binding(get: { scanResult != nil }, set: { if !$0 { scanResult = nil } })) {
                    Button("U redu", role: .cancel) { scanResult = nil }
                } message: {
                    Text(scanResult == true
                         ? String(localized: "Sigurnosni brojevi su isti na oba telefona. Niko nije između vas.")
                         : String(localized: "Ne šalji poruke ovom kontaktu: neko može biti između vas. Provjeri da li si skenirao pravi telefon; ako jesi, obrišite kontakt i povežite se ponovo pozivnicom, uživo."))
                }
                .confirmationDialog("Da li si uporedio cijeli broj sa sagovornikom?", isPresented: $confirmingTrust, titleVisibility: .visible) {
                    Button("Potvrdi podudaranje") { store.setVerified(contactID, value: true) }
                }
                .confirmationDialog("Kontakt će biti blokiran. Poruke su šifrovane i niko osim vas dvoje ih ne može pročitati, pa problem opiši na stranici podrške.", isPresented: $confirmingReport, titleVisibility: .visible) {
                    Button("Blokiraj i otvori podršku", role: .destructive) {
                        store.setBlocked(contactID, value: true)
                        openURL(AppConfig.support)
                    }
                }
                .confirmationDialog("Obrisati lokalne poruke? Kopije kod sagovornika se ne mogu povući.", isPresented: $confirmingClear, titleVisibility: .visible) {
                    Button("Obriši", role: .destructive) { store.clearChat(contactID) }
                }
                .confirmationDialog("Ukloniti kontakt i lokalne poruke?", isPresented: $confirmingDelete, titleVisibility: .visible) {
                    Button("Ukloni", role: .destructive) { store.deleteContact(contactID); dismiss() }
                }
        }.privacyShield()
    }
    private func stateText(_ contact: Contact) -> String {
        if contact.isDemo { return String(localized: "Lokalni test") }
        switch contact.state {
        case .connecting: return String(localized: "Čeka potvrdu")
        case .connected: return String(localized: "Povezano")
        case .disconnected: return String(localized: "Prekinuto")
        }
    }
    private func loadNumber() async {
        loadError = nil
        do {
            let value = try await store.safetyNumber(for: contactID)
            number = value
            verifyQR = QRImage.make(SafetyCode.link(value))
        }
        catch { loadError = error.localizedDescription }
    }
    /// A mismatch never removes an existing confirmation (the wrong phone may have been scanned), it only warns.
    private func scanned(_ value: String) {
        guard let number else { return }
        if SafetyCode.matches(value, number) {
            store.setVerified(contactID, value: true)
            scanResult = true
        } else {
            scanResult = false
        }
    }
    private func group(_ value: String) -> String {
        stride(from: 0, to: value.count, by: 5).map { start in
            let a = value.index(value.startIndex, offsetBy: start)
            let b = value.index(a, offsetBy: min(5, value.count - start))
            return String(value[a..<b])
        }.joined(separator: " ")
    }
}
