import SwiftUI

/// Lock screen with an app passcode: Face ID first if allowed, otherwise the passcode field.
struct PinUnlockView: View {
    @EnvironmentObject private var store: AppStore
    @State private var pin = ""
    @State private var forgot = false
    @FocusState private var focused: Bool
    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let waiting = (store.pinRecord?.lockedUntil).map { $0 > context.date } ?? false
            let failures = store.pinRecord?.failedAttempts ?? 0
            VStack(spacing: 16) {
                Text("Unesi šifru aplikacije").foregroundStyle(.secondary)
                SecureField("Šifra", text: $pin)
                    .keyboardType(.numberPad).font(.system(.title2, design: .monospaced)).multilineTextAlignment(.center)
                    .padding(14).background(GhostTheme.panel, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                    .focused($focused).disabled(waiting).privacySensitive()
                    .onChange(of: pin) { _, value in
                        let digits = String(value.filter(\.isNumber).prefix(AppPIN.maxLength))
                        if digits != value { pin = digits }
                    }
                if waiting, let until = store.pinRecord?.lockedUntil {
                    Text("Previše pogrešnih pokušaja. Pokušaj ponovo za \(Self.wait(until.timeIntervalSince(context.date))).")
                        .font(.footnote).foregroundStyle(.orange).multilineTextAlignment(.center)
                } else if failures > 0 {
                    Text("Pogrešna šifra. Neuspjelih pokušaja: \(String(failures)).").font(.footnote).foregroundStyle(.orange)
                }
                if store.settings.pinWipeAfterFailures && failures >= 5 {
                    Text("Nakon \(String(AppPIN.wipeAfter)) pogrešnih pokušaja svi podaci se brišu sa ovog uređaja.")
                        .font(.footnote).foregroundStyle(.red).multilineTextAlignment(.center)
                }
                PrimaryButton(title: "Otključaj", disabled: pin.count < AppPIN.minLength || waiting) {
                    let entered = pin
                    pin = ""
                    Task { await store.unlock(pin: entered) }
                }
                if store.settings.pinWithBiometrics {
                    Button { Task { await store.unlock() } } label: { Label("Koristi Face ID", systemImage: "faceid") }
                }
                Button("Zaboravljena šifra") { forgot = true }.font(.footnote).foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 40)
        .onAppear {
            if store.settings.pinWithBiometrics { Task { await store.unlock() } } else { focused = true }
        }
        .confirmationDialog("Zaboravljenu šifru nije moguće vratiti. Jedini izlaz je brisanje identiteta, ključeva i kontakata sa ovog uređaja.",
                            isPresented: $forgot, titleVisibility: .visible) {
            Button("Obriši identitet", role: .destructive) { Task { await store.eraseAccount() } }
        }
    }
    static func wait(_ seconds: TimeInterval) -> String {
        let value = max(1, Int(seconds.rounded(.up)))
        return value >= 60 ? "\(value / 60) min \(value % 60) s" : "\(value) s"
    }
}

enum PinSheet: String, Identifiable {
    case set, change, remove
    var id: String { rawValue }
}

/// Set, change or remove the app passcode.
struct PinSetupView: View {
    @EnvironmentObject private var store: AppStore
    @Environment(\.dismiss) private var dismiss
    let mode: PinSheet
    @State private var current = ""
    @State private var newPin = ""
    @State private var repeated = ""
    private var valid: Bool {
        switch mode {
        case .set: return AppPIN.isValidFormat(newPin) && newPin == repeated
        case .change: return !current.isEmpty && AppPIN.isValidFormat(newPin) && newPin == repeated
        case .remove: return !current.isEmpty
        }
    }
    private var title: String {
        switch mode {
        case .set: return String(localized: "Postavi šifru aplikacije")
        case .change: return String(localized: "Promijeni šifru aplikacije")
        case .remove: return String(localized: "Ukloni šifru aplikacije")
        }
    }
    var body: some View {
        NavigationStack {
            Form {
                if mode != .set {
                    Section("Trenutna šifra") { SecureField("Trenutna šifra", text: $current).keyboardType(.numberPad) }
                }
                if mode != .remove {
                    Section {
                        SecureField("Nova šifra (6–16 cifara)", text: $newPin).keyboardType(.numberPad)
                        SecureField("Ponovi novu šifru", text: $repeated).keyboardType(.numberPad)
                        if !repeated.isEmpty && newPin != repeated {
                            Text("Šifre se ne podudaraju.").font(.footnote).foregroundStyle(.orange)
                        }
                    } footer: {
                        Text("Zaboravljenu šifru nije moguće vratiti ni poslati; jedini izlaz je brisanje identiteta. Šifra se ne čuva, nego samo njen zaštićen otisak na ovom uređaju.")
                    }
                }
                Section {
                    Button(mode == .remove ? String(localized: "Ukloni šifru") : String(localized: "Sačuvaj šifru"), role: mode == .remove ? .destructive : nil) {
                        Task {
                            let done = mode == .remove ? await store.removePIN(current: current)
                                                       : await store.setPIN(newPin, current: mode == .set ? nil : current)
                            if done { dismiss() } else { current = "" }
                        }
                    }.disabled(!valid || store.busy)
                }
            }
            .navigationTitle(title).navigationBarTitleDisplayMode(.inline)
            .toolbar { Button("Otkaži") { dismiss() } }
        }.privacyShield()
    }
}
