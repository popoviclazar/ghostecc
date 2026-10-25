import SwiftUI
import UIKit
import PhotosUI
import UniformTypeIdentifiers

struct ChatView: View {
    @EnvironmentObject private var store: AppStore
    @Environment(\.scenePhase) private var phase
    let contactID: String
    @State private var draft = ""
    @State private var photoItem: PhotosPickerItem?
    @State private var pickingPhoto = false
    @State private var importing = false
    @State private var pendingPhoto: Data?
    @State private var photoPreview = false
    @State private var details = false
    @State private var importTask: Task<Void, Never>?
    @State private var importingFile = false
    @State private var pendingFile: FileAttachment?
    @StateObject private var recorder = VoiceRecorder()
    @StateObject private var player = VoicePlayer()
    @FocusState private var composing: Bool
    private var contact: Contact? { store.contact(contactID) }
    private var messages: [ChatMessage] { store.messages[contactID] ?? [] }
    private var canSend: Bool {
        guard let contact else { return false }
        return contact.verified && !contact.blocked && contact.state != .disconnected && !importing
    }
    private var draftIsEmpty: Bool { draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }

    var body: some View {
        VStack(spacing: 0) {
            if let contact {
                banner(contact)
                ScrollViewReader { proxy in
                    ScrollView {
                        if messages.isEmpty { emptyState }
                        LazyVStack(spacing: 0) {
                            ForEach(Array(messages.enumerated()), id: \.element.id) { index, message in
                                let grouped = index > 0 && messages[index - 1].outgoing == message.outgoing
                                MessageBubble(message: message, contactID: contactID, player: player)
                                    .padding(.top, grouped ? 3 : 12)
                                    .transition(.asymmetric(insertion: .move(edge: .bottom).combined(with: .opacity), removal: .opacity))
                            }
                        }.padding(.horizontal, 12).padding(.bottom, 10).animation(.spring(duration: 0.3), value: messages.count)
                    }
                    .scrollDismissesKeyboard(.interactively)
                    .defaultScrollAnchor(.bottom)
                    .onChange(of: messages.count) { _, _ in
                        if let last = messages.last { withAnimation { proxy.scrollTo(last.id, anchor: .bottom) } }
                    }
                }
                composer(contact)
            } else {
                ContentUnavailableView("Kontakt je uklonjen", systemImage: "person.crop.circle.badge.xmark")
            }
        }
        .background(GhostTheme.background)
        .navigationTitle(contact?.title ?? String(localized: "Razgovor")).navigationBarTitleDisplayMode(.inline)
        .toolbar(.hidden, for: .tabBar)
        .toolbar {
            Button { details = true } label: { Image(systemName: "shield.lefthalf.filled") }.accessibilityLabel("Detalji i sigurnosni broj")
        }
        .sheet(isPresented: $details) { ContactDetailView(contactID: contactID) }
        .sheet(isPresented: $photoPreview, onDismiss: { pendingPhoto = nil }) { photoSheet }
        .photosPicker(isPresented: $pickingPhoto, selection: $photoItem, matching: .images)
        .fileImporter(isPresented: $importingFile, allowedContentTypes: [.item], allowsMultipleSelection: false) { result in
            switch result {
            case .success(let urls): if let url = urls.first { loadFile(url) }
            case .failure(let error): store.error = error.localizedDescription
            }
        }
        .confirmationDialog("Poslati fajl?", isPresented: Binding(get: { pendingFile != nil }, set: { if !$0 { pendingFile = nil } }),
                            titleVisibility: .visible, presenting: pendingFile) { file in
            Button("Pošalji") {
                pendingFile = nil
                Task { if await store.send(.file(file), to: contactID) { sentFeedback() } }
            }
            Button("Otkaži", role: .cancel) { pendingFile = nil }
        } message: { file in
            Text(verbatim: file.name + " · " + ByteCountFormatter.string(fromByteCount: Int64(file.data.count), countStyle: .file))
        }
        .onAppear { store.chatOpened(contactID); recorder.onLimit = { finishRecording() } }
        .onDisappear { store.chatClosed(contactID); clearComposer() }
        .onChange(of: store.shouldCover) { _, covered in
            if covered { recorder.cancel(); player.stop() } else { store.chatOpened(contactID) }
        }
        .onChange(of: photoItem) { _, item in loadPhoto(item) }
        .onChange(of: phase) { _, newPhase in if newPhase == .background { clearComposer() } }
    }

    // MARK: - Pieces

    private var emptyState: some View {
        VStack(spacing: 14) {
            Image(systemName: "lock.shield").font(.system(size: 40)).foregroundStyle(GhostTheme.blue)
            Text("Razgovor bez istorije").font(.headline)
            Text("Poruke ističu za najviše 24 sata. Gašenje aplikacije ih uklanja i ranije.")
                .font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }.frame(maxWidth: .infinity).padding(.horizontal, 40).padding(.vertical, 60)
    }

    @ViewBuilder private func banner(_ contact: Contact) -> some View {
        Group {
            if contact.blocked {
                Label("Kontakt je blokiran", systemImage: "hand.raised.fill").foregroundStyle(.orange)
            } else if contact.state == .disconnected {
                Label("Veza je prekinuta. Povežite se ponovo novom pozivnicom.", systemImage: "link.badge.plus").foregroundStyle(.orange)
            } else if !contact.verified {
                Button { details = true } label: {
                    Label("Uporedi sigurnosni broj prije slanja", systemImage: "exclamationmark.shield.fill")
                        .padding(.horizontal, 14).padding(.vertical, 8)
                        .background(Color.orange.opacity(0.15), in: Capsule())
                }.foregroundStyle(.orange)
            } else if contact.state == .connecting {
                Label("Čeka se da sagovornik potvrdi vezu", systemImage: "hourglass").foregroundStyle(.secondary)
            } else {
                Label(contact.isDemo ? String(localized: "Lokalni kriptografski test") : String(localized: "Šifrovano s kraja na kraj · potvrđen kontakt"),
                      systemImage: "lock.fill").foregroundStyle(.secondary)
            }
        }.font(.caption).multilineTextAlignment(.center).padding(.horizontal, 16).padding(.vertical, 8)
    }

    @ViewBuilder private func composer(_ contact: Contact) -> some View {
        if recorder.recording {
            HStack(spacing: 14) {
                Button { recorder.cancel() } label: { Image(systemName: "trash").font(.title3).frame(width: 40, height: 44) }
                    .tint(.red).accessibilityLabel("Odbaci snimak")
                Circle().fill(Color.red).frame(width: 10, height: 10)
                Text(verbatim: Self.clock(recorder.elapsed)).monospacedDigit()
                Text("Snimanje…").foregroundStyle(.secondary)
                Spacer()
                Button { finishRecording() } label: { Image(systemName: "arrow.up.circle.fill").font(.system(size: 34)).frame(width: 44, height: 44) }
                    .accessibilityLabel("Pošalji glasovnu poruku")
            }.padding(.horizontal, 14).padding(.vertical, 8).background(.bar)
        } else {
            HStack(alignment: .bottom, spacing: 8) {
                Menu {
                    Button { pickingPhoto = true } label: { Label("Fotografija", systemImage: "photo") }
                    Button { importingFile = true } label: { Label("Fajl", systemImage: "doc") }
                } label: {
                    Image(systemName: "plus.circle.fill").font(.system(size: 30)).frame(width: 40, height: 44)
                }.disabled(!canSend).accessibilityLabel("Dodaj fotografiju ili fajl")
                TextField("Napiši poruku…", text: $draft, axis: .vertical)
                    .lineLimit(1...6).textInputAutocapitalization(.sentences).autocorrectionDisabled()
                    .focused($composing).padding(.horizontal, 14).padding(.vertical, 10)
                    .background(GhostTheme.panel, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
                    .disabled(contact.blocked || contact.state == .disconnected)
                    .onChange(of: draft) { _, value in
                        guard value.utf8.count > Limits.maxTextBytes else { return }
                        var trimmed = value
                        while trimmed.utf8.count > Limits.maxTextBytes { trimmed.removeLast() }
                        draft = trimmed
                    }
                if draftIsEmpty {
                    Button { startRecording() } label: { Image(systemName: "mic.circle.fill").font(.system(size: 34)).frame(width: 44, height: 44) }
                        .disabled(!canSend).accessibilityLabel("Snimi glasovnu poruku")
                } else {
                    Button { sendText() } label: { Image(systemName: "arrow.up.circle.fill").font(.system(size: 34)).frame(width: 44, height: 44) }
                        .disabled(!canSend).accessibilityLabel("Pošalji poruku")
                }
            }.padding(.horizontal, 10).padding(.vertical, 8).background(.bar)
        }
    }

    private var photoSheet: some View {
        NavigationStack {
            VStack(spacing: 24) {
                if let data = pendingPhoto, let image = UIImage(data: data) {
                    Image(uiImage: image).resizable().scaledToFit().clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous)).padding()
                }
                Label("Originalni EXIF/GPS podaci se ne prenose.", systemImage: "location.slash").font(.caption).foregroundStyle(.secondary)
                PrimaryButton(title: "Pošalji fotografiju", disabled: !canSend) {
                    guard let data = pendingPhoto else { return }
                    photoPreview = false; pendingPhoto = nil
                    Task { if await store.send(photo: data, to: contactID) { sentFeedback() } }
                }.padding()
            }.navigationTitle("Fotografija").navigationBarTitleDisplayMode(.inline)
                .toolbar { Button("Otkaži") { photoPreview = false; pendingPhoto = nil } }
        }.privacyShield()
    }

    // MARK: - Actions

    static func clock(_ seconds: TimeInterval) -> String {
        let value = Int(seconds)
        return String(format: "%d:%02d", value / 60, value % 60)
    }
    private func sentFeedback() { UIImpactFeedbackGenerator(style: .light).impactOccurred() }
    private func sendText() {
        let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        Task { if await store.send(text: text, to: contactID) { draft = ""; sentFeedback() } }
    }
    private func clearComposer() {
        importTask?.cancel(); draft = ""; pendingPhoto = nil; photoItem = nil; photoPreview = false; composing = false
        recorder.cancel(); player.stop(); pendingFile = nil; importingFile = false; pickingPhoto = false
    }
    private func startRecording() {
        composing = false
        player.stop()
        Task {
            guard await recorder.requestPermission() else {
                store.error = String(localized: "Dozvoli pristup mikrofonu u iOS podešavanjima: Podešavanja → Ghost ECC → Mikrofon.")
                return
            }
            guard !store.shouldCover, canSend else { return }
            do { try recorder.start(); UIImpactFeedbackGenerator(style: .medium).impactOccurred() }
            catch { store.error = String(localized: "Snimanje nije moguće pokrenuti.") }
        }
    }
    private func finishRecording() {
        guard let wav = recorder.stop() else { return }
        Task { if await store.send(.voice(wav), to: contactID) { sentFeedback() } }
    }
    /// Reads the picked file into memory; the app never copies it to its own storage.
    private func loadFile(_ url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
            let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
            guard size > 0, size <= Limits.maxFileBytes else { throw GhostError.tooLarge }
            let data = try Data(contentsOf: url)
            guard !data.isEmpty, data.count <= Limits.maxFileBytes else { throw GhostError.tooLarge }
            let type = UTType(filenameExtension: url.pathExtension)?.identifier ?? UTType.data.identifier
            pendingFile = FileAttachment(name: FileAttachment.cleanName(url.lastPathComponent), type: type, data: data)
        } catch { store.error = error.localizedDescription }
    }
    private func loadPhoto(_ item: PhotosPickerItem?) {
        importTask?.cancel(); guard let item else { return }; importing = true
        importTask = Task { @MainActor in
            defer { importing = false; photoItem = nil }
            do {
                guard let data = try await item.loadTransferable(type: Data.self) else { throw GhostError.invalidPayload }
                try Task.checkCancellation()
                let clean = try PhotoTools.sanitize(data)
                try Task.checkCancellation()
                guard !store.shouldCover else { return }
                pendingPhoto = clean; photoPreview = true
            } catch { if !Task.isCancelled { store.error = error.localizedDescription } }
        }
    }
}

// MARK: - Bubbles

struct MessageBubble: View {
    @EnvironmentObject private var store: AppStore
    let message: ChatMessage
    let contactID: String
    @ObservedObject var player: VoicePlayer
    @State private var showingPhoto = false
    private var shape: UnevenRoundedRectangle {
        UnevenRoundedRectangle(topLeadingRadius: 20, bottomLeadingRadius: message.outgoing ? 20 : 6,
                               bottomTrailingRadius: message.outgoing ? 6 : 20, topTrailingRadius: 20, style: .continuous)
    }
    var body: some View {
        HStack(spacing: 0) {
            if message.outgoing { Spacer(minLength: 60) }
            VStack(alignment: message.outgoing ? .trailing : .leading, spacing: 6) {
                if let preview = message.preview {
                    Button { showingPhoto = true } label: {
                        Image(uiImage: preview).resizable().scaledToFit()
                            .frame(maxWidth: 260, maxHeight: 320)
                            .clipShape(shape)
                            .overlay(alignment: .bottomTrailing) {
                                MessageMeta(message: message).padding(.horizontal, 8).padding(.vertical, 4)
                                    .background(.black.opacity(0.45), in: Capsule()).padding(8)
                            }
                    }.buttonStyle(.plain).accessibilityLabel("Otvori fotografiju")
                        .fullScreenCover(isPresented: $showingPhoto) { PhotoDetailView(message: message) }
                } else {
                    VStack(alignment: .trailing, spacing: 6) {
                        if let voice = message.voice { VoiceBubbleContent(id: message.id, data: voice, player: player) }
                        if let file = message.file { FileBubbleContent(file: file) }
                        if let text = message.text {
                            Text(text).foregroundStyle(.white).fixedSize(horizontal: false, vertical: true).textSelection(.disabled)
                        }
                        MessageMeta(message: message)
                    }
                    .padding(.horizontal, 14).padding(.vertical, 10)
                    .background(message.outgoing ? AnyShapeStyle(GhostTheme.outgoing) : AnyShapeStyle(GhostTheme.secondaryPanel), in: shape)
                }
                if message.outgoing && message.status == .failed && message.wire != nil {
                    Button { Task { await store.retry(message.id, in: contactID) } } label: {
                        Label("Nije poslato · Pokušaj ponovo", systemImage: "exclamationmark.circle.fill")
                    }.font(.caption.bold()).foregroundStyle(.red)
                }
            }
            if !message.outgoing { Spacer(minLength: 60) }
        }.id(message.id)
    }
}

/// Send time, delivery state and remaining lifetime in one discreet line.
struct MessageMeta: View {
    let message: ChatMessage
    private var statusText: String {
        switch message.status {
        case .local: return String(localized: "Lokalni test")
        case .sending: return String(localized: "Slanje…")
        case .accepted: return String(localized: "Na serveru")
        case .delivered: return String(localized: "Primljeno")
        case .failed: return String(localized: "Nije poslato")
        }
    }
    private var statusIcon: String {
        switch message.status {
        case .sending: return "clock"
        case .failed: return "exclamationmark.circle"
        case .local, .accepted, .delivered: return "checkmark"
        }
    }
    static func remaining(_ seconds: TimeInterval) -> String {
        let value = Int(seconds)
        if value >= 3600 { return "\(value / 3600) h" }
        if value >= 60 { return "\(value / 60) min" }
        return "\(value) s"
    }
    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            HStack(spacing: 4) {
                Text(message.sentAt, format: .dateTime.hour().minute())
                if message.outgoing { Image(systemName: statusIcon).accessibilityLabel(statusText) }
                Image(systemName: "timer").imageScale(.small).padding(.leading, 2)
                Text(verbatim: Self.remaining(message.remaining(now: context.date)))
            }
            .font(.caption2).monospacedDigit().foregroundStyle(.white.opacity(0.72))
            .accessibilityElement(children: .combine)
        }
    }
}

struct VoiceBubbleContent: View {
    let id: UUID
    let data: Data
    @ObservedObject var player: VoicePlayer
    var body: some View {
        let playing = player.playingID == id
        HStack(spacing: 12) {
            Button { player.toggle(id, data: data) } label: {
                Image(systemName: playing ? "pause.circle.fill" : "play.circle.fill").font(.system(size: 34))
            }.foregroundStyle(.white)
                .accessibilityLabel(playing ? String(localized: "Zaustavi") : String(localized: "Pusti glasovnu poruku"))
            VStack(alignment: .leading, spacing: 6) {
                ProgressView(value: playing ? player.progress : 0).tint(.white)
                Text(verbatim: ChatView.clock(WAV.duration(of: data).rounded())).font(.caption2).monospacedDigit().foregroundStyle(.white.opacity(0.8))
            }.frame(width: 150)
        }
    }
}

struct FileBubbleContent: View {
    let file: FileAttachment
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(systemName: "doc.fill").font(.title2).foregroundStyle(.white)
                VStack(alignment: .leading, spacing: 2) {
                    Text(verbatim: file.name).font(.subheadline.bold()).foregroundStyle(.white).lineLimit(2)
                    Text(verbatim: ByteCountFormatter.string(fromByteCount: Int64(file.data.count), countStyle: .file)).font(.caption2).foregroundStyle(.white.opacity(0.8))
                }
            }
            // Saving or sharing is the only way a file leaves the app's memory, and only by the user's choice.
            ShareLink(item: SharedFile(file: file), preview: SharePreview(file.name)) {
                Label("Sačuvaj ili podijeli", systemImage: "square.and.arrow.up")
            }.font(.caption.bold()).buttonStyle(.bordered).tint(.white)
        }.frame(maxWidth: 240, alignment: .leading)
    }
}

struct SharedFile: Transferable {
    let file: FileAttachment
    static var transferRepresentation: some TransferRepresentation {
        DataRepresentation(exportedContentType: .data) { $0.file.data }
            .suggestedFileName { $0.file.name }
    }
}

struct PhotoDetailView: View {
    let message: ChatMessage
    @EnvironmentObject private var store: AppStore
    @Environment(\.dismiss) private var dismiss
    @State private var image: UIImage?
    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            if store.shouldCover { Text("Fotografija je sakrivena.") }
            else if let image { Image(uiImage: image).resizable().scaledToFit() }
            else { ProgressView() }
            VStack { HStack { Spacer(); Button("Zatvori") { dismiss() }.padding() }; Spacer() }
        }
        .task { image = message.photo.flatMap { UIImage(data: $0) } }
        .onChange(of: store.shouldCover) { _, covered in if covered { dismiss() } }
        .onReceive(Timer.publish(every: 1, on: .main, in: .common).autoconnect()) { now in
            if message.remaining(now: now) <= 0 { dismiss() }
        }
    }
}
