import SwiftUI

enum InboxSheet: Identifiable {
    case newInvite, invite(UUID), join(String?), newGroup
    var id: String {
        switch self {
        case .newInvite: return "new-invite"
        case .newGroup: return "new-group"
        case .invite(let id): return "invite-" + id.uuidString
        case .join: return "join"
        }
    }
}

struct InboxView: View {
    @EnvironmentObject private var store: AppStore
    @State private var search = ""
    @State private var sheet: InboxSheet?
    private enum Row: Identifiable {
        case contact(Contact), group(GhostGroup)
        var id: String {
            switch self {
            case .contact(let contact): return contact.id
            case .group(let group): return group.chatID
            }
        }
        var title: String {
            switch self {
            case .contact(let contact): return contact.title
            case .group(let group): return group.title
            }
        }
    }
    /// Contacts and groups together: most recent conversation first, then alphabetically.
    private var rows: [Row] {
        let contacts = store.listedContacts
            .filter { search.isEmpty || $0.title.localizedCaseInsensitiveContains(search) || $0.id.localizedCaseInsensitiveContains(search) }
            .map { Row.contact($0) }
        let groups = store.groups
            .filter { $0.state == .joined && (search.isEmpty || $0.title.localizedCaseInsensitiveContains(search)) }
            .map { Row.group($0) }
        return (contacts + groups).sorted { a, b in
            let lhs = store.messages[a.id]?.last?.sentAt, rhs = store.messages[b.id]?.last?.sentAt
            if lhs != rhs { return (lhs ?? .distantPast) > (rhs ?? .distantPast) }
            return a.title.localizedCaseInsensitiveCompare(b.title) == .orderedAscending
        }
    }
    private var visibleInvites: [PendingInvite] { store.invites.filter { $0.introduction == nil } }
    private var groupInvitations: [GhostGroup] { store.groups.filter { $0.state == .invited } }
    var body: some View {
        NavigationStack {
            List {
                Section {
                    HStack {
                        Circle().fill(store.networkHealthy ? Color.green : Color.orange).frame(width: 6, height: 6)
                        Text(store.networkStatus).font(.caption).foregroundStyle(.secondary)
                        Spacer(); Label("24 h max", systemImage: "timer").font(.caption).foregroundStyle(.secondary)
                    }
                }.listRowBackground(Color.clear)
                if !groupInvitations.isEmpty {
                    Section("Pozivi u grupe") {
                        ForEach(groupInvitations) { group in
                            VStack(alignment: .leading, spacing: 10) {
                                HStack(spacing: 14) {
                                    GroupAvatar()
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(group.title).font(.headline)
                                        Text("\(store.displayName(group.admin, in: group)) · \(String(group.members.count)) članova").font(.subheadline).foregroundStyle(.secondary)
                                    }
                                }
                                HStack {
                                    Button("Prihvati") { Task { await store.acceptGroup(group.id) } }.buttonStyle(.borderedProminent).tint(GhostTheme.blue)
                                    Button("Odbij", role: .destructive) { Task { await store.leaveGroup(group.id) } }.buttonStyle(.bordered)
                                }
                            }.padding(.vertical, 6).listRowBackground(GhostTheme.panel)
                        }
                    }
                }
                if !visibleInvites.isEmpty {
                    Section("Pozivnice na čekanju") {
                        ForEach(visibleInvites) { invite in
                            Button { sheet = .invite(invite.id) } label: {
                                HStack(spacing: 14) {
                                    Image(systemName: "qrcode").font(.title3).foregroundStyle(GhostTheme.blue).frame(width: 48, height: 48)
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(invite.title).font(.headline).foregroundStyle(.primary)
                                        Text("Čeka da se sagovornik poveže").font(.subheadline).foregroundStyle(.secondary)
                                    }
                                }
                            }.listRowBackground(GhostTheme.panel)
                                .swipeActions { Button("Otkaži", role: .destructive) { Task { await store.cancelInvite(invite.id) } } }
                        }
                    }
                }
                if store.listedContacts.isEmpty && visibleInvites.isEmpty && store.groups.isEmpty {
                    VStack(spacing: 18) {
                        GhostMark(size: 78)
                        Text("Samo tvoji razgovori").font(.title3.bold())
                        Text("Kontakti se dodaju jednokratnom pozivnicom. Niko ti ne može pisati bez nje.").font(.subheadline).foregroundStyle(.secondary).multilineTextAlignment(.center)
                        Button("Nova pozivnica") { sheet = .newInvite }.buttonStyle(.borderedProminent).tint(GhostTheme.blue)
                        Button("Imam pozivnicu") { sheet = .join(nil) }.buttonStyle(.bordered)
                        Button("Otvori Ghost Lab") { Task { await store.addDemo() } }.font(.footnote).disabled(store.busy)
                    }.frame(maxWidth: .infinity).padding(.vertical, 36).listRowBackground(Color.clear)
                }
                ForEach(rows) { row in
                    switch row {
                    case .contact(let contact): contactRow(contact)
                    case .group(let group): groupRow(group)
                    }
                }
            }.scrollContentBackground(.hidden).background(GhostTheme.background)
                .navigationTitle("Razgovori").searchable(text: $search, prompt: String(localized: "Ime ili Ghost ID"))
                .toolbar {
                    ToolbarItem(placement: .topBarTrailing) {
                        Menu {
                            Button { sheet = .newInvite } label: { Label("Nova pozivnica", systemImage: "qrcode") }
                            Button { sheet = .join(nil) } label: { Label("Unesi pozivnicu", systemImage: "link") }
                            Button { sheet = .newGroup } label: { Label("Nova grupa", systemImage: "person.3") }
                        } label: { Image(systemName: "square.and.pencil") }.accessibilityLabel("Dodaj kontakt")
                    }
                }
                .sheet(item: $sheet) { item in sheetContent(item) }
                .onChange(of: store.pendingLink) { _, link in if let link { sheet = .join(link) } }
                .onAppear { if let link = store.pendingLink { sheet = .join(link) } }
        }.privacyShield()
    }
    @ViewBuilder private func sheetContent(_ item: InboxSheet) -> some View {
        switch item {
        case .newInvite: NewInviteView()
        case .invite(let id): InviteDetailView(inviteID: id)
        case .join(let link): JoinInviteView(link: link)
        case .newGroup: NewGroupView()
        }
    }

    private func contactRow(_ contact: Contact) -> some View {
        NavigationLink { ChatView(contactID: contact.id) } label: {
            let unread = store.unread[contact.id] ?? 0
            HStack(spacing: 14) {
                ContactAvatar(contact: contact)
                VStack(alignment: .leading, spacing: 5) {
                    HStack(spacing: 6) {
                        Text(contact.title).font(unread > 0 ? .headline.weight(.heavy) : .headline).lineLimit(1)
                        if contact.verified { Image(systemName: "checkmark.shield.fill").foregroundStyle(GhostTheme.blue).font(.caption) }
                        if contact.isDemo { Text("LAB").font(.caption2.bold()).foregroundStyle(GhostTheme.blue) }
                    }
                    Text(subtitle(contact)).font(.subheadline)
                        .foregroundStyle(contact.state == .disconnected ? Color.orange : (unread > 0 ? Color.primary : Color.secondary)).lineLimit(1)
                }
                Spacer(minLength: 8)
                RowTrailing(last: store.messages[contact.id]?.last, unread: unread)
            }.padding(.vertical, 8)
        }.listRowBackground(GhostTheme.panel)
            .swipeActions { Button("Obriši", role: .destructive) { store.deleteContact(contact.id) } }
    }

    private func groupRow(_ group: GhostGroup) -> some View {
        NavigationLink { ChatView(contactID: group.chatID) } label: {
            let unread = store.unread[group.chatID] ?? 0
            HStack(spacing: 14) {
                GroupAvatar()
                VStack(alignment: .leading, spacing: 5) {
                    HStack(spacing: 6) {
                        Text(group.title).font(unread > 0 ? .headline.weight(.heavy) : .headline).lineLimit(1)
                        if group.isDemo == true { Text("LAB").font(.caption2.bold()).foregroundStyle(GhostTheme.blue) }
                    }
                    Text(groupSubtitle(group)).font(.subheadline).foregroundStyle(unread > 0 ? Color.primary : Color.secondary).lineLimit(1)
                }
                Spacer(minLength: 8)
                RowTrailing(last: store.messages[group.chatID]?.last, unread: unread)
            }.padding(.vertical, 8)
        }.listRowBackground(GhostTheme.panel)
            .swipeActions { Button("Napusti", role: .destructive) { Task { await store.leaveGroup(group.id) } } }
    }

    private func groupSubtitle(_ group: GhostGroup) -> String {
        guard let last = store.messages[group.chatID]?.last else {
            return String(localized: "\(String(group.members.count)) članova")
        }
        return store.displayName(last.sender, in: group) + ": " + preview(last)
    }

    private func preview(_ message: ChatMessage) -> String {
        if let text = message.text { return text }
        if message.voice != nil { return String(localized: "Glasovna poruka") }
        if let file = message.file { return String(localized: "Fajl: \(file.name)") }
        return String(localized: "Fotografija")
    }
    private func subtitle(_ contact: Contact) -> String {
        if contact.blocked { return String(localized: "Blokiran") }
        switch contact.state {
        case .connecting: return String(localized: "Čeka potvrdu veze")
        case .disconnected: return String(localized: "Veza prekinuta")
        case .connected: break
        }
        if let last = store.messages[contact.id]?.last { return preview(last) }
        return contact.verified ? String(localized: "Nema sačuvane istorije") : String(localized: "Uporedi sigurnosni broj")
    }
}

struct NewInviteView: View {
    @EnvironmentObject private var store: AppStore
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var created: UUID?
    var body: some View {
        NavigationStack {
            Group {
                if let created {
                    if let invite = store.invites.first(where: { $0.id == created }) { InviteQRContent(invite: invite) }
                    else { ContentUnavailableView("Pozivnica je iskorišćena", systemImage: "checkmark.circle", description: Text("Kontakt je dodat u razgovore.")) }
                } else {
                    Form {
                        Section("Za koga je pozivnica") {
                            TextField("Ime na ovom uređaju", text: $name).textContentType(.nickname)
                        }
                        Section {
                            Text("Pozivnica je jednokratna i važi 7 dana. Ko je prvi iskoristi postaje kontakt, zato je pokaži uživo ili pošalji pouzdanim kanalom.").font(.footnote).foregroundStyle(.secondary)
                        }
                        Section {
                            Button(store.busy ? String(localized: "Pravljenje…") : String(localized: "Napravi pozivnicu")) {
                                Task { if let invite = await store.createInvite(name: name) { created = invite.id } }
                            }.disabled(store.busy)
                        }
                    }
                }
            }.navigationTitle("Nova pozivnica").navigationBarTitleDisplayMode(.inline)
                .toolbar { Button("Zatvori") { dismiss() } }
        }.privacyShield()
    }
}

struct InviteDetailView: View {
    @EnvironmentObject private var store: AppStore
    @Environment(\.dismiss) private var dismiss
    let inviteID: UUID
    var body: some View {
        NavigationStack {
            Group {
                if let invite = store.invites.first(where: { $0.id == inviteID }) { InviteQRContent(invite: invite) }
                else { ContentUnavailableView("Pozivnica više nije aktivna", systemImage: "checkmark.circle", description: Text("Iskorišćena je, otkazana ili je istekla.")) }
            }.navigationTitle("Pozivnica").navigationBarTitleDisplayMode(.inline)
                .toolbar { Button("Zatvori") { dismiss() } }
        }.privacyShield()
    }
}

struct InviteQRContent: View {
    @EnvironmentObject private var store: AppStore
    @Environment(\.dismiss) private var dismiss
    let invite: PendingInvite
    @State private var image: UIImage?
    var body: some View {
        ScrollView {
            VStack(spacing: 22) {
                Group {
                    if let image { Image(uiImage: image).interpolation(.none).resizable().scaledToFit() } else { ProgressView() }
                }.frame(width: 250, height: 250).padding(16).background(.white, in: RoundedRectangle(cornerRadius: 24))
                    .accessibilityLabel("QR kod jednokratne pozivnice")
                Text(invite.title).font(.title3.bold())
                Text("Sagovornik skenira kod u Ghost Talk aplikaciji: Razgovori → ✎ → Unesi pozivnicu. Važi do \(invite.expiresAt.formatted(date: .abbreviated, time: .shortened)).")
                    .font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center)
                ShareLink(item: invite.link) { Label("Podijeli link pozivnice", systemImage: "square.and.arrow.up") }.buttonStyle(.borderedProminent).tint(GhostTheme.blue)
                Text("Link sadrži ključ za otvaranje pozivnice. Ne objavljuj ga javno.").font(.caption).foregroundStyle(.secondary)
                Button("Otkaži pozivnicu", role: .destructive) { Task { await store.cancelInvite(invite.id); dismiss() } }
            }.padding(24).frame(maxWidth: .infinity)
        }.background(GhostTheme.background)
            .task(id: invite.id) { image = QRImage.make(invite.link) }
    }
}

struct JoinInviteView: View {
    @EnvironmentObject private var store: AppStore
    @Environment(\.dismiss) private var dismiss
    @State private var input: String
    @State private var name = ""
    @State private var scanning = false
    init(link: String?) { _input = State(initialValue: link ?? "") }
    var body: some View {
        NavigationStack {
            Form {
                Section("Pozivnica") {
                    TextField("Ime na ovom uređaju", text: $name).textContentType(.nickname)
                    TextField("ghost-ecc://invite/…", text: $input, axis: .vertical).lineLimit(2...5).textInputAutocapitalization(.never).autocorrectionDisabled()
                    Button { scanning = true } label: { Label("Skeniraj QR kod", systemImage: "qrcode.viewfinder") }
                }
                Section {
                    Text("Ime ostaje samo na ovom uređaju. Nakon povezivanja uporedi sigurnosni broj sa sagovornikom prije slanja poruka.").font(.footnote).foregroundStyle(.secondary)
                }
                Section {
                    Button(store.busy ? String(localized: "Povezivanje…") : String(localized: "Poveži se")) {
                        Task { if await store.acceptInvite(input, name: name) { dismiss() } }
                    }.disabled(input.isEmpty || store.busy)
                }
            }.navigationTitle("Unesi pozivnicu").navigationBarTitleDisplayMode(.inline)
                .toolbar { Button("Zatvori") { dismiss() } }
                .sheet(isPresented: $scanning) { QRScanView { value in input = value; scanning = false } }
                .onDisappear { store.pendingLink = nil }
        }.privacyShield()
    }
}

/// Time of the last message and the unread badge, shared by contact and group rows.
struct RowTrailing: View {
    let last: ChatMessage?
    let unread: Int
    var body: some View {
        VStack(alignment: .trailing, spacing: 6) {
            if let last {
                Text(last.sentAt, format: .dateTime.hour().minute()).font(.caption).monospacedDigit()
                    .foregroundStyle(unread > 0 ? GhostTheme.blue : Color.secondary)
            }
            if unread > 0 {
                Text(verbatim: unread > 99 ? "99+" : String(unread)).font(.caption2.bold()).monospacedDigit().foregroundStyle(.white)
                    .padding(.horizontal, 7).padding(.vertical, 3).background(GhostTheme.blue, in: Capsule())
                    .accessibilityLabel(String(localized: "Nepročitano: \(String(unread))"))
            }
        }
    }
}

struct GroupAvatar: View {
    var size: CGFloat = 48
    var body: some View {
        Image(systemName: "person.3.fill").font(.system(size: size * 0.36)).foregroundStyle(GhostTheme.blue)
            .frame(width: size, height: size).background(GhostTheme.secondaryPanel, in: Circle())
            .accessibilityHidden(true)
    }
}
