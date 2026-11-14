import SwiftUI

/// Wraps a contact id so a sheet can be presented for it.
struct ContactRef: Identifiable { let id: String }

struct MemberPickRow: View {
    let contact: Contact
    let selected: Bool
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                ContactAvatar(contact: contact, size: 36)
                Text(verbatim: contact.title).foregroundStyle(.primary)
                Spacer()
                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(selected ? GhostTheme.blue : Color.secondary)
            }
        }.accessibilityAddTraits(selected ? .isSelected : [])
    }
}

struct NewGroupView: View {
    @EnvironmentObject private var store: AppStore
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var selected = Set<String>()
    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Ime grupe", text: $name).textInputAutocapitalization(.sentences).autocorrectionDisabled()
                }
                Section {
                    if store.groupCandidates.isEmpty {
                        Text("Za grupu su potrebni kontakti sa potvrđenim sigurnosnim brojem.").foregroundStyle(.secondary)
                    }
                    ForEach(store.groupCandidates) { contact in
                        MemberPickRow(contact: contact, selected: selected.contains(contact.id)) { toggle(contact.id) }
                    }
                } header: { Text("Članovi") } footer: {
                    Text("Do \(String(GhostGroup.maxMembers - 1)) potvrđenih kontakata. Svako dobija poziv koji može prihvatiti ili odbiti; članovi koji se ne poznaju povezuju se automatski preko tebe.")
                }
            }
            .scrollContentBackground(.hidden).background(GhostTheme.background)
            .navigationTitle("Nova grupa").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Otkaži") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Napravi") {
                        Task { if await store.createGroup(name: name, memberIDs: Array(selected)) != nil { dismiss() } }
                    }.disabled(selected.isEmpty || name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || store.busy)
                }
            }
        }.privacyShield()
    }
    private func toggle(_ id: String) {
        if selected.contains(id) { selected.remove(id) }
        else if selected.count < GhostGroup.maxMembers - 1 { selected.insert(id) }
    }
}

struct GroupDetailView: View {
    @EnvironmentObject private var store: AppStore
    @Environment(\.dismiss) private var dismiss
    let groupID: String
    @State private var renaming = false
    @State private var newName = ""
    @State private var adding = false
    @State private var confirmingLeave = false
    @State private var contactDetail: ContactRef?
    private var group: GhostGroup? { store.group(groupID) }
    private var isAdmin: Bool { group?.admin == store.identity }

    var body: some View {
        NavigationStack {
            Group {
                if let group {
                    Form {
                        Section {
                            HStack {
                                Spacer()
                                VStack(spacing: 10) {
                                    GroupAvatar(size: 72)
                                    Text(verbatim: group.title).font(.title3.bold())
                                    Text("\(String(group.members.count)) članova").font(.footnote).foregroundStyle(.secondary)
                                }
                                Spacer()
                            }.padding(.vertical, 8)
                            if isAdmin {
                                Button { newName = group.name; renaming = true } label: { Label("Promijeni ime grupe", systemImage: "pencil") }
                            }
                        }
                        Section {
                            ForEach(group.members, id: \.ghostID) { member in memberRow(member, in: group) }
                            if isAdmin && group.isDemo != true && group.members.count < GhostGroup.maxMembers {
                                Button { adding = true } label: { Label("Dodaj članove", systemImage: "person.badge.plus") }
                            }
                        } header: { Text("Članovi") } footer: {
                            Text("Članovi koji se ne poznaju povezani su preko administratora. Za razgovor udvoje dodirni člana i potvrdi sigurnosni broj.")
                        }
                        Section {
                            Picker(selection: Binding(get: { group.lifetime ?? 0 }, set: { store.setLifetime($0 == 0 ? nil : $0, forChat: group.chatID) })) {
                                Text("Kao u podešavanjima").tag(0.0); Text("5 minuta").tag(300.0); Text("1 sat").tag(3600.0); Text("24 sata").tag(86_400.0)
                            } label: { Label("Trajanje poruka", systemImage: "timer") }
                        } footer: { Text("Važi za poruke koje ti šalješ u ovu grupu.") }
                        Section {
                            Button(role: .destructive) { confirmingLeave = true } label: {
                                Label(isAdmin ? String(localized: "Obriši grupu za sve") : String(localized: "Napusti grupu"),
                                      systemImage: "rectangle.portrait.and.arrow.right")
                            }
                        }
                    }
                    .scrollContentBackground(.hidden).background(GhostTheme.background)
                } else {
                    ContentUnavailableView("Grupa ne postoji", systemImage: "person.3")
                }
            }
            .navigationTitle("Grupa").navigationBarTitleDisplayMode(.inline)
            .toolbar { Button("Zatvori") { dismiss() } }
            .alert("Ime grupe", isPresented: $renaming) {
                TextField("Ime grupe", text: $newName)
                Button("Sačuvaj") { Task { await store.renameGroup(groupID, to: newName) } }
                Button("Otkaži", role: .cancel) { }
            }
            .confirmationDialog(isAdmin ? String(localized: "Obrisati grupu za sve članove?") : String(localized: "Napustiti grupu?"),
                                isPresented: $confirmingLeave, titleVisibility: .visible) {
                Button(isAdmin ? String(localized: "Obriši grupu") : String(localized: "Napusti"), role: .destructive) {
                    Task { await store.leaveGroup(groupID); dismiss() }
                }
            }
            .sheet(isPresented: $adding) { AddMembersView(groupID: groupID) }
            .sheet(item: $contactDetail) { ref in ContactDetailView(contactID: ref.id) }
        }.privacyShield()
    }

    @ViewBuilder private func memberRow(_ member: GroupMember, in group: GhostGroup) -> some View {
        let state = store.link(to: member)
        let contact = store.contacts.first { $0.ghostID == member.ghostID }
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(verbatim: store.displayName(member.ghostID, in: group))
                    if member.ghostID == group.admin { Text("admin").font(.caption2.bold()).foregroundStyle(GhostTheme.blue) }
                    if contact?.verified == true { Image(systemName: "checkmark.shield.fill").font(.caption).foregroundStyle(GhostTheme.blue) }
                }
                Text(statusText(state, contact: contact)).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if contact != nil && state != .me { Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary) }
        }
        .contentShape(Rectangle())
        .onTapGesture { if let contact, state != .me { contactDetail = ContactRef(id: contact.id) } }
        .swipeActions {
            if isAdmin && state != .me {
                Button("Ukloni", role: .destructive) { Task { await store.removeMember(member.ghostID, from: groupID) } }
            }
        }
    }

    private func statusText(_ state: AppStore.MemberLink, contact: Contact?) -> String {
        switch state {
        case .me: return String(localized: "Ti")
        case .connected:
            return contact?.isIntroduced == true && contact?.verified != true ? String(localized: "Povezan preko grupe") : String(localized: "Povezan")
        case .connecting: return String(localized: "Povezuje se…")
        case .unreachable: return String(localized: "Nije dostupan")
        }
    }
}

struct AddMembersView: View {
    @EnvironmentObject private var store: AppStore
    @Environment(\.dismiss) private var dismiss
    let groupID: String
    @State private var selected = Set<String>()
    private var candidates: [Contact] {
        guard let group = store.group(groupID) else { return [] }
        return store.groupCandidates.filter { group.member($0.ghostID) == nil }
    }
    private var room: Int { GhostGroup.maxMembers - (store.group(groupID)?.members.count ?? GhostGroup.maxMembers) }
    var body: some View {
        NavigationStack {
            Form {
                Section {
                    if candidates.isEmpty {
                        Text("Nema potvrđenih kontakata koji već nisu u grupi.").foregroundStyle(.secondary)
                    }
                    ForEach(candidates) { contact in
                        MemberPickRow(contact: contact, selected: selected.contains(contact.id)) { toggle(contact.id) }
                    }
                } footer: { Text("Novi članovi dobijaju poziv koji mogu prihvatiti ili odbiti.") }
            }
            .scrollContentBackground(.hidden).background(GhostTheme.background)
            .navigationTitle("Dodaj članove").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Otkaži") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Dodaj") { Task { await store.addMembers(Array(selected), to: groupID); dismiss() } }
                        .disabled(selected.isEmpty)
                }
            }
        }.privacyShield()
    }
    private func toggle(_ id: String) {
        if selected.contains(id) { selected.remove(id) }
        else if selected.count < room { selected.insert(id) }
    }
}

struct ForwardView: View {
    @EnvironmentObject private var store: AppStore
    @Environment(\.dismiss) private var dismiss
    let message: ChatMessage
    let from: String
    @State private var selected = Set<String>()
    @State private var sending = false
    private var targets: [ChatTarget] { store.forwardTargets.filter { $0.id != from } }
    var body: some View {
        NavigationStack {
            Form {
                Section {
                    if targets.isEmpty { Text("Nema drugih razgovora u koje se poruka može proslijediti.").foregroundStyle(.secondary) }
                    ForEach(targets) { target in
                        Button { toggle(target.id) } label: {
                            HStack(spacing: 12) {
                                Image(systemName: target.isGroup ? "person.3.fill" : "person.fill").foregroundStyle(GhostTheme.blue).frame(width: 28)
                                Text(verbatim: target.title).foregroundStyle(.primary)
                                Spacer()
                                Image(systemName: selected.contains(target.id) ? "checkmark.circle.fill" : "circle")
                                    .foregroundStyle(selected.contains(target.id) ? GhostTheme.blue : Color.secondary)
                            }
                        }.accessibilityAddTraits(selected.contains(target.id) ? .isSelected : [])
                    }
                } footer: { Text("Kopija se šifruje posebno za svakog primaoca i nosi oznaku „Proslijeđeno“.") }
            }
            .scrollContentBackground(.hidden).background(GhostTheme.background)
            .navigationTitle("Proslijedi").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Otkaži") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Pošalji") {
                        sending = true
                        Task {
                            _ = await store.forward(message, to: Array(selected))
                            sending = false
                            dismiss()
                        }
                    }.disabled(selected.isEmpty || sending)
                }
            }
        }.privacyShield()
    }
    private func toggle(_ id: String) {
        if selected.contains(id) { selected.remove(id) } else if selected.count < 10 { selected.insert(id) }
    }
}
