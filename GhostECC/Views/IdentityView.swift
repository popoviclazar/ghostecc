import SwiftUI
import UIKit
import CoreImage.CIFilterBuiltins

struct IdentityView: View {
    @EnvironmentObject private var store: AppStore
    @State private var inviting = false
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 26) {
                    GhostMark(size: 88).padding(.top, 24)
                    Text("Tvoj Ghost ID").font(.title2.bold())
                    if let identity = store.identity {
                        VStack(spacing: 6) {
                            Text(verbatim: "GHOST").font(.caption.bold()).tracking(2).foregroundStyle(.secondary)
                            Text(verbatim: Self.grouped(identity)).font(.system(.callout, design: .monospaced)).multilineTextAlignment(.center)
                                .textSelection(.enabled)
                        }.padding(16).frame(maxWidth: .infinity).background(GhostTheme.panel, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
                            .accessibilityElement(children: .combine)
                    }
                    PrimaryButton(title: "Nova pozivnica") { inviting = true }
                    VStack(alignment: .leading, spacing: 16) {
                        Label("Bez broja telefona i emaila", systemImage: "person.crop.square")
                        Label("Server ne zna tvoj Ghost ID ni sa kim pričaš", systemImage: "eye.slash")
                        Label("Privatni ključ ostaje na uređaju", systemImage: "key.fill")
                        Label("Bez izvoza ključeva i oporavka", systemImage: "externaldrive.badge.xmark")
                    }.font(.subheadline).padding(24).frame(maxWidth: .infinity, alignment: .leading).background(GhostTheme.panel, in: RoundedRectangle(cornerRadius: 24))
                    Text("Ghost ID služi za provjeru sigurnosnog broja. Kontakti se dodaju samo jednokratnim pozivnicama, pa ti niko ne može pisati bez tvoje pozivnice. Ako izgubiš uređaj ili obrišeš identitet, ne postoji bekap za vraćanje.")
                        .font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center)
                }.padding(24)
            }.background(GhostTheme.background).navigationTitle("Identitet")
                .sheet(isPresented: $inviting) { NewInviteView() }
        }
    }
}

extension IdentityView {
    /// 64 hex characters as four lines of four groups, like a safety number.
    static func grouped(_ id: GhostID) -> String {
        let hex = Array(id.rawValue.dropFirst("GHOST-".count))
        let groups = stride(from: 0, to: hex.count, by: 4).map { String(hex[$0..<min($0 + 4, hex.count)]) }
        return stride(from: 0, to: groups.count, by: 4).map { groups[$0..<min($0 + 4, groups.count)].joined(separator: " ") }.joined(separator: "\n")
    }
}

enum QRImage {
    static func make(_ string: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator(); filter.message = Data(string.utf8); filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)),
              let cg = CIContext().createCGImage(output, from: output.extent) else { return nil }
        return UIImage(cgImage: cg)
    }
}
