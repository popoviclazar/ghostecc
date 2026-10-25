import SwiftUI

struct AboutView: View {
    var body: some View {
        Form {
            Section {
                HStack(spacing: 16) {
                    GhostMark(size: 56)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(verbatim: "Ghost ECC").font(.headline)
                        Text(verbatim: AppConfig.version).font(.caption).foregroundStyle(.secondary)
                    }
                }.padding(.vertical, 6)
            }
            Section {
                Link(destination: AppConfig.privacyPolicy) { Label("Politika privatnosti", systemImage: "hand.raised") }
                Link(destination: AppConfig.support) { Label("Podrška i prijava problema", systemImage: "questionmark.circle") }
                Link(destination: AppConfig.sourceCode) { Label("Izvorni kod", systemImage: "chevron.left.forwardslash.chevron.right") }
            }
            Section("Licence") {
                Text("Ghost ECC je softver otvorenog koda pod licencom GNU Affero General Public License v3.0. Izvorni kod ove verzije je javno dostupan na linku iznad.").font(.footnote)
                Text("Enkripcija: libsignal, © Signal Messenger, LLC, licenca GNU AGPL v3.0. Ghost ECC nije proizvod kompanije Signal niti je ona podržava.").font(.footnote)
                Text("Kriptografski primitivi: Apple CryptoKit.").font(.footnote).foregroundStyle(.secondary)
            }
        }.scrollContentBackground(.hidden).background(GhostTheme.background).navigationTitle("O aplikaciji")
    }
}
