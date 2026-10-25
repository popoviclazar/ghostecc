import SwiftUI

enum GhostTheme {
    static let blue = Color(red: 0.20, green: 0.48, blue: 1)
    static let background = Color(red: 0.025, green: 0.04, blue: 0.075)
    static let panel = Color(red: 0.065, green: 0.09, blue: 0.15)
    static let secondaryPanel = Color(red: 0.09, green: 0.13, blue: 0.22)
    static let outgoing = LinearGradient(colors: [Color(red: 0.25, green: 0.54, blue: 1), Color(red: 0.15, green: 0.39, blue: 0.94)],
                                         startPoint: .topLeading, endPoint: .bottomTrailing)
}
struct GhostMark: View {
    var size: CGFloat = 96
    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.27).fill(GhostTheme.blue.opacity(0.13))
            GhostShape().fill(LinearGradient(colors: [.white, GhostTheme.blue], startPoint: .topLeading, endPoint: .bottomTrailing)).padding(size * 0.22)
                .shadow(color: GhostTheme.blue.opacity(0.55), radius: size * 0.1)
            HStack(spacing: size * 0.13) {
                Capsule().fill(GhostTheme.background).frame(width: size * 0.08, height: size * 0.12)
                Capsule().fill(GhostTheme.background).frame(width: size * 0.08, height: size * 0.12)
            }.offset(y: -size * 0.03)
        }.frame(width: size, height: size).accessibilityHidden(true)
    }
}
struct GhostShape: Shape {
    func path(in r: CGRect) -> Path {
        var p = Path(); p.move(to: CGPoint(x: 0, y: r.height))
        p.addLine(to: CGPoint(x: 0, y: r.height * 0.45))
        p.addCurve(to: CGPoint(x: r.width, y: r.height * 0.45), control1: CGPoint(x: 0, y: -r.height * 0.15), control2: CGPoint(x: r.width, y: -r.height * 0.15))
        p.addLine(to: CGPoint(x: r.width, y: r.height))
        for i in stride(from: 5, through: 0, by: -1) { p.addLine(to: CGPoint(x: r.width * CGFloat(i) / 6, y: r.height * (i % 2 == 0 ? 1 : 0.8))) }
        p.closeSubpath(); return p
    }
}
struct ContactAvatar: View {
    let contact: Contact
    var body: some View {
        ZStack {
            Circle().fill(GhostTheme.secondaryPanel)
            if contact.isDemo { Image(systemName: "testtube.2").foregroundStyle(GhostTheme.blue) }
            else { Text(String(contact.title.prefix(1)).uppercased()).font(.headline).foregroundStyle(.white) }
        }.frame(width: 48, height: 48).accessibilityHidden(true)
    }
}
struct PrimaryButton: View {
    let title: LocalizedStringKey
    var disabled = false
    let action: () -> Void
    var body: some View {
        Button(action: action) { Text(title).bold().frame(maxWidth: .infinity).padding(12) }
            .buttonStyle(.borderedProminent).tint(GhostTheme.blue).disabled(disabled)
    }
}
