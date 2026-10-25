import SwiftUI
import AVFoundation
import VisionKit

struct QRScanView: View {
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject private var store: AppStore
    var prefix: String = InviteLink.prefix
    var title = LocalizedStringKey("Skeniraj pozivnicu")
    let onResult: (String) -> Void
    @State private var permitted = false
    @State private var checked = false
    var body: some View {
        NavigationStack {
            Group {
                if permitted && DataScannerViewController.isSupported && DataScannerViewController.isAvailable {
                    QRScanner(active: !store.shouldCover, prefix: prefix, onResult: onResult).ignoresSafeArea(edges: .bottom)
                } else if !checked { ProgressView("Priprema kamere…") }
                else {
                    ContentUnavailableView("QR kamera nije dostupna", systemImage: "qrcode.viewfinder", description: Text("Omogući kameru u iOS podešavanjima. Na simulatoru kamera nije dostupna."))
                }
            }.navigationTitle(title).navigationBarTitleDisplayMode(.inline).toolbar { Button("Zatvori") { dismiss() } }
                .task {
                    permitted = await AVCaptureDevice.requestAccess(for: .video); checked = true
                }
        }.privacyShield()
    }
}
struct QRScanner: UIViewControllerRepresentable {
    let active: Bool
    let prefix: String
    let onResult: (String) -> Void
    func makeCoordinator() -> Coordinator { Coordinator(prefix: prefix, onResult: onResult) }
    func makeUIViewController(context: Context) -> DataScannerViewController {
        let controller = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])], qualityLevel: .balanced,
            recognizesMultipleItems: false, isHighFrameRateTrackingEnabled: false, isPinchToZoomEnabled: true, isGuidanceEnabled: true, isHighlightingEnabled: true)
        controller.delegate = context.coordinator
        if active { try? controller.startScanning() }
        return controller
    }
    func updateUIViewController(_ controller: DataScannerViewController, context: Context) {
        if active && !controller.isScanning { try? controller.startScanning() }
        else if !active { controller.stopScanning() }
    }
    static func dismantleUIViewController(_ controller: DataScannerViewController, coordinator: Coordinator) { controller.stopScanning() }
    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let prefix: String
        let onResult: (String) -> Void
        var didReturn = false
        init(prefix: String, onResult: @escaping (String) -> Void) { self.prefix = prefix; self.onResult = onResult }
        func dataScanner(_ dataScanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) {
            guard !didReturn else { return }
            for item in addedItems {
                if case .barcode(let barcode) = item, let value = barcode.payloadStringValue,
                   value.hasPrefix(prefix), value.count < 2048 {
                    didReturn = true; dataScanner.stopScanning(); onResult(value); return
                }
            }
        }
    }
}
