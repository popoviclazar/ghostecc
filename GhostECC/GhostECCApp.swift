import SwiftUI
import UIKit
import UserNotifications

extension Notification.Name {
    /// Posted with the APNs token as a lowercase hex String, or nil when registration failed.
    static let ghostDeviceToken = Notification.Name("GhostDeviceToken")
}

final class GhostAppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        return true
    }
    func application(_ application: UIApplication, shouldAllowExtensionPointIdentifier extensionPointIdentifier: UIApplication.ExtensionPointIdentifier) -> Bool {
        // Keep message entry within Apple's system keyboard instead of third-party keyboard extensions.
        extensionPointIdentifier != .keyboard
    }
    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let token = deviceToken.map { String(format: "%02x", $0) }.joined()
        NotificationCenter.default.post(name: .ghostDeviceToken, object: token)
    }
    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        NotificationCenter.default.post(name: .ghostDeviceToken, object: nil)
    }
    // While the app is open it shows new messages itself, so the generic banner is suppressed.
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([])
    }
}

@main
struct GhostECCApp: App {
    @UIApplicationDelegateAdaptor(GhostAppDelegate.self) private var delegate
    @StateObject private var store = AppStore()
    @Environment(\.scenePhase) private var phase
    var body: some Scene {
        WindowGroup {
            RootView().environmentObject(store).preferredColorScheme(.dark)
                .task { await store.boot() }
                .onChange(of: phase) { _, newPhase in store.sceneChanged(newPhase) }
                .onOpenURL { url in store.openLink(url) }
                .onReceive(NotificationCenter.default.publisher(for: UIScreen.capturedDidChangeNotification)) { _ in store.captured = AppStore.screenCaptured }
                .onReceive(NotificationCenter.default.publisher(for: UIApplication.userDidTakeScreenshotNotification)) { _ in
                    store.notice = "iOS je zabilježio snimak ekrana. Već napravljen snimak nije moguće povući."
                }
        }
    }
}
