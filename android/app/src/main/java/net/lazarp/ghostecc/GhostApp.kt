package net.lazarp.ghostecc

import android.app.Application
import net.lazarp.ghostecc.net.RelayClient
import net.lazarp.ghostecc.security.KeystoreVault
import net.lazarp.ghostecc.security.SignalEngine

/** Production endpoints and the long-lived objects of the app. Forks change the relay here. */
class GhostApp : Application() {
    val vault by lazy { KeystoreVault(this) }
    val engine by lazy { SignalEngine(vault) }
    val relay by lazy { RelayClient(DEFAULT_SERVER) }

    companion object {
        const val DEFAULT_SERVER = "https://relay.relayghostecc.net"
        const val PRIVACY_POLICY = "https://popoviclazar.github.io/ghostecc/privacy.html"
        const val SUPPORT = "https://popoviclazar.github.io/ghostecc/support.html"
        const val SOURCE_CODE = "https://github.com/popoviclazar/ghostecc"
    }
}
