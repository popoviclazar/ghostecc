package net.lazarp.ghostecc

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import net.lazarp.ghostecc.core.Content
import net.lazarp.ghostecc.core.GhostID
import net.lazarp.ghostecc.core.PayloadKind
import net.lazarp.ghostecc.core.PrivatePayload
import net.lazarp.ghostecc.core.ReplyAddress
import net.lazarp.ghostecc.security.MemoryVault
import net.lazarp.ghostecc.security.SignalEngine

object GhostColors {
    val background = Color(0xFF060A13)
    val panel = Color(0xFF111A2E)
    val blue = Color(0xFF3D7BFF)
    val secondary = Color(0xFF8A94A8)
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Android, unlike iOS, can block screenshots, screen recording and the preview in recent apps entirely.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        val app = application as GhostApp
        setContent {
            MaterialTheme(colorScheme = darkColorScheme(primary = GhostColors.blue, background = GhostColors.background, surface = GhostColors.panel)) {
                Surface(Modifier.fillMaxSize(), color = GhostColors.background) { DiagnosticsScreen(app) }
            }
        }
    }
}

/** Phase 1: proves on a real phone that identity, encryption and the relay work, before the full interface exists. */
@Composable
fun DiagnosticsScreen(app: GhostApp) {
    val scope = rememberCoroutineScope()
    var identity by remember { mutableStateOf<GhostID?>(null) }
    var crypto by remember { mutableStateOf("Not run") }
    var server by remember { mutableStateOf("Not checked") }
    var mailbox by remember { mutableStateOf("Not run") }
    LaunchedEffect(Unit) { identity = runCatching { app.engine.loadIdentity()?.first }.getOrNull() }

    Column(
        Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("GHOST TALK", fontSize = 30.sp, fontWeight = FontWeight.Black, color = Color.White)
        Text("Android preview · phase 1: identity, encryption and server", color = GhostColors.secondary)

        Section("Ghost ID") {
            val id = identity
            if (id == null) {
                Action("Create Ghost ID") { scope.launch { identity = runCatching { app.engine.loadIdentity(create = true)?.first }.getOrNull() } }
            } else {
                Text(grouped(id), fontFamily = FontFamily.Monospace, color = Color.White, fontSize = 13.sp)
            }
        }
        Section("Encryption self-test (on this phone, nothing is sent)") {
            Text(crypto, color = Color.White)
            Action("Run") { scope.launch { crypto = selfTest(app.engine) } }
        }
        Section("Server") {
            Text(server, color = Color.White)
            Action("Check relay.relayghostecc.net") {
                scope.launch { server = runCatching { app.relay.health(); "Reachable · HTTPS" }.getOrElse { it.message ?: "Error" } }
            }
        }
        Section("Signed requests (creates and deletes a test mailbox)") {
            Text(mailbox, color = Color.White)
            Action("Run") {
                scope.launch {
                    mailbox = runCatching {
                        val queue = app.relay.createQueue(null)
                        app.relay.delete(queue)
                        "Passed: the server accepted the Ed25519 signatures"
                    }.getOrElse { it.message ?: "Error" }
                }
            }
        }
        Spacer(Modifier.height(24.dp))
    }
}

/** Full PQXDH + ratchet round trip between this identity (RAM copy) and a throw-away local peer. */
private suspend fun selfTest(engine: SignalEngine): String = runCatching {
    engine.loadIdentity() ?: return "Create a Ghost ID first"
    val me = engine.localTestClone()
    val (myID, myKey) = me.loadIdentity()!!
    val lab = SignalEngine(MemoryVault())
    val (labID, labKey) = lab.loadIdentity(create = true)!!
    lab.prepareSession(me.invitationBundle())
    val hello = PrivatePayload.hello(labID, myID, ReplyAddress("https://relay.example.com", "A".repeat(32)))
    val opened = me.decrypt(lab.encrypt(hello), expectedKey = null)
    check(opened.payload.kind == PayloadKind.hello && opened.senderKey.contentEquals(labKey))
    val reply = PrivatePayload.content(myID, labID, Content.Text("ratchet works"))
    val back = lab.decrypt(me.encrypt(reply), expectedKey = myKey)
    check(back.payload.text == "ratchet works")
    check(me.safetyNumber(labID, labKey) == lab.safetyNumber(myID, myKey))
    "Passed: PQXDH, Double Ratchet + SPQR, padding and safety number"
}.getOrElse { "Failed: ${it.message ?: it::class.simpleName}" }

private fun grouped(id: GhostID): String =
    id.rawValue.removePrefix("GHOST-").chunked(4).chunked(4).joinToString("\n") { it.joinToString(" ") }

@Composable
private fun Section(title: String, content: @Composable () -> Unit) {
    Column(
        Modifier.fillMaxWidth().background(GhostColors.panel, RoundedCornerShape(18.dp)).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text(title, color = GhostColors.secondary, fontSize = 13.sp)
        content()
    }
}

@Composable
private fun Action(label: String, onClick: () -> Unit) {
    Button(onClick = onClick, colors = ButtonDefaults.buttonColors(containerColor = GhostColors.blue)) { Text(label) }
}
