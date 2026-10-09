package so.openkey.capacitor

import android.content.Intent
import android.os.Handler
import android.os.Looper
import androidx.browser.customtabs.CustomTabsIntent
import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.CapacitorPlugin
import org.json.JSONObject
import java.net.URI
import java.net.URLDecoder

internal fun matchesOpenKeyRedirect(actual: String, expected: String, state: String): Boolean = try {
    val received = URI(actual)
    val callback = URI(expected)
    val responseParameters = received.rawQuery ?: received.rawFragment ?: ""
    val responseStates = responseParameters.split('&').mapNotNull { part ->
        val key = part.substringBefore('=')
        if (key == "state") URLDecoder.decode(part.substringAfter('=', ""), "UTF-8") else null
    }
    received.scheme.equals(callback.scheme, ignoreCase = true) &&
        received.host.equals(callback.host, ignoreCase = true) &&
        received.port == callback.port && received.path == callback.path && responseStates == listOf(state)
} catch (_: Exception) { false }

internal fun secureStoreResult(value: String?): JSObject = JSObject().put("value", value ?: JSONObject.NULL)

@CapacitorPlugin(name = "OpenKeyCapacitor")
class OpenKeyCapacitorPlugin : Plugin() {
    private var pending: PluginCall? = null
    private var launched = false
    private var callbackUrl: String? = null
    private var expectedState: String? = null
    private val handler = Handler(Looper.getMainLooper())
    private var cancel: Runnable? = null
    private lateinit var store: SecureStore

    override fun load() {
        store = SecureStore(context)
    }

    @PluginMethod
    fun openAuthSession(call: PluginCall) {
        val url = call.getString("url")
        val scheme = call.getString("callbackScheme")
        val callback = call.getString("callbackUrl")
        val state = call.getString("expectedState")
        if (url == null || !url.startsWith("https://") || scheme.isNullOrBlank() || scheme.equals("https", ignoreCase = true) || callback.isNullOrBlank() || state.isNullOrBlank() ||
            !android.net.Uri.parse(callback).scheme.equals(scheme, ignoreCase = true) || android.net.Uri.parse(callback).host.isNullOrBlank() ||
            android.net.Uri.parse(callback).path != "/callback") {
            call.reject("Invalid authorization URL or callback scheme", "INVALID_REQUEST")
            return
        }
        if (pending != null) { call.reject("An authorization session is already open", "ALREADY_IN_PROGRESS"); return }
        pending = call
        callbackUrl = callback
        expectedState = state
        launched = true
        try {
            CustomTabsIntent.Builder().build().launchUrl(activity, android.net.Uri.parse(url))
        } catch (_: Exception) {
            pending = null
            launched = false
            callbackUrl = null
            expectedState = null
            call.reject("Could not open browser", "UNAVAILABLE")
        }
    }

    override fun handleOnNewIntent(intent: Intent) {
        super.handleOnNewIntent(intent)
        val url = intent.data ?: return
        val call = pending ?: return
        val expected = callbackUrl ?: return
        val state = expectedState ?: return
        if (intent.action != Intent.ACTION_VIEW || !matchesOpenKeyRedirect(url.toString(), expected, state)) {
            // A foreign intent can close the Custom Tab. Keep the flow pending
            // for the redirect grace period, then settle it as cancellation.
            scheduleCancellation()
            return
        }
        cancel?.let(handler::removeCallbacks)
        cancel = null
        pending = null
        launched = false
        callbackUrl = null
        expectedState = null
        call.resolve(JSObject().put("url", url.toString()))
    }

    override fun handleOnResume() {
        super.handleOnResume()
        scheduleCancellation()
    }

    private fun scheduleCancellation() {
        if (!launched || pending == null) return
        // A redirect may arrive just after the app resumes. Give it a short grace period.
        val task = Runnable {
            pending?.reject("The browser was closed", "USER_CANCELLED")
            pending = null
            launched = false
            callbackUrl = null
            expectedState = null
            cancel = null
        }
        cancel?.let(handler::removeCallbacks)
        cancel = task
        handler.postDelayed(task, 900)
    }

    @PluginMethod fun secureStoreGet(call: PluginCall) {
        val key = call.getString("key") ?: run { call.reject("Missing key", "INVALID_REQUEST"); return }
        try { call.resolve(secureStoreResult(store.get(key))) }
        catch (error: Exception) { call.reject("Secure store read failed (${error.javaClass.simpleName})", "STORAGE") }
    }
    @PluginMethod fun secureStoreSet(call: PluginCall) {
        val key = call.getString("key") ?: run { call.reject("Missing key", "INVALID_REQUEST"); return }
        val value = call.getString("value") ?: run { call.reject("Missing value", "INVALID_REQUEST"); return }
        try { store.set(key, value); call.resolve() }
        catch (error: Exception) { call.reject("Secure store write failed (${error.javaClass.simpleName})", "STORAGE") }
    }
    @PluginMethod fun secureStoreRemove(call: PluginCall) {
        val key = call.getString("key") ?: run { call.reject("Missing key", "INVALID_REQUEST"); return }
        try { store.remove(key); call.resolve() }
        catch (error: Exception) { call.reject("Secure store delete failed (${error.javaClass.simpleName})", "STORAGE") }
    }
}
