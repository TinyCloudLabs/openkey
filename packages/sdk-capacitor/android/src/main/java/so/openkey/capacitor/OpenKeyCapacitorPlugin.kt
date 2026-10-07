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

@CapacitorPlugin(name = "OpenKeyCapacitor")
class OpenKeyCapacitorPlugin : Plugin() {
    private var pending: PluginCall? = null
    private var launched = false
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
        if (url == null || !url.startsWith("https://") || scheme.isNullOrBlank()) {
            call.reject("Invalid authorization URL or callback scheme", "INVALID_REQUEST")
            return
        }
        if (pending != null) { call.reject("An authorization session is already open", "UNAVAILABLE"); return }
        pending = call
        launched = true
        try {
            CustomTabsIntent.Builder().build().launchUrl(activity, android.net.Uri.parse(url))
        } catch (_: Exception) {
            pending = null
            launched = false
            call.reject("Could not open browser", "UNAVAILABLE")
        }
    }

    override fun handleOnNewIntent(intent: Intent) {
        super.handleOnNewIntent(intent)
        val url = intent.data ?: return
        val call = pending ?: return
        cancel?.let(handler::removeCallbacks)
        cancel = null
        pending = null
        launched = false
        call.resolve(JSObject().put("url", url.toString()))
    }

    override fun handleOnResume() {
        super.handleOnResume()
        if (!launched || pending == null) return
        // A redirect may arrive just after the app resumes. Give it a short grace period.
        val task = Runnable {
            pending?.reject("The browser was closed", "USER_CANCELLED")
            pending = null
            launched = false
            cancel = null
        }
        cancel?.let(handler::removeCallbacks)
        cancel = task
        handler.postDelayed(task, 900)
    }

    @PluginMethod fun secureStoreGet(call: PluginCall) {
        val key = call.getString("key") ?: run { call.reject("Missing key", "INVALID_REQUEST"); return }
        try { call.resolve(JSObject().put("value", store.get(key))) }
        catch (_: Exception) { call.reject("Secure store read failed", "SERVER") }
    }
    @PluginMethod fun secureStoreSet(call: PluginCall) {
        val key = call.getString("key") ?: run { call.reject("Missing key", "INVALID_REQUEST"); return }
        val value = call.getString("value") ?: run { call.reject("Missing value", "INVALID_REQUEST"); return }
        try { store.set(key, value); call.resolve() }
        catch (_: Exception) { call.reject("Secure store write failed", "SERVER") }
    }
    @PluginMethod fun secureStoreRemove(call: PluginCall) {
        val key = call.getString("key") ?: run { call.reject("Missing key", "INVALID_REQUEST"); return }
        try { store.remove(key); call.resolve() }
        catch (_: Exception) { call.reject("Secure store delete failed", "SERVER") }
    }
}
