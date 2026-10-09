package so.openkey.capacitor

import android.app.Activity
import android.content.Intent
import android.os.Bundle

/** Returns a Custom Tab redirect to the existing Capacitor activity. */
class OpenKeyRedirectActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val launch = packageManager.getLaunchIntentForPackage(packageName)
        if (launch != null && intent?.data != null) {
            launch.action = Intent.ACTION_VIEW
            launch.data = intent.data
            launch.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            startActivity(launch)
        }
        finish()
    }
}
