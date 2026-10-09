package so.openkey.capacitor

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OpenKeyRedirectTest {
    private val callback = "xyz.tinycloud.exo://openkey/callback"

    @Test fun acceptsOnlyThePendingCallbackAndState() {
        assertTrue(matchesOpenKeyRedirect("$callback?code=abc&state=expected", callback, "expected"))
        assertTrue(matchesOpenKeyRedirect("$callback#code=abc&state=expected", callback, "expected"))
        assertFalse(matchesOpenKeyRedirect("xyz.tinycloud.exo://oauth/google?state=expected", callback, "expected"))
        assertFalse(matchesOpenKeyRedirect("xyz.tinycloud.exo://openkey/other?state=expected", callback, "expected"))
        assertFalse(matchesOpenKeyRedirect("other://openkey/callback?state=expected", callback, "expected"))
        assertFalse(matchesOpenKeyRedirect("xyz.tinycloud.exo://openkey:123/callback?state=expected", callback, "expected"))
        assertFalse(matchesOpenKeyRedirect("$callback?code=abc&state=unknown", callback, "expected"))
        assertFalse(matchesOpenKeyRedirect("$callback?code=abc&state=expected&state=expected", callback, "expected"))
        assertFalse(matchesOpenKeyRedirect("$callback?code=abc", callback, "expected"))
    }
}
