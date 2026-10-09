package so.openkey.capacitor

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class OpenKeyStoreResultTest {
    @Test fun missingKeyIsAnExplicitJsonNull() {
        val result = secureStoreResult(null)
        assertTrue(result.has("value"))
        assertTrue(result.isNull("value"))
        assertEquals(JSONObject.NULL, result.get("value"))
    }
}
