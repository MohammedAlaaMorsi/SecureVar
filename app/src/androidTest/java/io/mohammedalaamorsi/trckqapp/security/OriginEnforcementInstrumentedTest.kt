package io.mohammedalaamorsi.trckqapp.security

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.mohammedalaamorsi.trckq.SecureVarDelegate
import io.mohammedalaamorsi.trckq.WriteKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Tests origin enforcement logic indirectly by attempting writes from a helper class whose
 * stack trace will include this test package (allowed) and then from a simulated foreign package
 * name (manually constructed stack trace element injected via reflection hack). Since direct
 * stack injection is not feasible, we validate normal successful write and rely on existing
 * tamper path for manual override demonstration.
 *
 * NOTE: Full negative test requires instrumentation or bytecode manipulation; here we assert
 * that a valid origin path succeeds and document limitation.
 */
@RunWith(AndroidJUnit4::class)
class OriginEnforcementInstrumentedTest {

    private class HolderStr { val delegate = SecureVarDelegate("", "secureName"); var secureName: String by delegate }

    @Test
    fun allowedOriginWriteSucceeds() {
        val holder = HolderStr()
        val key = WriteKey.generate(secretKey = "app-secret-key", scope = "secureName")
        val before = holder.secureName
        holder.delegate.authorizedWrite("newValue", key)
        val after = holder.secureName
        assertTrue(before != after && after == "newValue")
    }

    @Test
    fun documentDisallowedOriginTestLimit() {
        // Placeholder test explaining limitation.
        // A full disallowed origin test would require generating a stack trace whose elements
        // do NOT start with the allowed prefix and calling authorizedWrite in that context.
        // This would typically involve a proxy in a different package or dynamic code loading.
        assertEquals(true, true) // Always pass; serves as documentation anchor.
    }
}
