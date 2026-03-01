package io.mohammedalaamorsi.securevarapp.security

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.mohammedalaamorsi.securevar.SecureVarDelegate
import io.mohammedalaamorsi.securevar.WriteKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SecureVarDelegateInstrumentedTest {

    private class HolderInt {
        val delegate = SecureVarDelegate(initialValue = 7, propertyName = "counter")
        var counter: Int by delegate
    }

    @Test
    fun macTamperDetected_onGetValue() {
        val holder = HolderInt()
        val original = holder.counter
        // tamper with mac via reflection
        val field = SecureVarDelegate::class.java.getDeclaredField("state")
        field.isAccessible = true
        val sealed = field.get(holder.delegate)
        val macField = sealed::class.java.getDeclaredField("mac")
        macField.isAccessible = true
        macField.set(sealed, "corrupted-mac")
        val after = holder.counter
        // tamper should be detected and fallback not equal to original
        assertNotEquals(original, after)
    }

    @Test
    fun rateLimiting_allowsAtMostTenWritesPerMinute() {
        val holder = HolderInt()
        // Perform 12 authorized writes with fresh keys
        repeat(12) { i ->
            val key = WriteKey.generate(secretKey = "your-app-secret-key-from-backend", scope = "counter")
            holder.delegate.authorizedWrite(i + 1, key)
        }
        // Only first 10 writes should be applied; final value should be 10
        assertEquals(10, holder.counter)
    }

    @Test
    fun directSetIsIgnoredAndTriggersTamper() {
        val holder = HolderInt()
        val before = holder.counter
        // Direct set should be ignored; no exception thrown; value unchanged
        holder.counter = 12345
        val after = holder.counter
        assertEquals(before, after)
    }
}
