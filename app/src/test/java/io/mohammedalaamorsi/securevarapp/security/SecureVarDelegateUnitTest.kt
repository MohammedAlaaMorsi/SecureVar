package io.mohammedalaamorsi.securevarapp.security

import io.mohammedalaamorsi.securevar.SecureVarDelegate
import io.mohammedalaamorsi.securevar.WriteKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import kotlin.reflect.KProperty
import org.mockito.kotlin.mock

@RunWith(RobolectricTestRunner::class)
@Config(manifest=Config.NONE, sdk=[34])
class SecureVarDelegateUnitTest {

    @Test
    fun macTamperDetected() {
        val delegate = SecureVarDelegate(initialValue = 42, propertyName = "testInt")
        // Access value to ensure sealed state
        val mockProp = mock<KProperty<Any?>>()
        val original = delegate.getValue(null, mockProp)
        // Reflectively tamper with internal mac (simulate attacker)
        val field = SecureVarDelegate::class.java.getDeclaredField("state")
        field.isAccessible = true
        val sealed = field.get(delegate)
        val sealedClass = sealed::class.java
        val macField = sealedClass.getDeclaredField("mac")
        macField.isAccessible = true
        macField.set(sealed, "badmac")
        val retrieved = delegate.getValue(null, mockProp)
        // Should not return the original (will fallback to default)
        assertTrue(retrieved != original)
    }

    @Test
    fun authorizedWriteChangesValue() {
        val delegate = SecureVarDelegate(initialValue = false, propertyName = "flag")
        val key = WriteKey.generate(secretKey = "your-app-secret-key-from-backend", scope = "flag")
        
        val mockProp = mock<KProperty<Any?>>()
        val before = delegate.getValue(null, mockProp)
        
        delegate.authorizedWrite(true, key)
        
        val after = delegate.getValue(null, mockProp)
        assertTrue(before is Boolean && after is Boolean)
        assertEquals(true, after)
    }
}
