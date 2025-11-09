package io.mohammedalaamorsi.trckqapp.security

import io.mohammedalaamorsi.trckq.SecureVarDelegate
import io.mohammedalaamorsi.trckq.WriteKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SecureVarDelegateUnitTest {

    @Test
    fun macTamperDetected() {
        val delegate = SecureVarDelegate(initialValue = 42, propertyName = "testInt")
        // Access value to ensure sealed state
        val original = delegate.getValue(null, DummyProperty("dummy"))
        // Reflectively tamper with internal mac (simulate attacker)
        val field = SecureVarDelegate::class.java.getDeclaredField("state")
        field.isAccessible = true
        val sealed = field.get(delegate)
        val sealedClass = sealed::class.java
        val macField = sealedClass.getDeclaredField("mac")
        macField.isAccessible = true
        macField.set(sealed, "badmac")
        val retrieved = delegate.getValue(null, DummyProperty("dummy"))
        // Should not return the original (will fallback to default)
        assertTrue(retrieved != original)
    }

    @Test
    fun authorizedWriteChangesValue() {
        val delegate = SecureVarDelegate(initialValue = false, propertyName = "flag")
        val key = WriteKey.generate(secretKey = "app-secret-key", scope = "flag")
        val before = delegate.getValue(null, DummyProperty("dummy"))
        delegate.authorizedWrite(true, key)
        val after = delegate.getValue(null, DummyProperty("dummy"))
        assertTrue(before is Boolean && after is Boolean)
        assertEquals(true, after)
    }

    // Minimal KProperty stub for direct delegate calls
    private class DummyProperty(private val n: String) : kotlin.reflect.KProperty<Any?> {
        override val name: String get() = n
        override val annotations: List<Annotation> get() = emptyList()
        override val isLateinit: Boolean get() = false
        override val isConst: Boolean get() = false
        override val isAbstract: Boolean get() = false
        override val parameters: List<kotlin.reflect.KParameter> get() = emptyList()
        override fun call(vararg args: Any?): Any? = null
        override fun callBy(args: Map<kotlin.reflect.KParameter, Any?>): Any? = null
        override val getter: kotlin.reflect.KProperty.Getter<Any?> get() = throw UnsupportedOperationException()
        override val returnType: kotlin.reflect.KType get() = kotlin.reflect.typeOf<Any?>()
        override val typeParameters: List<kotlin.reflect.KTypeParameter> get() = emptyList()
        override val visibility: kotlin.reflect.KVisibility? get() = kotlin.reflect.KVisibility.PUBLIC
        override val isSuspend: Boolean get() = false
    }
}
