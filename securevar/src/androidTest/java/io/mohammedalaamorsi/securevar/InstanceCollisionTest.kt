package io.mohammedalaamorsi.securevar

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Test to verify that two SecureVarDelegate instances with the same propertyName
 * produce different encryption keys and MACs due to per-instance salt.
 */
@RunWith(AndroidJUnit4::class)
class InstanceCollisionTest {

    @Before
    fun setup() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        // Initialize SecureVarManager with test configuration
        SecureVarManager.initialize(
            SecureVarConfig(
                action = SecureVarAction.Alert("https://test.example.com"),
                secretProvider = object : SecretProvider {
                    override fun getMacSecret(): String = "test-mac-secret-collision"
                    override fun getEncSecret(propertyName: String): String = "test-enc-secret-collision"
                }
            )
        )
    }

    @Test
    fun testTwoDelegatesWithSamePropertyName_ProduceDifferentMACs() {
        // Create two delegates with identical propertyName
        val delegate1 = SecureVarDelegate(initialValue = "value1", propertyName = "testProperty")
        val delegate2 = SecureVarDelegate(initialValue = "value2", propertyName = "testProperty")

        // Access their internal sealed states via reflection
        val state1 = getStateViaReflection(delegate1) as SealedState.Sealed<*>
        val state2 = getStateViaReflection(delegate2) as SealedState.Sealed<*>

        // Verify MACs are different (because instanceSalt differs)
        assertNotEquals(
            "Two delegates with same propertyName should produce different MACs due to instanceSalt",
            state1.mac,
            state2.mac
        )

        println("Delegate1 MAC: ${state1.mac}")
        println("Delegate2 MAC: ${state2.mac}")
    }

    @Test
    fun testTwoDelegatesWithSamePropertyName_CannotShareSealedState() {
        // Create two delegates with identical propertyName and initial values
        val delegate1 = SecureVarDelegate(initialValue = "sharedValue", propertyName = "testProperty")
        val delegate2 = SecureVarDelegate(initialValue = "sharedValue", propertyName = "testProperty")

        // Get the sealed state from delegate1
        val state1 = getStateViaReflection(delegate1) as SealedState.Sealed<String>

        // Attempt to inject delegate1's state into delegate2 via reflection
        setStateViaReflection(delegate2, state1)

        // Now try to read from delegate2 - it should detect tampering because the MAC won't match
        // (delegate2 has a different instanceSalt)
        var tamperDetected = false
        SecureVarManager.initialize(
            SecureVarConfig(
                action = SecureVarAction.Alert("https://test.example.com"),
                secretProvider = object : SecretProvider {
                    override fun getMacSecret(): String = "test-mac-secret-collision"
                    override fun getEncSecret(propertyName: String): String = "test-enc-secret-collision"
                }
            )
        )

        // Trigger getValue which will check MAC
        val result = delegate2.getValue(null, MockProperty("testProperty"))

        // The tamper will be detected internally and logged
        // We can't easily intercept it in the test, but we verify the result is a default value
        // because when MAC fails, the delegate returns a safe default

        println("Result after injected state (should be default/empty): '$result'")
        
        // Verify result is empty string (default for String type when tamper detected)
        assertEquals(
            "Delegate2 should return default value when using delegate1's sealed state (MAC mismatch)",
            "",
            result
        )
    }

    @Test
    fun testSameDelegate_MACRemainsConsistent() {
        // Create a delegate
        val delegate = SecureVarDelegate(initialValue = "value", propertyName = "testProperty")

        // Get its MAC
        val state1 = getStateViaReflection(delegate) as SealedState.Sealed<*>
        val mac1 = state1.mac

        // Read the value (this internally validates MAC)
        val value = delegate.getValue(null, MockProperty("testProperty"))

        // Get MAC again
        val state2 = getStateViaReflection(delegate) as SealedState.Sealed<*>
        val mac2 = state2.mac

        // MAC should remain the same for the same delegate instance
        assertEquals(
            "Same delegate should produce consistent MAC across reads",
            mac1,
            mac2
        )

        assertEquals("value", value)
    }

    // Helper to access private state field via reflection
    private fun getStateViaReflection(delegate: SecureVarDelegate<*>): SealedState<*> {
        val field = SecureVarDelegate::class.java.getDeclaredField("state")
        field.isAccessible = true
        return field.get(delegate) as SealedState<*>
    }

    // Helper to set private state field via reflection
    private fun setStateViaReflection(delegate: SecureVarDelegate<*>, state: SealedState<*>) {
        val field = SecureVarDelegate::class.java.getDeclaredField("state")
        field.isAccessible = true
        field.set(delegate, state)
    }

    // Mock property for testing
    private class MockProperty(private val propName: String) : kotlin.reflect.KProperty<String> {
        override val name: String get() = propName
        override val annotations: List<Annotation> get() = emptyList()
        override val isAbstract: Boolean get() = false
        override val isConst: Boolean get() = false
        override val isFinal: Boolean get() = false
        override val isLateinit: Boolean get() = false
        override val isOpen: Boolean get() = false
        override val isSuspend: Boolean get() = false
        override val returnType: kotlin.reflect.KType
            get() = throw NotImplementedError()
        override val typeParameters: List<kotlin.reflect.KTypeParameter>
            get() = emptyList()
        override val visibility: kotlin.reflect.KVisibility?
            get() = null
        override fun call(vararg args: Any?): String = throw NotImplementedError()
        override fun callBy(args: Map<kotlin.reflect.KParameter, Any?>): String = throw NotImplementedError()
        override val getter: kotlin.reflect.KProperty.Getter<String>
            get() = throw NotImplementedError()
        override val parameters: List<kotlin.reflect.KParameter>
            get() = emptyList()
    }
}
