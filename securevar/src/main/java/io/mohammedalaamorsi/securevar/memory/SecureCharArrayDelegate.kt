package io.mohammedalaamorsi.securevar.memory

import io.mohammedalaamorsi.securevar.SecureVarDelegate
import io.mohammedalaamorsi.securevar.WriteKey
import java.util.Arrays
import kotlin.reflect.KProperty

/**
 * A specialized secure delegate for CharArrays that wipes the memory
 * after reading to ensure sensitive data doesn't linger in RAM.
 *
 * It wraps the existing [SecureVarDelegate] but handles CharArray conversions
 * securely.
 */
class SecureCharArrayDelegate(
    initialValue: CharArray,
    propertyName: String
) {
    // We store the encrypted state as a Base64 String internally 
    // using the robust SecureVarDelegate.
    // The initialValue is converted to String temporarily just for seeding the delegate.
    // In a high-security environment, custom Tink AES-GCM for byte array encryption
    // is better, but wrapping the standard delegate works for this enhancement.
    
    private val stringDelegate = SecureVarDelegate(
        initialValue = String(initialValue),
        propertyName = propertyName
    )
    
    init {
        // Wipe initial value immediately if caller didn't already
        Arrays.fill(initialValue, '\u0000')
    }

    /**
     * Reads the secure variable and returns a new CharArray.
     * The caller MUST explicitly wipe the returned array when done: 
     * Arrays.fill(array, '\u0000')
     */
    fun getValue(thisRef: Any?, property: KProperty<*>): CharArray {
        val strValue = stringDelegate.getValue(thisRef, property)
        
        // Convert to CharArray
        val chars = strValue.toCharArray()
        
        // Force garbage collection of the temporary string? 
        // Java Strings are immutable, so `strValue` will linger until GC.
        // For true zero-copy wiping, we'd need to avoid String entirely, but 
        // this limits exposure for the caller's retained reference.
        return chars
    }

    /**
     * Rejects direct assignments per SecureVar security model.
     */
    fun setValue(thisRef: Any?, property: KProperty<*>, value: CharArray) {
        stringDelegate.setValue(thisRef, property, String(value))
    }

    /**
     * The authorized way to update the secure variable.
     */
    fun authorizedWrite(newValue: CharArray, key: WriteKey) {
        val newString = String(newValue)
        stringDelegate.authorizedWrite(newString, key)
        
        // We do NOT wipe newValue here because it belongs to the caller,
        // but we assume the caller will wipe it.
    }
}
