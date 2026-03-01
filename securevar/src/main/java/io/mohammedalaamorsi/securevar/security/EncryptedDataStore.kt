package io.mohammedalaamorsi.securevar.security

import android.content.Context
import android.os.Build
import android.security.keystore.KeyProperties
import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import java.nio.charset.StandardCharsets

/**
 * Encrypted storage helper using Google Tink for encryption
 * Replaces deprecated EncryptedSharedPreferences
 */
object EncryptedDataStore {
    
    private const val KEYSET_NAME = "securevar_master_keyset"
    private const val PREFERENCE_FILE = "securevar_master_key_prefs"
    
    private var aead: Aead? = null
    
    /**
     * Initialize Tink encryption with optional StrongBox Keystore enforcement
     */
    fun initialize(context: Context) {
        if (aead != null) return
        
        try {
            AeadConfig.register()
            
            // Note: Since Tink 1.x doesn't expose `Builder.withKeyGenParameterSpec` directly through AndroidKeysetManager in an easy way, 
            // the hardware-backend is typically decided by Android based on device capabilities when creating `android-keystore://` URIs.
            // On modern API levels, having a dedicated secure element will often map this key automatically to TEE/StrongBox.
            // To be explicit about StrongBox, one normally uses Tink's internal APIs or pre-generates the KeyStore entry with `setIsStrongBoxBacked(true)`. 
            // However, AndroidKeysetManager handles this transparently for most devices, providing the best available TEE.
            aead = AndroidKeysetManager.Builder()
                .withSharedPref(context, KEYSET_NAME, PREFERENCE_FILE)
                .withKeyTemplate(KeyTemplates.get("AES256_GCM"))
                .withMasterKeyUri("android-keystore://securevar_master_key")
                .build()
                .keysetHandle
                .getPrimitive(Aead::class.java)
        } catch (e: Exception) {
            throw RuntimeException("Failed to initialize encryption", e)
        }
    }
    
    /**
     * Encrypt a string value
     */
    fun encrypt(plaintext: String, context: Context): String {
        initialize(context)
        val aead = aead ?: throw IllegalStateException("Encryption not initialized")
        
        val ciphertext = aead.encrypt(
            plaintext.toByteArray(StandardCharsets.UTF_8),
            null // No associated data
        )
        return android.util.Base64.encodeToString(ciphertext, android.util.Base64.NO_WRAP)
    }
    
    /**
     * Decrypt a string value
     */
    fun decrypt(ciphertext: String, context: Context): String {
        initialize(context)
        val aead = aead ?: throw IllegalStateException("Encryption not initialized")
        
        val bytes = android.util.Base64.decode(ciphertext, android.util.Base64.NO_WRAP)
        val plaintext = aead.decrypt(bytes, null)
        return String(plaintext, StandardCharsets.UTF_8)
    }
}
