package io.mohammedalaamorsi.trckqapp.security

import android.content.Context
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
    
    private const val KEYSET_NAME = "trckq_master_keyset"
    private const val PREFERENCE_FILE = "trckq_master_key_prefs"
    
    private var aead: Aead? = null
    
    /**
     * Initialize Tink encryption
     */
    fun initialize(context: Context) {
        if (aead != null) return
        
        try {
            AeadConfig.register()
            
            aead = AndroidKeysetManager.Builder()
                .withSharedPref(context, KEYSET_NAME, PREFERENCE_FILE)
                .withKeyTemplate(KeyTemplates.get("AES256_GCM"))
                .withMasterKeyUri("android-keystore://trckq_master_key")
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
