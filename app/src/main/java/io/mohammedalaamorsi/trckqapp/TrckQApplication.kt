package io.mohammedalaamorsi.trckqapp

import android.app.Application
import io.mohammedalaamorsi.trckqapp.di.AppContainer
import io.mohammedalaamorsi.trckq.TrckqManager
import io.mohammedalaamorsi.trckq.TrckqConfig
import io.mohammedalaamorsi.trckq.TrckqAction
import io.mohammedalaamorsi.trckq.SecretProvider
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import io.mohammedalaamorsi.trckqapp.security.WriteKeyValidator
import io.mohammedalaamorsi.trckqapp.security.EncryptedDataStore
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.runBlocking

private val Application.dataStore by preferencesDataStore(name = "trckq_secrets")

/**
 * Application class for dependency injection setup
 */
class TrckQApplication : Application() {
    
    lateinit var appContainer: AppContainer
        private set
    
    override fun onCreate() {
        super.onCreate()
        
        // Initialize Tink encryption
        EncryptedDataStore.initialize(this)
        
        // Initialize dependency injection container
        appContainer = AppContainer(applicationContext)
        
        // Initialize TrckqManager with dynamic secret provider
        TrckqManager.initialize(
            TrckqConfig(
                action = TrckqAction.Alert(url = "https://example.com/security/alert"),
                secretProvider = object : SecretProvider {
                    override fun getMacSecret(): String = getOrCreate("mac_secret")
                    override fun getEncSecret(propertyName: String): String = getOrCreate("enc_secret")
                    
                    private fun getOrCreate(key: String): String = runBlocking {
                        val prefKey = stringPreferencesKey(key)
                        val encryptedValue = dataStore.data.map { it[prefKey] }.first()
                        
                        if (encryptedValue != null) {
                            // Decrypt existing value
                            return@runBlocking EncryptedDataStore.decrypt(encryptedValue, this@TrckQApplication)
                        }
                        
                        // Generate new secret
                        val bytes = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
                        val plaintext = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
                        
                        // Encrypt and store
                        val encrypted = EncryptedDataStore.encrypt(plaintext, this@TrckQApplication)
                        dataStore.edit { preferences ->
                            preferences[prefKey] = encrypted
                        }
                        plaintext
                    }
                },
                writeKeyVerifier = { key ->
                    when (val result = WriteKeyValidator.validate(key, this@TrckQApplication)) {
                        is WriteKeyValidator.ValidationResult.Valid -> {
                            println("✅ WriteKey VALID: nonce=${key.nonce}, userId=${key.userId}, propertyName=${key.propertyName}")
                            // Mark nonce as used after validation passes
                            WriteKeyValidator.markNonceUsed(key, this@TrckQApplication)
                            true
                        }
                        is WriteKeyValidator.ValidationResult.InvalidFormat -> {
                            println("❌ WriteKey INVALID FORMAT: ${result.reason}, nonce=${key.nonce}")
                            false
                        }
                        is WriteKeyValidator.ValidationResult.Expired -> {
                            println("❌ WriteKey EXPIRED: age=${result.ageMillis}ms, nonce=${key.nonce}")
                            false
                        }
                        is WriteKeyValidator.ValidationResult.Replay -> {
                            println("❌ WriteKey REPLAY: nonce=${result.nonce}")
                            false
                        }
                        is WriteKeyValidator.ValidationResult.SignatureMismatch -> {
                            println("❌ WriteKey SIGNATURE MISMATCH: expected=${result.expected?.take(20)}..., actual=${result.actual?.take(20)}..., nonce=${key.nonce}, userId=${key.userId}, propertyName=${key.propertyName}, scope=${key.scope}")
                            false
                        }
                        is WriteKeyValidator.ValidationResult.ClockSkewExceeded -> {
                            println("❌ WriteKey CLOCK SKEW: skew=${result.skewMillis}ms, nonce=${key.nonce}")
                            false
                        }
                        is WriteKeyValidator.ValidationResult.AsymSignatureMismatch -> {
                            println("❌ WriteKey ASYM SIGNATURE FAIL: ${result.reason}, nonce=${key.nonce}")
                            false
                        }
                        is WriteKeyValidator.ValidationResult.NonceStoreTampered -> {
                            println("❌ WriteKey NONCE STORE TAMPERED: nonce=${key.nonce}")
                            false
                        }
                    }
                }
            )
        )
    }
}
