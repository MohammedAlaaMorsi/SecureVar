package io.mohammedalaamorsi.trckqapp

import android.app.Application
import io.mohammedalaamorsi.trckqapp.di.AppContainer
import io.mohammedalaamorsi.trckq.TrckqManager
import io.mohammedalaamorsi.trckq.TrckqConfig
import io.mohammedalaamorsi.trckq.TrckqAction
import io.mohammedalaamorsi.trckq.SecretProvider
import io.mohammedalaamorsi.trckq.WriteKeyVerifier
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import io.mohammedalaamorsi.trckqapp.security.WriteKeyValidator

/**
 * Application class for dependency injection setup
 */
class TrckQApplication : Application() {
    
    lateinit var appContainer: AppContainer
        private set
    
    override fun onCreate() {
        super.onCreate()
        
        // Initialize dependency injection container
    appContainer = AppContainer(applicationContext)
        
        // Initialize TrckqManager with dynamic secret provider
        TrckqManager.initialize(
            TrckqConfig(
                action = TrckqAction.Alert(url = "https://example.com/security/alert"),
                secretProvider = object : SecretProvider {
                    private val prefs by lazy {
                        val masterKey = MasterKey.Builder(this@TrckQApplication)
                            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                            .build()
                        EncryptedSharedPreferences.create(
                            this@TrckQApplication,
                            "trckq_secrets",
                            masterKey,
                            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
                        )
                    }
                    override fun getMacSecret(): String = getOrCreate("mac_secret")
                    override fun getEncSecret(propertyName: String): String = getOrCreate("enc_secret")
                    private fun getOrCreate(key: String): String {
                        val existing = prefs.getString(key, null)
                        if (existing != null) return existing
                        val bytes = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
                        val b64 = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
                        prefs.edit().putString(key, b64).apply()
                        return b64
                    }
                },
                writeKeyVerifier = WriteKeyVerifier { key ->
                    val result = WriteKeyValidator.validate(key, this@TrckQApplication)
                    when (result) {
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
