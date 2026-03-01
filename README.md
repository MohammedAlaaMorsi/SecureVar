# SecureVar - Secure Variable Library for Android

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Android-green.svg)](https://developer.android.com)
[![Kotlin](https://img.shields.io/badge/Kotlin-1.9+-purple.svg)](https://kotlinlang.org)

**SecureVar** is a production-grade Android security library that provides **re-sealable secure variables** with server-authorized write control. Variables are protected by multiple cryptographic layers and can only be modified with time-limited, one-time-use write keys issued by your backend.

## 🎯 Core Concept

Traditional variable protection approaches use read-only properties or obfuscation. SecureVar takes a different approach:

- **Variables are writable**, but only through cryptographically validated authorization
- **Server controls all writes** via time-limited, one-time-use WriteKeys
- **Multi-layer protection** prevents tampering, replay attacks, and unauthorized modifications
- **Zero-trust architecture** assumes the client is compromised and validates everything

## 🔐 Security Architecture

### Multi-Layer Defense

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                       │
│  ┌────────────┐                      ┌─────────────────┐    │
│  │ SessionMgr │──────────────────────│  SecureVar<T>   │    │
│  └────────────┘                      └─────────────────┘    │
│         │                                    │              │
│         │ authorizedWrite(value, WriteKey)   │              │
│         └────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│              Authorization Layer (WriteKey)                 │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  • Nonce (one-time use) + Timestamp + TTL            │   │
│  │  • HMAC-SHA256 or ECDSA signature                    │   │
│  │  • Bound to: userId, propertyName, scope             │   │
│  │  • Replay prevention via nonce store + MAC           │   │
│  │  • Risk posture enforcement (debugger/root/hook)     │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│              Sealing Layer (SecureVarDelegate)              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  • AES-GCM-128 encryption (per-instance key)         │   │
│  │  • HMAC-SHA256 MAC (propertyName:salt:IV:cipher)     │   │
│  │  • Checksum fallback                                 │   │
│  │  • Obfuscation (split + noise)                       │   │
│  │  • Per-instance salt (prevents cross-instance reuse) │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│              Runtime Protection Layer                       │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  • Stack trace origin verification                   │   │
│  │  • Rate limiting (10 writes/min per variable)        │   │
│  │  • Tamper detection & alerts                         │   │
│  │  • Direct assignment rejection                       │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│              Secret Management Layer                        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  • Per-install random secrets (MAC + ENC)            │   │
│  │  • Google Tink AEAD encryption                       │   │
│  │  • Android Keystore backing                          │   │
│  │  • DataStore with encrypted storage                  │   │
│  │  • Dynamic secret provisioning via SecretProvider    │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Security Features

#### 1. **Server-Issued Authorization (WriteKey)**
- **One-time use**: Nonces are tracked and rejected on replay
- **Time-limited**: TTL enforcement with configurable clock skew tolerance
- **Cryptographically signed**: HMAC-SHA256 or ECDSA (asymmetric preferred)
- **Context-bound**: Signatures include userId, propertyName, and scope
- **Risk-aware**: High-risk environments (debugger/root) require asymmetric signatures

#### 2. **Local Sealing (SecureVarDelegate)**
- **AES-GCM encryption**: 128-bit authentication tag, unique IV per write
- **Per-instance keys**: Derived from `SHA-256(encSecret:propertyName:instanceSalt)`
- **MAC protection**: HMAC-SHA256 over `propertyName:instanceSalt:IV:ciphertext`
- **Tamper detection**: MAC + checksum dual verification
- **Obfuscation**: Split value + random noise for additional depth

#### 3. **Replay Prevention**
- **Nonce store**: Persistent encrypted SharedPreferences
- **Integrity MAC**: HMAC over canonical nonce list (detects store tampering)
- **Automatic cleanup**: Expired nonces pruned on validation

#### 4. **Runtime Protection**
- **Origin enforcement**: Stack trace verification (allowed package prefixes)
- **Rate limiting**: Configurable per-variable write throttling (default: 10/min)
- **Direct assignment rejection**: `setValue()` triggers tamper alert and ignores write

#### 5. **Dynamic Secret Management**
- **Per-install secrets**: Random 32-byte Base64 secrets generated once
- **Encrypted storage**: Google Tink AEAD with AES256-GCM
- **Hardware-backed**: Android Keystore integration
- **DataStore**: Modern async preferences with encryption layer
- **SecretProvider**: Runtime interface for MAC/ENC secret retrieval

## 📦 Installation

### 1. Add the library module to your project

```kotlin
// settings.gradle.kts
include(":securevar")
```

### 2. Add dependency to your app module

```kotlin
// app/build.gradle.kts
dependencies {
    implementation(project(":securevar"))
    
    // Required for encrypted storage
    implementation("androidx.datastore:datastore-preferences:1.1.1")
    implementation("com.google.crypto.tink:tink-android:1.15.0")
}
```

## 🚀 Quick Start

### 1. Initialize SecureVar in your Application class

```kotlin
class SecureVarApplication : Application() {
    private val dataStore by preferencesDataStore(name = "securevar_secrets")
    
    override fun onCreate() {
        super.onCreate()
        
        // Initialize Tink encryption
        EncryptedDataStore.initialize(this)
        
        // Initialize SecureVar with encrypted secret provider
        SecureVarManager.initialize(
            SecureVarConfig(
                action = SecureVarAction.Alert("https://your-backend.com/security/alert"),
                secretProvider = object : SecretProvider {
                    override fun getMacSecret(): String = getOrCreateSecret("mac_secret")
                    override fun getEncSecret(propertyName: String): String = getOrCreateSecret("enc_secret")
                    
                    private fun getOrCreateSecret(key: String): String = runBlocking {
                        val prefKey = stringPreferencesKey(key)
                        val encrypted = dataStore.data.map { it[prefKey] }.first()
                        
                        if (encrypted != null) {
                            // Decrypt existing secret
                            return@runBlocking EncryptedDataStore.decrypt(encrypted, this@SecureVarApplication)
                        }
                        
                        // Generate new secret
                        val bytes = ByteArray(32)
                        java.security.SecureRandom().nextBytes(bytes)
                        val plaintext = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
                        
                        // Encrypt and store
                        val encryptedValue = EncryptedDataStore.encrypt(plaintext, this@SecureVarApplication)
                        dataStore.edit { it[prefKey] = encryptedValue }
                        plaintext
                    }
                },
                writeKeyVerifier = { writeKey ->
                    // Optional: Add custom WriteKey validation
                    WriteKeyValidator.validate(writeKey, this).let { result ->
                        when (result) {
                            is WriteKeyValidator.ValidationResult.Valid -> {
                                WriteKeyValidator.markNonceUsed(writeKey, this)
                                true
                            }
                            else -> false
                        }
                    }
                }
            )
        )
    }
}
```

### 2. Define secure variables in your data class

```kotlin
class SessionManager {
    // Delegate pattern: property backed by SecureVarDelegate
    private val isPremiumUserDelegate = SecureVarDelegate(
        initialValue = false,
        propertyName = "isPremiumUser"
    )
    
    var isPremiumUser: Boolean
        get() = isPremiumUserDelegate.getValue(this, ::isPremiumUser)
        private set(value) {
            // Direct assignment is FORBIDDEN and will be ignored
            isPremiumUserDelegate.setValue(this, ::isPremiumUser, value)
        }

    private val usernameDelegate = SecureVarDelegate(
        initialValue = "",
        propertyName = "username"
    )
    
    var username: String
        get() = usernameDelegate.getValue(this, ::usernameDelegate)
        private set(value) {
            usernameDelegate.setValue(this, ::usernameDelegate, value)
        }

    // Authorized write method - ONLY way to update secure variables
    suspend fun upgradeUserToPremium(userId: String) {
        // 1. Request WriteKey from your backend
        val writeKey = UserApi.requestPremiumUpgrade(userId)
        
        // 2. Validate and apply with authorizedWrite
        isPremiumUserDelegate.authorizedWrite(
            newValue = true,
            key = writeKey
        )
    }

    suspend fun updateUsername(userId: String, newUsername: String) {
        val writeKey = UserApi.requestUsernameChange(userId, newUsername)
        usernameDelegate.authorizedWrite(
            newValue = newUsername,
            key = writeKey
        )
    }
}
```

### 3. Backend: Issue WriteKeys

```kotlin
// Backend API example (Node.js/Express)
app.post('/api/writekey/premium-upgrade', async (req, res) => {
    const { userId } = req.body;
    
    // Validate user is authorized for premium upgrade
    if (!await canUpgradeToPremium(userId)) {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // Generate WriteKey
    const nonce = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();
    const ttlMillis = 5 * 60 * 1000; // 5 minutes
    const propertyName = 'isPremiumUser';
    const scope = 'premium_upgrade';
    
    // Create HMAC signature
    const message = `${nonce}:${timestamp}:${userId}:${propertyName}:${scope}`;
    const hmacSignature = crypto
        .createHmac('sha256', process.env.APP_SECRET_KEY)
        .update(message)
        .digest('base64');
    
    // Optional: Create ECDSA signature for high-security scenarios
    const sign = crypto.createSign('SHA256');
    sign.update(message);
    const asymSignature = sign.sign(privateKey, 'base64');
    
    res.json({
        nonce,
        timestamp,
        signature: hmacSignature,
        asymSignature,
        ttlMillis,
        userId,
        propertyName,
        scope
    });
});
```

### 4. Client: Request and apply WriteKey

```kotlin
object UserApi {
    suspend fun requestPremiumUpgrade(userId: String): WriteKey {
        val response = httpClient.post("https://your-backend.com/api/writekey/premium-upgrade") {
            setBody(json { "userId" to userId })
        }
        val data = response.body<JsonObject>()
        
        return WriteKey(
            nonce = data["nonce"].asString,
            timestamp = data["timestamp"].asLong,
            signature = data["signature"]?.asString,
            asymSignature = data["asymSignature"]?.asString,
            ttlMillis = data["ttlMillis"]?.asLong ?: 300_000L,
            userId = data["userId"]?.asString,
            propertyName = data["propertyName"]?.asString,
            scope = data["scope"]?.asString
        )
    }
}
```

## 🔬 Advanced Usage

### Custom Tamper Detection

```kotlin
SecureVarManager.initialize(
    SecureVarConfig(
        action = SecureVarAction.Logout, // Logout user on tamper detection
        secretProvider = mySecretProvider
    )
)
```

### Risk Posture Configuration

```kotlin
// In WriteKeyValidator, configure risk detection
WriteKeyValidator.apply {
    // Force high-risk mode for testing
    forceHighRisk(true)
    
    // Configure public key for asymmetric verification
    setPublicKey(yourECDSAPublicKey)
}
```

### Rate Limiting Configuration

```kotlin
class SecureVarDelegate<T>(
    initialValue: T,
    propertyName: String,
    private val writeLimitPerMinute: Int = 20 // Custom limit
) : ReadWriteProperty<Any?, T> {
    // ... implementation
}
```

## 🧪 Testing

### Run Unit Tests

```bash
./gradlew :securevar:test
```

### Run Instrumented Tests

```bash
./gradlew :securevar:connectedDebugAndroidTest
```

### Test Coverage

- ✅ WriteKey validation (nonce, timestamp, signature, replay)
- ✅ MAC tamper detection
- ✅ Rate limiting enforcement
- ✅ Origin verification (stack trace)
- ✅ Asymmetric signature verification
- ✅ Nonce store integrity (MAC protection)
- ✅ Instance collision prevention (same propertyName across delegates)

## 📊 Performance Characteristics

| Operation | Time | Notes |
|-----------|------|-------|
| `getValue()` | ~0.5ms | AES-GCM decrypt + MAC verify |
| `authorizedWrite()` | ~2-5ms | WriteKey validation + encryption |
| WriteKey validation | ~1-3ms | HMAC or ECDSA verify + nonce check |
| Nonce store MAC | ~0.5ms | HMAC over canonical nonce list |

## 🛡️ Threat Model

### Protected Against

✅ **Memory inspection**: Variables encrypted at rest  
✅ **Direct assignment**: `setValue()` rejected, triggers alert  
✅ **Replay attacks**: Nonce tracking prevents reuse  
✅ **Tampering**: MAC + checksum detect modifications  
✅ **Time manipulation**: TTL + clock skew enforcement  
✅ **Unauthorized origins**: Stack trace verification  
✅ **Rate abuse**: Per-variable write throttling  
✅ **Cross-instance state injection**: Per-instance salt prevents key reuse  
✅ **Nonce store tampering**: Integrity MAC detects modifications  

### Limitations

⚠️ **Root access**: Root users can bypass AndroidKeyStore protections  
⚠️ **Frida/Xposed**: Runtime hooks can intercept method calls (mitigated by risk posture checks)  
⚠️ **Physical device access**: Attacker with physical access can extract keys from KeyStore  
⚠️ **Stack trace spoofing**: Advanced attackers may forge stack traces (rare)  

## 🔧 Configuration Options

### SecureVarConfig

```kotlin
data class SecureVarConfig(
    val action: SecureVarAction,           // Alert | Logout | Crash
    val secretProvider: SecretProvider? // MAC/ENC secret source
)
```

### SecureVarAction

```kotlin
sealed class SecureVarAction {
    data class Alert(val url: String) : SecureVarAction()  // Send alert to backend
    object Logout : SecureVarAction()                      // Force user logout
    object Crash : SecureVarAction()                       // Crash app immediately
}
```

### SecretProvider

```kotlin
interface SecretProvider {
    fun getMacSecret(): String                    // MAC key for HMAC operations
    fun getEncSecret(propertyName: String): String // Base secret for AES key derivation
}
```

## 📚 Documentation

- [Security Architecture](docs/SECURITY.md) - Detailed threat model and cryptographic design
- [API Reference](docs/API.md) - Complete API documentation
- [Migration Guide](docs/MIGRATION.md) - Upgrading from previous versions
- [Best Practices](docs/BEST_PRACTICES.md) - Security recommendations

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- AndroidX Security Crypto for encrypted storage
- Kotlin coroutines for async operations
- JUnit and AndroidX Test for testing framework

## 🔗 Links

- [GitHub Repository](https://github.com/mohammedalaamorsi/SecureVar)
- [Issue Tracker](https://github.com/mohammedalaamorsi/SecureVar/issues)
- [Discussions](https://github.com/mohammedalaamorsi/SecureVar/discussions)

---

**Built with ❤️ for Android security**
