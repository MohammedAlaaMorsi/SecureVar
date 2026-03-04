# SecureVar - Secure Variable Library for Android

[![Maven Central](https://img.shields.io/maven-central/v/io.github.mohammedalaamorsi/securevar.svg)](https://central.sonatype.com/artifact/io.github.mohammedalaamorsi/securevar)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Android-green.svg)](https://developer.android.com)
[![API](https://img.shields.io/badge/API-24%2B-brightgreen.svg)](https://developer.android.com/about/versions/nougat)
[![Kotlin](https://img.shields.io/badge/Kotlin-2.2+-purple.svg)](https://kotlinlang.org)

**SecureVar** is a production-grade Android security library that provides **re-sealable secure variables** with server-authorized write control. Variables are protected by multiple cryptographic layers and can only be modified with time-limited, one-time-use write keys issued by your backend.

## 📦 Installation

Add the Maven Central dependency to your app's `build.gradle.kts`:

```kotlin
// app/build.gradle.kts
dependencies {
    implementation("io.github.mohammedalaamorsi:securevar:0.0.3")
}
```

## 🎯 Core Concept

Traditional variable protection approaches use read-only properties or obfuscation. SecureVar takes a different approach:

- **Variables are writable**, but only through cryptographically validated authorization
- **Server controls all writes** via time-limited, one-time-use WriteKeys
- **Multi-layer protection** prevents tampering, replay attacks, and unauthorized modifications
- **Zero-trust architecture** assumes the client is compromised and validates everything
- **Runtime threat detection** actively monitors for root, hooking, and debugging

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
│  │  • OriginVerifier: stack trace + ClassLoader + APK   │   │
│  │    signature + call depth + caller method checks     │   │
│  │  • RiskDetector: root/hook/emulator/debugger scan    │   │
│  │  • SecureMemory: plaintext wiping + GC hints         │   │
│  │  • Rate limiting (10 writes/min per variable)        │   │
│  │  • Tamper detection & alerts                         │   │
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

### Implemented Security Features

#### 1. Server-Issued Authorization (WriteKey)
- **One-time use**: Nonces tracked and rejected on replay
- **Time-limited**: TTL enforcement with configurable clock skew tolerance
- **Cryptographically signed**: HMAC-SHA256 or ECDSA (asymmetric preferred)
- **Context-bound**: Signatures include userId, propertyName, and scope
- **Risk-aware**: High-risk environments (debugger/root) require asymmetric signatures

#### 2. Local Sealing (SecureVarDelegate)
- **AES-GCM encryption**: 128-bit authentication tag, unique IV per write
- **Per-instance keys**: Derived from `SHA-256(encSecret:propertyName:instanceSalt)`
- **MAC protection**: HMAC-SHA256 over `propertyName:instanceSalt:IV:ciphertext`
- **Tamper detection**: MAC + checksum dual verification
- **Obfuscation**: Split value + random noise for additional depth

#### 3. Replay Prevention
- **Nonce store**: Persistent encrypted SharedPreferences
- **Integrity MAC**: HMAC over canonical nonce list (detects store tampering)
- **Automatic cleanup**: Expired nonces pruned on validation

#### 4. Runtime Threat Detection (RiskDetector)

| Category | Checks |
|----------|--------|
| **Root detection** | SU binaries, Magisk, KernelSU, root build tags, suspicious system properties, mount namespace cloaking, SELinux permissive mode, Zygisk/Shamiko DenyList artifacts, `/proc` access tampering, native property reading (bypasses hooked `getprop`) |
| **Hook detection** | Frida port scanning (default + range 27000–27100 with D-Bus fingerprinting), `/proc/maps` agent library scanning, Frida gadget class loading, Xposed/EdXposed/LSPosed class detection, Substrate detection, native hook libraries, thread name scanning (`/proc/self/task/*/comm` for `gmain`, `gdbus`, `gum-js-loop`), suspicious file descriptor scanning (`/proc/self/fd`), process name integrity check |
| **Emulator detection** | Build fingerprint, hardware, manufacturer, model, and product heuristics |
| **Debugger detection** | `Debug.isDebuggerConnected()`, TracerPid in `/proc/self/status`, `ApplicationInfo.FLAG_DEBUGGABLE` |
| **Package scanning** | Detects installed root managers, hooking frameworks, and reverse engineering tools |

#### 5. Origin Verification (OriginVerifier)
- **Stack trace analysis**: Validates calling package prefixes
- **ClassLoader validation**: Detects custom/injected ClassLoaders
- **APK signature pinning**: SHA-256 signing certificate verification
- **Call depth validation**: Rejects calls with abnormal stack depth (spoofed stacks)
- **Caller method verification**: Requires specific method names in the call chain

#### 6. Memory Protection (SecureMemory)
- **String wiping**: Reflection-based zeroing of `String` backing `byte[]`/`char[]` arrays
- **Byte/Char array wiping**: Direct zero-fill utilities
- **SecureScope**: Auto-wipes all tracked secrets on scope exit
- **GC hints**: Triggers garbage collection after wipe to reduce plaintext window
- **PeriodicWiper**: Background daemon thread sweeps globally tracked weak references every 30 seconds

#### 7. Certificate Pinning (CertificatePinning)
- **Framework-agnostic**: Works with `HttpsURLConnection`, OkHttp, Ktor, and others
- **SHA-256 SPKI pinning**: Validates server certificate public key hashes
- **Backup pins**: Supports certificate rotation without breaking existing installs
- **Subdomain support**: Optional `*.hostname` matching
- **Pin computation helper**: `computePin()` for discovering pins during development

#### 8. Dynamic Secret Management
- **Per-install secrets**: Random 32-byte Base64 secrets generated once
- **Encrypted storage**: Google Tink AEAD with AES256-GCM
- **Hardware-backed**: Android Keystore integration
- **DataStore**: Modern async preferences with encryption layer
- **SecretProvider**: Runtime interface for MAC/ENC secret retrieval


## 🚀 Quick Start

### 1. Initialize SecureVar in your Application class

```kotlin
class SecureVarApplication : Application() {
    private val dataStore by preferencesDataStore(name = "securevar_secrets")
    
    override fun onCreate() {
        super.onCreate()
        
        // Initialize Tink encryption
        EncryptedDataStore.initialize(this)
        
        // Start periodic memory wiper (recommended)
        SecureMemory.PeriodicWiper.start()
        
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
                            return@runBlocking EncryptedDataStore.decrypt(encrypted, this@SecureVarApplication)
                        }
                        
                        val bytes = ByteArray(32)
                        java.security.SecureRandom().nextBytes(bytes)
                        val plaintext = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
                        
                        val encryptedValue = EncryptedDataStore.encrypt(plaintext, this@SecureVarApplication)
                        dataStore.edit { it[prefKey] = encryptedValue }
                        plaintext
                    }
                },
                originVerifier = OriginVerifier.Builder(this)
                    .allowPackage("io.mohammedalaamorsi")
                    .pinSignature("SHA-256:AB:CD:...")
                    .expectCallDepth(5..30)
                    .expectCallerMethod("authorizedWrite")
                    .build(),
                context = this,
                onRiskDetected = { report ->
                    Log.w("SecureVar", "Risk detected: ${report.details}")
                    // Handle: logout, wipe data, notify server, etc.
                },
                writeKeyVerifier = { writeKey ->
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

    // Authorized write method - ONLY way to update secure variables
    suspend fun upgradeUserToPremium(userId: String) {
        val writeKey = UserApi.requestPremiumUpgrade(userId)
        isPremiumUserDelegate.authorizedWrite(
            newValue = true,
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
    
    if (!await canUpgradeToPremium(userId)) {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const nonce = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();
    const ttlMillis = 5 * 60 * 1000; // 5 minutes
    const propertyName = 'isPremiumUser';
    const scope = 'premium_upgrade';
    
    const message = `${nonce}:${timestamp}:${userId}:${propertyName}:${scope}`;
    const hmacSignature = crypto
        .createHmac('sha256', process.env.APP_SECRET_KEY)
        .update(message)
        .digest('base64');
    
    // Optional: ECDSA for high-security
    const sign = crypto.createSign('SHA256');
    sign.update(message);
    const asymSignature = sign.sign(privateKey, 'base64');
    
    res.json({
        nonce, timestamp, signature: hmacSignature, asymSignature,
        ttlMillis, userId, propertyName, scope
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

### Certificate Pinning for WriteKey Endpoints

```kotlin
val pinConfig = CertificatePinning.PinConfig(
    hostname = "api.yourapp.com",
    sha256Pins = setOf("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
    backupPins = setOf("sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
)

// With HttpsURLConnection
val connection = URL("https://api.yourapp.com/writekey").openConnection() as HttpsURLConnection
CertificatePinning.apply(connection, pinConfig)

// With OkHttp
val okPinner = okhttp3.CertificatePinner.Builder()
    .add(pinConfig.hostname, *pinConfig.allPins.toTypedArray())
    .build()
val client = OkHttpClient.Builder().certificatePinner(okPinner).build()
```

### Secure Memory Handling

```kotlin
// Wipe a single string after use
val secret = decryptSomething()
useSecret(secret)
SecureMemory.wipeString(secret)

// Auto-wipe everything in a scope
SecureMemory.withSecureScope { scope ->
    val token = scope.track(decryptToken())
    val key = scope.track(decryptKey())
    // ... use token and key ...
}   // Both wiped automatically + GC hint

// Track long-lived secrets for periodic cleanup
SecureMemory.PeriodicWiper.trackGlobal(sensitiveString)
```

### Runtime Risk Detection

```kotlin
// Quick check
if (RiskDetector.isHighRisk(context)) {
    // Respond: logout, wipe data, alert server
}

// Detailed report
val report = RiskDetector.getDetailedRiskReport(context)
if (report.highRisk) {
    Log.w("Security", "Threats: ${report.details}")
    // e.g., ["root:magisk_detected", "hook:frida_thread_detected", "root:selinux_permissive"]
}
```

### Custom Tamper Detection

```kotlin
SecureVarManager.initialize(
    SecureVarConfig(
        action = SecureVarAction.Logout, // Logout user on tamper detection
        secretProvider = mySecretProvider
    )
)
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
- ✅ Origin verification (stack trace, ClassLoader, APK signature)
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
| Risk detection | ~50-200ms | Full scan (root + hook + emulator) |
| Memory wipe | ~0.1ms | Reflection-based backing array zero |

## 🛡️ Threat Model

### Protected Against

✅ **Memory inspection**: Variables encrypted at rest  
✅ **Direct assignment**: `setValue()` rejected, triggers alert  
✅ **Replay attacks**: Nonce tracking prevents reuse  
✅ **Tampering**: MAC + checksum detect modifications  
✅ **Key forgery**: HMAC/ECDSA signatures prevent unauthorized write keys  
✅ **Context escalation**: Signatures bound to specific users, properties, and scopes  
✅ **Time manipulation**: TTL + clock skew enforcement  
✅ **Unauthorized origins**: Stack trace + ClassLoader + APK signature verification  
✅ **Rate abuse**: Per-variable write throttling  
✅ **Cross-instance state injection**: Per-instance salt prevents key reuse  
✅ **Nonce store tampering**: Integrity MAC detects modifications  
✅ **Root/Magisk/KernelSU**: Multi-signal detection with SELinux and Zygisk checks  
✅ **Frida/Xposed/Substrate**: Thread scanning, port probing, fd inspection  
✅ **Emulator & debugger**: Build fingerprint and TracerPid detection  
✅ **Plaintext exposure**: SecureMemory wipe + periodic background sweeps  
✅ **MITM attacks**: CertificatePinning with backup pin support  

### Limitations & Mitigations

| Threat | Mitigation | Residual Risk |
|--------|-----------|---------------|
| **Root access** | `RiskDetector` detects Magisk, KernelSU, SU binaries, mount namespace cloaking, SELinux permissive mode, Zygisk/Shamiko DenyList artifacts, `/proc` access tampering, and native property reading (bypasses hooked `getprop`); triggers risk callback | Kernel-level rootkits with fully custom cloaking remain theoretically possible |
| **Frida/Xposed** | `RiskDetector` scans `/proc/maps`, checks loaded framework classes, probes default + extended port range (27000–27100) with D-Bus protocol fingerprinting, scans thread names (`/proc/self/task/*/comm`), checks `/proc/self/fd` for injected artifacts, and validates process name integrity | Attackers who rename all artifacts AND patch thread names simultaneously (extremely difficult) |
| **Physical device access** | AndroidKeyStore + Tink encryption; risk callback allows app-level response | Hardware key extraction remains possible on some devices |
| **Stack trace spoofing** | `OriginVerifier` adds ClassLoader validation + APK signature pinning + call chain depth validation + expected method name verification | Kernel-level call stack manipulation (extremely rare) |
| **Plaintext exposure** | `SecureMemory` wipes String backing arrays via reflection; `withSecureScope` auto-wipes on exit; GC hint after every wipe; `PeriodicWiper` background sweeps every 30s | JIT may retain register copies briefly (< 30s exposure window) |
| **Server compromise** | `CertificatePinning` helper with backup pins for key rotation; ECDSA signatures require private key | Compromised private key remains out of scope |

## 🔧 Configuration Options

### SecureVarConfig

```kotlin
SecureVarConfig(
    action = SecureVarAction.Alert("https://your-server.com/alert"),
    secretProvider = mySecretProvider,                    // MAC/ENC secret source
    writeKeyVerifier = myWriteKeyVerifier,                // Custom WriteKey validator
    originVerifier = OriginVerifier.Builder(context)      // Multi-signal origin verification
        .allowPackage("com.yourapp")
        .pinSignature("SHA-256:AB:CD:...")
        .expectCallDepth(5..30)
        .expectCallerMethod("authorizedWrite")
        .build(),
    allowedCallerPackages = listOf("com.yourapp"),        // Fallback stack trace prefixes
    context = applicationContext,                          // For runtime risk detection
    onRiskDetected = { report ->                          // Risk callback
        Log.w("SecureVar", "Risk: ${report.details}")
    }
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

## � Library Structure

```
securevar/
├── SecureVarDelegate.kt          # Core delegate with sealing/unsealing
├── SecureVarManager.kt           # Central config & lifecycle manager
├── SecureVarWriter.kt            # Type-safe write helpers
├── WriteKeyValidator.kt          # WriteKey nonce/signature validation
├── integrity/
│   ├── PlayIntegrityManager.kt   # Google Play Integrity API
│   └── WriteKeyIntegrityBundler.kt
├── memory/
│   ├── SecureCharArrayDelegate.kt # Char array wrapper
│   └── SecureMemory.kt           # String wiping + PeriodicWiper
├── risk/
│   └── RiskDetector.kt           # Root/hook/emulator/debugger detection
└── security/
    ├── CertificatePinning.kt     # MITM protection with backup pins
    ├── EncryptedDataStore.kt     # Tink AEAD encrypted storage
    └── OriginVerifier.kt         # Multi-signal origin validation
```

## 📚 Documentation

- [Security Architecture](docs/SECURITY.md) - Detailed threat model and cryptographic design

## 📄 License

This project is licensed under the Apache License 2.0 - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Google Tink for AEAD encryption
- AndroidX DataStore for modern encrypted storage
- Google Play Integrity API for device attestation
- Kotlin coroutines for async operations

## 🔗 Links

- [GitHub Repository](https://github.com/MohammedAlaaMorsi/SecureVar)
- [Maven Central](https://central.sonatype.com/artifact/io.github.mohammedalaamorsi/securevar)
- [Issue Tracker](https://github.com/MohammedAlaaMorsi/SecureVar/issues)
- [Discussions](https://github.com/MohammedAlaaMorsi/SecureVar/discussions)

---

**Built with ❤️ for Android security**
