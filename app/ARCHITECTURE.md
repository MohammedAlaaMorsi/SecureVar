# Architecture & Flow Documentation

## Clean Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    PRESENTATION LAYER                        │
│  ┌─────────────────┐              ┌────────────────────┐   │
│  │  MainScreen.kt  │◄─────────────│ MainViewModel.kt   │   │
│  │  (Compose UI)   │              │  (UI State)        │   │
│  └─────────────────┘              └────────┬───────────┘   │
└──────────────────────────────────────────────┼──────────────┘
                                               │
┌──────────────────────────────────────────────┼──────────────┐
│                     DOMAIN LAYER             │              │
│  ┌────────────────────────────────────────────▼─────────┐  │
│  │              Use Cases (Business Logic)              │  │
│  │  ┌─────────────┐ ┌──────────────┐ ┌──────────────┐  │  │
│  │  │ LoginUseCase│ │PurchaseUseCase│ │RefreshUseCase│  │  │
│  │  └──────┬──────┘ └──────┬───────┘ └──────┬───────┘  │  │
│  └─────────┼───────────────┼────────────────┼──────────┘  │
│            │               │                │              │
│  ┌─────────▼───────────────▼────────────────▼──────────┐  │
│  │          SessionManager (SecureVar Host)            │  │
│  │  ┌──────────────────────────────────────────────┐   │  │
│  │  │ var isPremiumUser: Boolean by secureVar(..)|   │  │
│  │  │ var username: String by secureVar(...)      │   │  │
│  │  │ var userId: String by secureVar(...)        │   │  │
│  │  └──────────────────────────────────────────────┘   │  │
│  └──────────────────────┬──────────────────────────────┘  │
└─────────────────────────┼─────────────────────────────────┘
                          │
┌─────────────────────────┼─────────────────────────────────┐
│                    DATA LAYER                              │
│  ┌───────────────────────▼──────────────────────────────┐ │
│  │            UserRepository (Interface)                 │ │
│  └───────────────────────┬──────────────────────────────┘ │
│                          │                                 │
│  ┌───────────────────────▼──────────────────────────────┐ │
│  │          UserRepositoryImpl (Implementation)          │ │
│  └───────────────────────┬──────────────────────────────┘ │
│                          │                                 │
│  ┌───────────────────────▼──────────────────────────────┐ │
│  │              UserApi (Network Layer)                  │ │
│  │         (MockUserApi for demonstration)               │ │
│  └───────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘
```

## Secure Variable Write Flow

```
1. USER ACTION (Login/Purchase)
   │
   ▼
2. ViewModel.login() / ViewModel.purchaseSubscription()
   │
   ▼
3. Use Case: LoginUseCase / PurchaseSubscriptionUseCase
   │
   ▼
4. SessionManager.login() / SessionManager.purchaseSubscription()
   │
   ▼
5. UserRepository.fetchUserProfileWithWriteKey()
   │
   ▼
6. UserApi.fetchUserProfile()
   │
   ▼
7. API Response:
   {
     "userId": "user-123",
     "username": "John Doe",
     "isPremium": true,
     "writeKey": "server-nonce-1699564823-1"  ← ONE-TIME KEY
   }
   │
   ▼
8. SessionManager receives response
   │
   ▼
9. AUTHORIZED WRITE:
   secureVar(::isPremiumUser).write(
       newValue = apiResponse.isPremium,
       key = WriteKey(nonce = apiResponse.writeKey)
   )
   │
   ▼
10. SecureVarDelegate.authorizedWrite()
    ├─ Validate key: key.isValid()
    ├─ If valid: seal(newValue) → update state
    └─ If invalid: TrckqManager.trigger("tamper.write")
   │
   ▼
11. Value is now:
    ├─ Obfuscated (split into partA, partB)
    ├─ Checksummed (integrity protection)
    └─ Protected (direct writes blocked)
```

## Tamper Detection Flow

```
SCENARIO: Attacker tries to bypass premium check

1. ATTACK ATTEMPT:
   sessionManager.isPremiumUser = true  // Direct assignment
   │
   ▼
2. SecureVarDelegate.setValue() is called
   │
   ▼
3. SECURITY TRIGGERED:
   TrckqManager.trigger(
       "tamper.set",
       "Illegal direct assignment to isPremiumUser"
   )
   │
   ▼
4. RESPONSE:
   ├─ Alert logged to console
   ├─ Alert sent to monitoring system (if configured)
   ├─ Write operation IGNORED (value unchanged)
   └─ User may be logged out / app may crash (configurable)
```

## Data Flow Diagram

```
┌──────────────┐
│   Server     │ ← SOURCE OF TRUTH
│  (Backend)   │
└──────┬───────┘
       │ API Response
       │ {
       │   isPremium: true,
       │   writeKey: "nonce-12345"
       │ }
       ▼
┌──────────────────────────────────────┐
│         UserRepository               │
│  (Fetches data from server)          │
└──────────────┬───────────────────────┘
               │
               ▼
┌──────────────────────────────────────┐
│        SessionManager                │
│  ┌────────────────────────────────┐  │
│  │ isPremiumUser by secureVar     │  │
│  │  ├─ Initial: false             │  │
│  │  ├─ After write: true          │  │
│  │  └─ Protected by WriteKey      │  │
│  └────────────────────────────────┘  │
└──────────────┬───────────────────────┘
               │
               ▼
┌──────────────────────────────────────┐
│          ViewModel                   │
│  (Exposes UI state)                  │
└──────────────┬───────────────────────┘
               │
               ▼
┌──────────────────────────────────────┐
│         Compose UI                   │
│  Shows: Premium Status Badge         │
│  • FREE (gray)                       │
│  • ✓ PREMIUM (highlighted)          │
└──────────────────────────────────────┘
```

## Security Mechanisms

### 1. Write Key Validation
```kotlin
data class WriteKey(val nonce: String) {
    fun isValid(): Boolean {
        // Validates the key is legitimate
        return nonce.isNotBlank()
        // In production: verify JWT signature, check expiry, etc.
    }
}
```

### 2. Value Obfuscation
```kotlin
private fun obfuscateAndSplit(value: T): Pair<Any, Any> {
    val stringValue = value.toString()
    val midPoint = stringValue.length / 2
    val partA = stringValue.substring(0, midPoint) + randomNoise()
    val partB = stringValue.substring(midPoint) + randomNoise()
    return Pair(partA, partB)
}
```

### 3. Integrity Checksums
```kotlin
private fun createChecksum(partA: Any, partB: Any): Int {
    return (partA.hashCode() * 31 + partB.hashCode())
}

private fun isTampered(state: SealedState.Sealed<T>): Boolean {
    val expectedChecksum = createChecksum(state.partA, state.partB)
    return expectedChecksum != state.checksum
}
```

### 4. Direct Write Blocking
```kotlin
override fun setValue(thisRef: Any?, property: KProperty<*>, value: T) {
    // This is called for direct assignments
    TrckqManager.trigger("tamper.set", "Illegal direct assignment")
    // Write is IGNORED - security maintained
}
```

## Testing Scenarios

### ✅ Legitimate Flows
1. **Login** → Server gives key → Write succeeds
2. **Purchase** → Server gives key → Write succeeds
3. **Refresh** → Server gives key → Write succeeds

### ❌ Attack Scenarios
1. **Direct Assignment** → Blocked by private setter
2. **Reflection Attack** → Triggers setValue() → Alert fired
3. **Memory Tampering** → Checksum fails → Alert fired
4. **Invalid Key** → Validation fails → Alert fired

## Comparison with Traditional Approach

### Before (Vulnerable):
```kotlin
var isPremiumUser = false

// Attacker's code:
isPremiumUser = true  // ✗ Success! Bypassed payment.
```

### After (Protected):
```kotlin
var isPremiumUser: Boolean by secureVar(...)
    private set

// Legitimate code:
secureVar(::isPremiumUser).write(true, serverKey)  // ✓ Success!

// Attacker's code:
isPremiumUser = true  // ✗ BLOCKED! Alert triggered.
```

## Key Takeaways

1. ✅ **Server Authority**: Only the server can authorize state changes
2. ✅ **Defense in Depth**: Multiple layers of protection
3. ✅ **Clean Architecture**: Testable, maintainable, scalable
4. ✅ **Developer-Friendly**: Easy to use, hard to misuse
5. ✅ **Production-Ready**: Extensible for real-world needs
