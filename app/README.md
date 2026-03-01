# SecureVar Sample App - Clean Architecture Demo

This sample app demonstrates the use of SecureVar's secure variable system with clean architecture principles.

## Architecture Overview

The app follows **Clean Architecture** with three main layers:

### 1. Data Layer (`data/`)
- **`model/`**: Data models (DTOs)
  - `UserProfile.kt`: Server response model with write key
  
- **`remote/`**: API interfaces and implementations
  - `UserApi.kt`: API interface for user operations
  - `MockUserApi`: Simulated API for demo purposes
  
- **`repository/`**: Repository pattern implementation
  - `UserRepository.kt`: Repository interface
  - `UserRepositoryImpl.kt`: Concrete implementation

### 2. Domain Layer (`domain/`)
- **`manager/`**: Business logic managers
  - `SessionManager.kt`: **Demonstrates SecureVar usage** ✨
  
- **`usecase/`**: Single-responsibility use cases
  - `LoginUseCase.kt`: Handles login logic
  - `PurchaseSubscriptionUseCase.kt`: Handles subscription purchase
  - `RefreshUserStatusUseCase.kt`: Refreshes user status from server

### 3. Presentation Layer (`presentation/`)
- **`MainViewModel.kt`**: UI state management with coroutines
- **`MainScreen.kt`**: Jetpack Compose UI components

### Dependency Injection (`di/`)
- **`AppContainer.kt`**: Simple DI container (manual dependency injection)

## How Secure Variables Work

### The Problem
Traditional variables can be modified directly, making them vulnerable to tampering:
```kotlin
var isPremiumUser = false
// Attacker can easily do:
isPremiumUser = true  // ❌ Bypassed payment!
```

### The Solution: SecureVar
```kotlin
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

// Direct assignment is BLOCKED:
isPremiumUser = true  // ❌ Triggers security alert!

// Only authorized writes with server-provided keys work:
isPremiumUserDelegate.authorizedWrite(
    newValue = true,
    key = WriteKey(nonce = "server-generated-key-12345")  // ✓ Authorized!
)
```

## Key Features Demonstrated

### 1. Server as Source of Truth
Every critical state change requires server validation:
- Login → Server provides write key
- Purchase → Server provides write key
- Refresh → Server provides write key

### 2. One-Time Write Keys
Each API response includes a unique, single-use key:
```kotlin
data class UserProfile(
    val isPremium: Boolean,
    val writeKey: String  // "server-nonce-1699564823-1"
)
```

### 3. Tamper Detection
The SecureVar system includes:
- **Obfuscation**: Values are split and obfuscated in memory
- **Checksums**: Integrity validation on every read
- **Alert System**: Unauthorized access triggers `SecureVarManager.trigger()`

### 4. Private Setters
Kotlin's `private set` prevents even legitimate code from direct assignment:
```kotlin
var isPremiumUser: Boolean by secureVar(...)
    private set  // Compiler enforces write protection
```

## Testing the App

### 1. Login Flow
1. Tap "Login" button
2. Server authenticates and returns profile with `writeKey`
3. SessionManager uses key to authorize write to `isPremiumUser`

### 2. Purchase Flow
1. While logged in, tap "Purchase Premium Subscription"
2. Server processes purchase and returns updated profile with new `writeKey`
3. SessionManager updates `isPremiumUser = true` using authorized write

### 3. Refresh Flow
1. Tap "Refresh User Status"
2. Server returns latest status with new `writeKey`
3. SessionManager syncs local state with server

### 4. Security Test
1. Tap "Attempt Unauthorized Write" button
2. System detects illegal direct assignment
3. Alert is triggered: `🚨 SecureVar Security Alert: [tamper.set]`
4. Write is **ignored** - security maintained!

## Benefits of This Architecture

### Clean Architecture
✅ **Separation of Concerns**: Each layer has a single responsibility  
✅ **Testability**: Easy to unit test each component  
✅ **Maintainability**: Changes in one layer don't affect others  
✅ **Scalability**: Easy to add new features  

### Secure Variables
✅ **Payment Protection**: Can't bypass premium checks  
✅ **Server Authority**: Server always controls critical state  
✅ **Tamper Detection**: Alerts on unauthorized access  
✅ **Memory Safety**: Obfuscated values resist memory inspection  

## Project Structure

```
app/src/main/java/io/mohammedalaamorsi/securevarapp/
├── data/
│   ├── model/
│   │   └── UserProfile.kt
│   ├── remote/
│   │   └── UserApi.kt
│   └── repository/
│       ├── UserRepository.kt
│       └── UserRepositoryImpl.kt
├── domain/
│   ├── manager/
│   │   └── SessionManager.kt          ⭐ SecureVar Implementation
│   └── usecase/
│       ├── LoginUseCase.kt
│       ├── PurchaseSubscriptionUseCase.kt
│       └── RefreshUserStatusUseCase.kt
├── presentation/
│   ├── MainViewModel.kt
│   └── MainScreen.kt
├── di/
│   └── AppContainer.kt
├── ui/theme/
│   └── ... (theme files)
├── MainActivity.kt
└── SecureVarApplication.kt
```

## Dependencies

- **SecureVar Library**: Local project module (`:securevar`)
- **Jetpack Compose**: Modern UI toolkit
- **Coroutines**: Async operations
- **ViewModel**: Lifecycle-aware state management

## Future Enhancements

- [ ] Replace manual DI with Dagger Hilt or Koin
- [ ] Add Retrofit for real API calls
- [ ] Implement encrypted storage for offline state
- [ ] Add comprehensive unit and integration tests
- [ ] Implement JWT-based write key validation
- [ ] Add biometric authentication for sensitive operations

## Security Notes

⚠️ This is a demonstration. In production:
1. Use HTTPS for all API calls
2. Implement proper JWT/OAuth authentication
3. Add certificate pinning
4. Encrypt sensitive data at rest
5. Implement rate limiting
6. Add device fingerprinting
7. Use ProGuard/R8 obfuscation

## License

This is a sample project for demonstration purposes.
