# Quick Start Guide

## Running the Sample App

### Prerequisites
- Android Studio (latest version)
- Android SDK 24+
- Kotlin 1.9+

### Build and Run

1. **Open the project** in Android Studio
2. **Sync Gradle** files (should happen automatically)
3. **Run the app** on an emulator or device

### What to Test

#### 1. Login Flow (Legitimate Write)
```
Action: Tap "Login" button
Expected: 
  - Loading spinner appears
  - After ~1.5s, user status shows "John Doe" with "FREE" badge
  - Snackbar: "Login successful!"
```

#### 2. Purchase Flow (Legitimate Write)
```
Action: Tap "Purchase Premium Subscription"
Expected:
  - Loading spinner appears
  - After ~2s, user status updates to "✓ PREMIUM" (highlighted)
  - Snackbar: "Subscription purchased successfully!"
  - Purchase button disappears
```

#### 3. Refresh Flow (Server Sync)
```
Action: Tap "Refresh User Status"
Expected:
  - Status syncs with server
  - Snackbar: "Status refreshed!"
```

#### 4. Security Test (Tamper Detection)
```
Action: Tap "Attempt Unauthorized Write" (red button)
Expected:
  - Snackbar: "⚠️ Hack attempt detected! Alert triggered."
  - Premium status UNCHANGED (security maintained)
  - Console log: 🚨 SecureVar Security Alert: [tamper.set]
```

## Understanding the Code

### SessionManager - The Star of the Show

```kotlin
class SessionManager(private val userRepository: UserRepository) {
    
    // 1️⃣ Declare secure variable
    var isPremiumUser: Boolean by secureVar(
        initialValue = false, 
        propertyName = "isPremiumUser"
    )
        private set  // Only SessionManager can call the setter
    
    // 2️⃣ Legitimate update with server key
    suspend fun refreshUserStatus() {
        val apiResponse = userRepository.fetchUserProfileWithWriteKey()
        
        // 3️⃣ Use authorized write with server-provided key
        secureVar(::isPremiumUser).write(
            newValue = apiResponse.isPremium,
            key = WriteKey(nonce = apiResponse.writeKey)
        )
    }
}
```

### Why Direct Assignment Fails

```kotlin
// ❌ This won't compile (private setter):
sessionManager.isPremiumUser = true

// ❌ If someone bypasses with reflection, this triggers alert:
// SecureVarDelegate.setValue() → SecureVarManager.trigger("tamper.set")

// ✅ Only this works (with server key):
secureVar(::isPremiumUser).write(true, WriteKey("server-key"))
```

## Viewing Console Logs

### Android Studio Logcat
1. Open **Logcat** tab at the bottom
2. Filter by: `SecureVar` or `Security Alert`
3. Look for: `🚨 SecureVar Security Alert: [tamper.set]`

### Sample Output
```
🚨 SecureVar Security Alert: {
    accessType=tamper.set, 
    details=Illegal direct assignment to isPremiumUser, 
    timestamp=1699564823000
}
```

## Experimenting with the Code

### Modify API Responses

Edit `MockUserApi.kt` to change behaviors:

```kotlin
// Make users start as premium after login
override suspend fun login(email: String, password: String): UserProfile {
    return UserProfile(
        userId = "user-123",
        username = "Premium User",
        email = email,
        isPremium = true,  // Changed from false
        writeKey = "login-key-${System.currentTimeMillis()}"
    )
}
```

### Add More Secure Variables

In `SessionManager.kt`:

```kotlin
var subscriptionLevel: String by secureVar(
    initialValue = "free",
    propertyName = "subscriptionLevel"
)
    private set

suspend fun refreshUserStatus() {
    val apiResponse = userRepository.fetchUserProfileWithWriteKey()
    
    secureVar(::subscriptionLevel).write(
        newValue = apiResponse.subscriptionLevel,  // Add this to UserProfile
        key = WriteKey(nonce = apiResponse.writeKey)
    )
}
```

### Test Tamper Detection

Add a test button in `MainScreen.kt`:

```kotlin
Button(onClick = {
    // Try to directly read/write the secure variable
    try {
        val currentValue = viewModel.sessionManager.isPremiumUser
        // This read is OK, but any tampering attempt fails
    } catch (e: Exception) {
        // Handle security exception
    }
}) {
    Text("Test Security")
}
```

## Common Issues

### Issue: Compilation Error in SecureVarDelegate
**Solution**: Ensure Kotlin reflection is added to `securevar/build.gradle.kts`:
```gradle
implementation("org.jetbrains.kotlin:kotlin-reflect:1.9.20")
```

### Issue: "Cannot access private setter"
**Solution**: This is expected! Use `secureVar(::property).write()` instead.

### Issue: App crashes on startup
**Solution**: Check:
1. `AndroidManifest.xml` has `android:name=".SecureVarApplication"`
2. All packages are correctly named `io.mohammedalaamorsi.securevarapp`

### Issue: ViewModel not found
**Solution**: Ensure dependencies in `app/build.gradle.kts`:
```gradle
implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
```

## Next Steps

### Enhance Security
1. Implement JWT validation in `WriteKey.isValid()`
2. Add nonce replay prevention
3. Implement certificate pinning for API calls

### Add Features
1. Create more use cases (logout, profile update)
2. Add persistence with DataStore or Room
3. Implement proper error handling

### Testing
1. Write unit tests for `SessionManager`
2. Write integration tests for API calls
3. Add UI tests with Compose Testing

## Resources

- **Clean Architecture**: [Blog Post by Uncle Bob](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
- **Jetpack Compose**: [Official Guide](https://developer.android.com/jetpack/compose)
- **Coroutines**: [Kotlin Docs](https://kotlinlang.org/docs/coroutines-overview.html)
- **Kotlin Delegates**: [Language Guide](https://kotlinlang.org/docs/delegated-properties.html)

## Questions?

Check the following files for detailed explanations:
- `README.md` - Architecture overview
- `ARCHITECTURE.md` - Flow diagrams and security mechanisms
- Code comments in `SessionManager.kt` - Inline documentation
