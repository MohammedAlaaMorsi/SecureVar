# 🎬 Visual App Flow Guide

## App Screenshots Flow (Conceptual)

### Screen 1: Initial State (Logged Out)
```
┌─────────────────────────────────────┐
│   TrckQ Secure Variable Demo        │
│                                      │
│  ┌───────────────────────────────┐  │
│  │        Login                  │  │
│  │                               │  │
│  │  Email: user@example.com     │  │
│  │                               │  │
│  │  Password: ••••••••••        │  │
│  │                               │  │
│  │  [        Login       ]       │  │
│  └───────────────────────────────┘  │
│                                      │
└─────────────────────────────────────┘
```

### Screen 2: After Login (Free User)
```
┌─────────────────────────────────────┐
│   TrckQ Secure Variable Demo        │
│                                      │
│  ┌───────────────────────────────┐  │
│  │      User Status              │  │
│  │  ─────────────────────────    │  │
│  │  Username:      John Doe      │  │
│  │  Premium Status:  FREE        │  │
│  └───────────────────────────────┘  │
│                                      │
│  [  Purchase Premium Subscription ] │
│                                      │
│  [     Refresh User Status      ]   │
│                                      │
│  ─────────────────────────────────  │
│           Security Test              │
│  ┌───────────────────────────────┐  │
│  │  ⚠️ Tamper Detection Demo    │  │
│  │                               │  │
│  │  This simulates a hack        │  │
│  │  attempt...                   │  │
│  │                               │  │
│  │  [ Attempt Unauthorized Write]│  │
│  └───────────────────────────────┘  │
│                                      │
│  ┌───────────────────────────────┐  │
│  │  ℹ️ How It Works             │  │
│  │  • Server is source of truth  │  │
│  │  • Each API has write key     │  │
│  │  • Only authorized writes OK  │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

### Screen 3: After Purchase (Premium User)
```
┌─────────────────────────────────────┐
│   TrckQ Secure Variable Demo        │
│                                      │
│  ┌───────────────────────────────┐  │
│  │      User Status              │  │
│  │  ─────────────────────────    │  │
│  │  Username:      John Doe      │  │
│  │  Premium Status: ✓ PREMIUM   │  │
│  │              (highlighted)     │  │
│  └───────────────────────────────┘  │
│                                      │
│  [     Refresh User Status      ]   │
│                                      │
│  ─────────────────────────────────  │
│  (Rest of screen same as above)     │
└─────────────────────────────────────┘

  Snackbar: "Subscription purchased successfully!"
```

### Screen 4: After Security Test
```
┌─────────────────────────────────────┐
│   TrckQ Secure Variable Demo        │
│                                      │
│  (Same content as Screen 3)          │
│                                      │
│  Premium Status: ✓ PREMIUM          │
│  (Still premium - attack BLOCKED!)   │
│                                      │
└─────────────────────────────────────┘

  Snackbar: "⚠️ Hack attempt detected! Alert triggered."
  
  Console:
  🚨 TrckQ Security Alert: [tamper.set]
     Illegal direct assignment to isPremiumUser
```

## Interaction Sequence Diagram

```
User          UI           ViewModel      UseCase      SessionMgr   Repository   API
 │             │               │             │             │            │          │
 │  Tap Login  │               │             │             │            │          │
 │────────────>│               │             │             │            │          │
 │             │   login()     │             │             │            │          │
 │             │──────────────>│             │             │            │          │
 │             │               │  invoke()   │             │            │          │
 │             │               │────────────>│             │            │          │
 │             │               │             │  login()    │            │          │
 │             │               │             │────────────>│            │          │
 │             │               │             │             │ fetch()    │          │
 │             │               │             │             │───────────>│          │
 │             │               │             │             │            │  GET /   │
 │             │               │             │             │            │─────────>│
 │             │               │             │             │            │          │
 │             │               │             │             │            │ Response │
 │             │               │             │             │            │ +writeKey│
 │             │               │             │             │            │<─────────│
 │             │               │             │             │UserProfile │          │
 │             │               │             │             │<───────────│          │
 │             │               │             │             │            │          │
 │             │               │             │secureVar()  │            │          │
 │             │               │             │  .write()   │            │          │
 │             │               │             │  (with key) │            │          │
 │             │               │             │─────────────┤            │          │
 │             │               │             │             │            │          │
 │             │               │             │  Success    │            │          │
 │             │               │             │<────────────┤            │          │
 │             │               │  Success    │             │            │          │
 │             │               │<────────────│             │            │          │
 │             │  UI Update    │             │             │            │          │
 │             │<──────────────│             │             │            │          │
 │   Display   │               │             │             │            │          │
 │<────────────│               │             │             │            │          │
```

## State Transitions

```
┌─────────────┐
│ Logged Out  │
└──────┬──────┘
       │ login()
       │ with valid credentials
       ▼
┌─────────────┐     purchaseSubscription()     ┌─────────────┐
│ Logged In   │────────────────────────────────>│ Logged In   │
│ (FREE)      │                                 │ (PREMIUM)   │
└──────┬──────┘                                 └──────┬──────┘
       │                                               │
       │ refreshStatus()                    refreshStatus()
       │ (stays FREE)                       (stays PREMIUM)
       │                                               │
       ▼                                               ▼
┌─────────────┐                                ┌─────────────┐
│ Logged In   │                                │ Logged In   │
│ (FREE)      │                                │ (PREMIUM)   │
└─────────────┘                                └─────────────┘
```

## Security Flow: Attack vs Legitimate

### Legitimate Write Flow ✅
```
1. User Action
   │
2. ViewModel → UseCase
   │
3. SessionManager.login/purchase/refresh()
   │
4. Repository.fetchUserProfileWithWriteKey()
   │
5. API returns: { isPremium: true, writeKey: "abc123" }
   │
6. secureVar(::isPremiumUser).write(true, WriteKey("abc123"))
   │
7. SecureVarDelegate.authorizedWrite()
   ├─ key.isValid() ✓ TRUE
   ├─ seal(true) ✓ Obfuscate
   └─ state = sealed ✓ Update
   │
8. isPremiumUser now returns true ✓
```

### Attack Attempt Flow ❌
```
1. Attacker's Code
   │
2. sessionManager.isPremiumUser = true
   │
3. SecureVarDelegate.setValue() called
   │
4. TrckqManager.trigger("tamper.set", "Illegal...") ✓
   │
5. Write IGNORED ✓
   │
6. isPremiumUser still returns false ✓
```

## Data State Diagram

```
┌────────────────────────────────────────────┐
│         SecureVarDelegate State            │
│                                            │
│  ┌──────────────────────────────────────┐ │
│  │  SealedState                         │ │
│  │  ├─ partA: "tr" + "7823"            │ │
│  │  ├─ partB: "ue" + "4591"            │ │
│  │  └─ checksum: 928374651              │ │
│  └──────────────────────────────────────┘ │
│                                            │
│  On Read:                                  │
│  1. Check: createChecksum(partA, partB)   │
│  2. If checksum matches → reassemble       │
│  3. If checksum fails → trigger alert      │
│                                            │
│  On Write (authorized):                    │
│  1. Validate WriteKey                      │
│  2. If valid → create new SealedState     │
│  3. If invalid → trigger alert             │
│                                            │
│  On Write (unauthorized):                  │
│  1. setValue() called                      │
│  2. Trigger alert immediately              │
│  3. Ignore write completely                │
└────────────────────────────────────────────┘
```

## Component Communication Map

```
┌─────────────────────────────────────────────────────────────┐
│                        PRESENTATION                          │
│  ┌──────────────┐         observes         ┌─────────────┐ │
│  │  MainScreen  │<─────StateFlow──────────│ MainViewModel│ │
│  │  (Compose)   │                          │   (State)   │ │
│  └──────────────┘                          └──────┬──────┘ │
│                                                    │        │
└────────────────────────────────────────────────────┼────────┘
                                                     │
                                           calls     │
┌────────────────────────────────────────────────────┼────────┐
│                         DOMAIN                     │        │
│  ┌─────────────────────────────────────────────────▼─────┐ │
│  │              LoginUseCase                             │ │
│  │              PurchaseSubscriptionUseCase              │ │
│  │              RefreshUserStatusUseCase                 │ │
│  └─────────────────────────┬─────────────────────────────┘ │
│                            │                                │
│                            │ delegates to                   │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐  │
│  │            SessionManager                           │  │
│  │  ┌───────────────────────────────────────────────┐  │  │
│  │  │ var isPremiumUser by secureVar(...)          │  │  │
│  │  │     ▲                                         │  │  │
│  │  │     │ reads/writes                           │  │  │
│  │  │     │                                         │  │  │
│  │  │  SecureVarDelegate                           │  │  │
│  │  │  (obfuscation, checksum, alerts)             │  │  │
│  │  └───────────────────────────────────────────────┘  │  │
│  └─────────────────────────┬─────────────────────────────┘ │
└────────────────────────────┼───────────────────────────────┘
                             │ uses
┌────────────────────────────┼───────────────────────────────┐
│                        DATA│                                │
│  ┌─────────────────────────▼─────────────────────────────┐ │
│  │         UserRepository (interface)                    │ │
│  └─────────────────────────┬─────────────────────────────┘ │
│                            │                                │
│  ┌─────────────────────────▼─────────────────────────────┐ │
│  │         UserRepositoryImpl                            │ │
│  └─────────────────────────┬─────────────────────────────┘ │
│                            │                                │
│  ┌─────────────────────────▼─────────────────────────────┐ │
│  │         UserApi / MockUserApi                         │ │
│  └───────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘
```

## Key Moments Timeline

```
t=0s    App Launch
        └─ TrckQApplication.onCreate()
           └─ Initialize AppContainer

t=0.5s  MainActivity.onCreate()
        └─ Create MainViewModel
        └─ Compose UI rendered
        └─ Show login screen

t=5s    User taps "Login"
        └─ ViewModel.login()

t=5.5s  Loading state
        └─ UI shows spinner

t=7s    API response received
        └─ UserProfile + writeKey

t=7.1s  SecureVar authorized write
        └─ isPremiumUser = false
        └─ username = "John Doe"

t=7.2s  UI updates
        └─ Show user status (FREE)
        └─ Snackbar: "Login successful!"

t=15s   User taps "Purchase Premium"
        └─ ViewModel.purchaseSubscription()

t=17s   API response received
        └─ UserProfile + new writeKey

t=17.1s SecureVar authorized write
        └─ isPremiumUser = true

t=17.2s UI updates
        └─ Show premium badge ✓
        └─ Snackbar: "Subscription purchased!"

t=25s   User taps "Attempt Unauthorized Write"
        └─ SessionManager.attemptDirectWrite()

t=25.1s SECURITY ALERT TRIGGERED
        └─ TrckqManager.trigger("tamper.set")
        └─ Write IGNORED
        └─ Console: 🚨 Security Alert

t=25.2s UI updates
        └─ isPremiumUser still true (unchanged)
        └─ Snackbar: "⚠️ Hack attempt detected!"
```

## File Access Pattern

```
When user taps "Purchase":

MainActivity
    ↓
MainViewModel.purchaseSubscription()
    ↓
PurchaseSubscriptionUseCase.invoke()
    ↓
SessionManager.purchaseSubscription()
    ↓
UserRepository.purchaseSubscription()
    ↓
MockUserApi.purchaseSubscription()
    ↓
Returns: UserProfile(isPremium=true, writeKey="xyz")
    ↓
SessionManager receives response
    ↓
secureVar(::isPremiumUser).write(true, WriteKey("xyz"))
    ↓
SecureVarWriter.write()
    ↓
SecureVarDelegate.authorizedWrite()
    ├─ Validate key ✓
    ├─ Create SealedState ✓
    └─ Update internal state ✓
    ↓
Success flows back up the chain
    ↓
ViewModel updates UI state
    ↓
Compose recomposes with new data
    ↓
User sees premium badge ✓
```

---

This visual guide shows how the app flows from user interaction through all the architectural layers, demonstrating both legitimate operations and security protection mechanisms.
