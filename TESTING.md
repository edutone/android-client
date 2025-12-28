# Android Client Testing Guide

## Prerequisites

1. Android Studio (or command-line SDK tools)
2. Docker and Docker Compose
3. Android emulator or physical device

## Starting the Test Environment

### 1. Start Keycloak with K12 Realm

```bash
cd ../netbird/dev
docker compose -f docker-compose.yml -f docker-compose.mobile.yml up -d
```

Wait for Keycloak to start (about 30 seconds):
```bash
docker compose logs -f keycloak
# Look for: "Listening on: http://0.0.0.0:8080"
```

### 2. Verify Keycloak is Running

Access the admin console:
- URL: http://localhost:8180/admin
- Username: `admin`
- Password: `admin`

### 3. Configure Android Emulator Network Access

The Android emulator uses `10.0.2.2` to access the host machine.
Configure the app to use: `http://10.0.2.2:8180`

## Test Accounts

| User | Password | Role | Use Case |
|------|----------|------|----------|
| alice.student@school.edu | Student@123 | student | Basic student VPN access |
| bob.student@school.edu | Student@123 | student | Middle school student |
| carol.teacher@school.edu | Teacher@123 | teacher | Teacher with classroom management |
| david.admin@school.edu | Admin@123 | admin, staff | Full administrative access |

## Test Scenarios

### 1. Student Login (Basic Flow)

1. Launch the app
2. Tap "Login with School Account"
3. Enter credentials: `alice.student@school.edu` / `Student@123`
4. Complete login in browser
5. Verify redirect back to app
6. Verify session info displayed (email, role: student)

**Expected Result**: Session created with role=student

### 2. Teacher Login

1. Launch the app
2. Tap "Login with School Account"
3. Enter credentials: `carol.teacher@school.edu` / `Teacher@123`
4. Complete login
5. Verify session shows role=teacher

**Expected Result**: Session created with role=teacher

### 3. Admin Login

1. Launch the app
2. Tap "Login with School Account"
3. Enter credentials: `david.admin@school.edu` / `Admin@123`
4. Verify session shows roles=[admin, staff]

**Expected Result**: Session created with multiple roles

### 4. Invalid Credentials

1. Launch the app
2. Tap "Login with School Account"
3. Enter invalid credentials
4. Attempt login

**Expected Result**: Error shown, no session created

### 5. Session Persistence

1. Complete successful login
2. Force-close the app
3. Reopen the app
4. Check if session is restored

**Expected Result**: Session restored from secure storage

### 6. Token Refresh

1. Complete successful login
2. Wait 5+ minutes (or adjust REFRESH_CHECK_INTERVAL_MS for testing)
3. Verify auto-refresh occurred (check logs)

**Expected Result**: Token refreshed without re-login

### 7. Logout

1. Complete successful login
2. Tap "Logout" (or trigger logout)
3. Verify session is cleared
4. Verify secure storage is empty

**Expected Result**: Session revoked, tokens deleted, login required again

### 8. Network Error Handling

1. Start login flow
2. Disable network mid-flow
3. Verify graceful error handling

**Expected Result**: Error message shown, no crash

## Debugging

### Enable Verbose Logging

In `SSOBridge.kt`, logs are tagged with `SSOBridge`.
Filter logcat:
```bash
adb logcat | grep -E "(SSOBridge|SecureTokenStore)"
```

### Inspect Secure Storage

On rooted devices/emulators, you can inspect:
```bash
adb shell
run-as io.netbird.client
cat shared_prefs/sd_vpn_encrypted_prefs.xml
# (Values will be encrypted)
```

### Check Keystore Status

```kotlin
SSOBridge.isSecureStorageHardwareBacked()
// Returns true on devices with hardware security
```

## Troubleshooting

### "Connection refused" on emulator

- Ensure Keycloak is running: `docker compose ps`
- Use `10.0.2.2` not `localhost` from emulator
- Check port binding: `docker compose port keycloak 8080`

### Deep link not captured

1. Verify AndroidManifest.xml has intent filter for `sdvpn://`
2. Check OAuthCallbackActivity is declared
3. Test with: `adb shell am start -a android.intent.action.VIEW -d "sdvpn://oauth/callback?code=test&state=test"`

### Session not stored

1. Verify Context is passed to SSOBridge.initialize()
2. Check SecureTokenStore singleton is created
3. Verify no exceptions in logcat
