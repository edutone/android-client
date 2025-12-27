# SchoolDay Privacy VPN - Android Client

Fork of [NetBird Android Client](https://github.com/netbirdio/android-client) with K-12 SSO integration.

## Changes from Upstream

1. **Go Library Symlink**: Uses `../netbird` (our SSO-enabled fork) instead of upstream submodule
2. **OIDC SSO Integration**: System browser login with deep link callback (VPN-9.2)
3. **Secure Token Storage**: Android Keystore for session tokens (VPN-9.4)
4. **Branding**: SchoolDay Privacy VPN customization (VPN-9.6)

## Development Setup

### Prerequisites

- Android Studio (with SDK, NDK 23.1.7779620)
- Go 1.24+
- gomobile (`go install golang.org/x/mobile/cmd/gomobile@latest`)

### Environment Variables

```bash
export ANDROID_HOME=$HOME/Library/Android/sdk
export JAVA_HOME=/Applications/Android\ Studio.app/Contents/jbr/Contents/Home
```

### Build Go Library

```bash
# From android-client directory
./build-android-lib.sh
```

This builds `gomobile/netbird.aar` from our modified NetBird Go library.

### Build Android App

```bash
./gradlew assembleDebug -PversionCode=1 -PversionName=0.1.0
```

## Architecture

```
android-client/
├── netbird -> ../netbird    # Symlink to our SSO-enabled fork
├── gomobile/
│   └── netbird.aar          # Built Go library (gomobile bind output)
├── app/
│   └── src/main/java/io/netbird/client/
│       ├── MainActivity.java
│       ├── CustomTabURLOpener.java  # Opens system browser for OAuth
│       └── OAuthCallbackActivity.kt # NEW: Deep link handler (VPN-9.2)
└── build-android-lib.sh     # Builds Go library
```

## SSO Flow

```
1. User taps "Login with School Account"
2. App generates PKCE challenge
3. System browser opens to IdP (Keycloak/Okta/etc.)
4. User authenticates
5. IdP redirects to sdvpn://oauth/callback?code=...
6. OAuthCallbackActivity receives deep link
7. App exchanges code for tokens
8. VPN connects with session
```

## Upstream Sync

```bash
git fetch upstream
git merge upstream/main
```

## Related

- Go Library: `../netbird/` (SSO Bridge at `management/server/sso/`)
- SSO Documentation: `../netbird/management/server/sso/docs/`
- VPN-9 Plan: `~/.claude/plans/synchronous-wondering-raccoon.md`
