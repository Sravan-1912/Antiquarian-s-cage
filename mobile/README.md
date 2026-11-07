# Cage Authenticator (Android / iOS)

Phone app for passwordless sign-in to Antiquarian's Cage: the computer shows a number, you tap the same number on the
phone and confirm with **fingerprint or face**. Built with Expo / React Native (one TypeScript codebase).

## How it is secured

| Piece | How |
|---|---|
| Signing key | RSA-2048 created by the OS key store (Android Keystore / iOS Keychain) via `react-native-biometrics`, with *user authentication required*: the private key never leaves the key store and **every** signature needs a fresh biometric match. No PIN fallback (`allowDeviceCredentials: false`). |
| Pairing | One-time QR from the console (5 min). The app signs `CAGE-PAIR-V1|token|sha256(public key)` — pairing already requires a biometric match. |
| Approval | The app shows three numbers; only the one on the computer approves. The signed message binds request id, server challenge, decision and number. Wrong number or *Deny* blocks the sign-in and raises a high-severity alert. |
| Polling | A per-phone poll secret (Keychain/Keystore-encrypted storage, this-device-only) lets the app list requests; it cannot approve anything without the biometric key. |
| Transport | https required; plain http only for private-LAN development servers, shown as "not encrypted (dev)". |
| Removal | Removing the phone in the console, or offboarding the employee, revokes it; the app detects this and forgets the account. |

Protocol and server checks: `backend/app/services/phone_auth.py`, tests in `backend/tests/test_phone_auth.py`.

## Limitations (honest list)

* **No push notifications yet** — the app checks for requests every 3 s *while it is open*. Push needs a Firebase
  (Android) / APNs (iOS) account; not set up.
* **Android face unlock**: most Android phones classify face unlock as "weak" (class 2), which the Keystore does not
  accept for keys bound to biometrics. On those phones only the **fingerprint** works. iPhone Face ID works.
* **iOS** uses an RSA key in the Keychain protected by a biometry access-control flag (the Secure Enclave supports only
  EC keys, which this library does not use).
* Not yet tested on a physical phone in this repository (see `documentation/test-log.md`).

## Build the Android APK (Windows, as done here)

Prerequisites installed on D: — JDK 17 (`D:\DevTools\jdk-17…`), Android SDK (`D:\DevTools\android-sdk`).

```bash
cd mobile
npm install
npx expo prebuild --platform android      # only if android/ is missing
cd android
set JAVA_HOME=D:\DevTools\jdk-17.0.21+9
set ANDROID_HOME=D:\DevTools\android-sdk
set GRADLE_USER_HOME=D:\DevTools\gradle-home
gradlew.bat assembleRelease
```

Output: `android/app/build/outputs/apk/release/app-release.apk`. The release key lives in `mobile/credentials/`
(gitignored): `release.keystore` + `signing.properties`. **Back it up** — Android refuses updates signed with a
different key. The build fails on purpose if no release key is configured (it will not ship a debug-signed release).

Install on a phone: enable *Install unknown apps* for your file manager, copy the APK, open it. Or with USB debugging:
`D:\DevTools\android-sdk\platform-tools\adb install app-release.apk`.

## Build the iOS app (.ipa) — needs a Mac or Expo's cloud

Windows cannot build iOS apps. Either:

* **On a Mac** (Xcode 16+): `cd mobile && npm install && npx expo prebuild --platform ios && cd ios && pod install`,
  open `CageAuthenticator.xcworkspace`, set your Apple Developer team, *Product → Archive → Distribute*.
* **Expo EAS cloud**: `npx eas-cli build --platform ios` with your Expo account and Apple Developer account
  ($99/year). Bundle id: `com.antiquarianscage.authenticator`.

## Connecting a phone to a development server

A phone cannot reach `localhost`. Run the API on the LAN and tell the server its address:

1. `.env`: `PHONE_API_BASE_URL=http://<this PC's LAN IP>:8000`
2. Start the API with `--host 0.0.0.0` and allow port 8000 in Windows Firewall (private networks only).
3. Phone and PC on the same Wi-Fi. Console → Account → Security → *Pair a phone* → scan.
