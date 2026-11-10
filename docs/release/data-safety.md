# Play Console answers (Data safety, content rating, app content)

## Data safety
- **Does your app collect or share any of the required user data types?** No (the developer receives nothing; all data stays on the device or on the user's own companion/servers).
  - Note: data sent to servers the user configures themselves is not "collection" by the developer.
- **Is all user data encrypted in transit?** SSH to servers: yes. Companion mode uses plain HTTP on the user's own network today. Answer **No** until companion HTTPS ships, or answer per Play's current definitions if companion traffic is excluded as user-controlled.
- **Can users request data deletion?** Data is on-device only: uninstall/clear data deletes it.
- **Third-party SDKs:** none that collect data (QR decoding uses the open-source ZXing library on the device; no Google Play services, analytics or ads).

## App content
- **Ads:** No · **In-app purchases:** No · **Target audience:** 18+ (tool for server administrators) · **News app:** No
- **App access:** All features are usable without an account. Reviewers can open "Just this phone" and see every screen; adding a real server requires an SSH server they control.
- **Content rating questionnaire:** Utility/productivity; no violence, sexual content, gambling, user-generated content sharing, or location sharing.
- **Permissions:** CAMERA (QR pairing), POST_NOTIFICATIONS, USE_BIOMETRIC, ACCESS_NETWORK_STATE. No restricted permissions (no SMS/Call log, no QUERY_ALL_PACKAGES, no background location, no VpnService).
- **Government / financial / health features:** None.

## Signing
- Use **Play App Signing**. Upload key: `secrets/tileops-upload.jks` (password in `secrets/upload-keystore.properties`).
- Upload key certificate SHA-256: `9B:4E:76:E4:62:0A:60:EE:B4:39:3F:33:2F:C3:92:75:80:84:A2:05:35:14:37:2E:4E:2A:65:49:E1:24:3E:7D`
- **Back up both files somewhere safe and offline.** If the upload key is lost, Play support can reset it, but it takes time.
