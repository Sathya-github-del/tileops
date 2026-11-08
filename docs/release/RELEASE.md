# Releasing TileOps (v0.3.0)

Everything that doesn't need your Google account is done. Files:

| What | Where |
|---|---|
| Play upload bundle (AAB) | `dist/TileOps-0.3.0.aab` (19 MB) |
| Direct-install APK | `dist/TileOps-0.3.0.apk` (30 MB) + `dist/SHA256SUMS` |
| Crash de-obfuscation map | `dist/TileOps-0.3.0-mapping.txt` (upload with the AAB) |
| Upload key + passwords | `secrets/tileops-upload.jks`, `secrets/upload-keystore.properties` (**back these up offline**) |
| Store text | `docs/release/store-listing.md` |
| Icon, feature graphic, 8 screenshots | `docs/release/icon-512.png`, `feature-graphic-1024x500.png`, `screenshots/` |
| Privacy policy | `docs/release/privacy-policy.html` (needs a public URL) |
| Play forms (Data safety, content rating, app access) | `docs/release/data-safety.md` |

Rebuild: `cd android && ./build.sh clean bundleRelease assembleRelease` (never use `-PreleaseTest` for uploads:
that makes a side-by-side test copy with a different package name).

## Steps that need you
1. **Google Play developer account** (one-time fee, identity verification). Organisation accounts also need a D-U-N-S number.
2. **Host the privacy policy** somewhere public (GitHub Pages, your website…) and note the URL.
3. **Create the app** in Play Console: name "TileOps: Server Watch", free, app (not game).
4. **Play App Signing:** accept Google-managed signing; upload `dist/TileOps-0.3.0.aab` (it's signed with the upload key; certificate SHA-256 is in `data-safety.md`). Upload the mapping file too.
5. **Store listing:** paste from `store-listing.md`, upload icon, feature graphic, screenshots.
6. **App content:** fill Data safety, content rating, target audience (18+), ads (none), app access, from `data-safety.md`.
7. **Testing tracks:**
   - *Internal testing* (up to 100 testers, available within minutes): start here.
   - *Closed testing:* new personal developer accounts must run a closed test with a minimum number of opted-in testers for a continuous period (currently 12 testers for 14 days; check the Play Console for the current rule) before they can apply for production.
   - *Production:* apply when the closed test is done.

## Alternative / in parallel: direct APK
Share `dist/TileOps-0.3.0.apk` (and its SHA-256) from a page you control. Users allow "Install unknown apps" for their browser/file manager. All future updates must be signed with the same upload key, or users have to uninstall first.
