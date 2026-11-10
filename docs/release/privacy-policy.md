# TileOps privacy policy

_Last updated: 8 November 2026 · Developer: Sathya Prakash J_

TileOps is a tool for watching your own servers. It has **no user accounts, no ads, no analytics and no tracking**, and the developer receives **no data** from the app.

## What the app stores, and where
Everything stays on your device, in the app's private storage, encrypted with a key held in the Android Keystore:
- the servers you add (name, address, port, login user, folders and services to watch, optional health-check URLs);
- an SSH key pair TileOps generates for each server (the private key never leaves the device);
- the trusted host-key fingerprint of each server;
- the results of checks: the baseline, alerts with their evidence, the incident timeline, restart runs;
- your restart approval PIN, stored only as a salted hash;
- in companion mode, the companion's address and pairing code.

Uninstalling the app, or clearing its data, deletes all of it. Device backups exclude TileOps data.

## What the app connects to
Only addresses you choose:
- **your servers**, over SSH, to run read-only checks (and service restarts you approve);
- **health-check URLs** you set, to confirm a restart worked;
- **your own TileOps companion**, if you use companion mode.

TileOps does not send your server data anywhere else.

## Permissions
- **Camera:** only to scan a companion's pairing QR code. Images are decoded on the device by the open-source ZXing library and are never stored or sent.
- **Notifications:** to show alerts.
- **Biometric / screen lock:** to confirm restarts and opening your VPN app. TileOps never sees your fingerprint or screen-lock PIN.
- **Network state:** to tell whether a VPN is connected before checking VPN-only servers.

## Third-party components
TileOps contains no analytics, advertising or tracking SDKs, and no Google Play services code. If you use the optional companion with push notifications, the companion (which you run yourself) sends short alert titles to the ntfy.sh service under a random topic you control.

## Children
TileOps is a tool for server administrators and is not directed at children.

## Contact
Questions: _<your support email>_.
