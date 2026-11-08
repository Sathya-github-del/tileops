# Changelog

## 0.3.0 (first public release)
- Two modes: **Just this phone** (the app checks your servers itself) and **Always-on companion** (24/7 checks, push alerts).
- Seven tripwires: users, SSH keys, cron, listening ports, unknown CPU-heavy processes, web-root files, systemd units; baseline, deduplication, evidence.
- Add servers from the app with a generated, readable setup command; host-key confirmation; connection test.
- Servers behind a VPN ("only reachable over a VPN"; Connect VPN button protected by fingerprint/screen lock).
- Restart allow-listed services with PIN + biometric approval and health-check verification; incident timeline.
- Companion over HTTPS with certificate pinning; QR / link / manual pairing.
- Quick Settings tile, home-screen widget, dark theme. Android 13+.
