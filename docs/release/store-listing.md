# Google Play store listing: TileOps

**App name** (max 30): `TileOps: Server Watch`
**Short description** (max 80): `Get alerted when something changes on your Linux servers. No agent, no cloud.`

**Full description** (max 4000):

TileOps watches your Linux servers and tells you the moment something changes: a new user account, a new SSH key, a new scheduled task, a new open port, an unknown program eating the CPU, a new file in your website folder, or a new system service. Those are the classic signs of a break-in or of a change nobody told you about.

**No agent, no account, no cloud.** TileOps logs in to your server over SSH with its own limited user and runs a fixed set of read-only checks. Nothing is installed except that user. Your data stays on your phone (or on your own always-on companion).

**How it works**
• Add a server in the app. TileOps gives you a one-time setup command; paste it into any SSH app on the server. TileOps never asks for your server password.
• Confirm the server's identity (its host-key fingerprint), test, and run the first scan. That records what's normal.
• From then on, any change raises an alert with the evidence: what changed, when, and the exact command output.

**Act safely**
• Mark a change as expected, acknowledge it, or snooze it.
• Restart a service (only ones you allow), and only after your PIN and your fingerprint or screen lock. A restart only counts as done when your health-check URL answers again.
• Every step goes into an incident timeline.

**Two ways to run it**
• Just this phone: easiest; checks when you open the app and in the background when Android allows.
• Always-on companion: a small program on a spare phone, Raspberry Pi or server checks every 5 minutes, 24/7, and pushes alerts even when your phone is off.

**Servers behind a VPN**
Mark a server "only reachable over a VPN". TileOps checks it while your VPN (e.g. OpenVPN Connect) is connected and quietly waits otherwise. The Connect VPN button asks for your fingerprint or screen lock first.

Also: Quick Settings tile (scan with one tap), home-screen status widget, dark theme, encrypted on-device storage (Android Keystore).

TileOps is made by Sathya Prakash J.

**Category:** Tools · **Tags:** server monitoring, security, SSH, sysadmin, intrusion detection
**Contains ads:** No · **In-app purchases:** No
**Contact email:** _<your support email>_ · **Website:** https://github.com/Sathya-github-del/tileops · **Privacy policy URL:** _<where you host privacy-policy.html>_

**Graphics in this folder:** `icon-512.png` (app icon), `feature-graphic-1024x500.png`, `screenshots/*.png` (8 phone screenshots, 766×1532, made with demo data only).
