# Setting up the TileOps companion

The companion is a small Python program that checks your servers every 5 minutes, 24/7, and pushes alerts
to your phone. Run it on any always-on Linux machine that can reach your servers: a Raspberry Pi, a home
server, a small VPS, or a spare old Android phone with a Linux environment.

## 1. Install
```sh
sudo apt install python3 python3-venv git          # Debian, Ubuntu, Raspberry Pi OS
git clone https://github.com/Sathya-github-del/tileops.git tileops && cd tileops
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp config.example.yaml config.yaml && chmod 600 config.yaml
```

## 2. Configure
Edit `config.yaml`:
- `bind_host`: this machine's LAN IP (e.g. `192.168.1.20`), so your phone can reach it.
- `public_url`: `http://<that IP>:8800` (it becomes `https://` automatically; TLS is on by default).
- `approval_pin`: the PIN that approves service restarts.
- Leave `servers:` empty: you can add servers from the app.

## 3. Run
```sh
.venv/bin/python -m companion -c config.yaml serve
```
On first start it prints a **QR code**, a **pairing link**, the **address**, a **pairing code** and the
**certificate fingerprint**. In the TileOps app choose **Always-on companion → Connect a companion** and
scan the QR (or paste the link, or type the address and code and compare the fingerprint).
Show them again later with `.venv/bin/python -m companion -c config.yaml pair`.

## 4. Keep it running
Example systemd user service (`~/.config/systemd/user/tileops.service`):
```ini
[Unit]
Description=TileOps companion
After=network-online.target

[Service]
WorkingDirectory=%h/tileops
ExecStart=%h/tileops/.venv/bin/python -m companion -c config.yaml serve
Restart=on-failure

[Install]
WantedBy=default.target
```
Then `systemctl --user enable --now tileops` (and `loginctl enable-linger $USER` so it runs without you being logged in).

## Notes
- Keep the pairing code private: it gives full access to the companion.
- Push alerts go through ntfy.sh under a random topic (only the alert title, never evidence). Subscribe to the topic in the ntfy app; set `ntfy: enabled: false` to turn this off.
- For servers behind a VPN, the companion's machine itself must be connected to that VPN.
