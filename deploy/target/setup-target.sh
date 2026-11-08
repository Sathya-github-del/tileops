#!/usr/bin/env bash
# Recreate the TileOps demo target container (systemd Ubuntu 24.04).
# Usage: deploy/target/setup-target.sh [LAN_IP] [PUBKEY] [SERVICES...]
#   LAN_IP   default: first 192.168.x address of this host
#   PUBKEY   default: secrets/target_ed25519.pub
#   SERVICES services the tileops user may `systemctl restart/status` (default: nginx)
set -euo pipefail
cd "$(dirname "$0")/../.."
LAN_IP="${1:-$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | grep '^192\.168\.' | head -n1)}"
PUBKEY="${2:-secrets/target_ed25519.pub}"
shift $(( $# >= 2 ? 2 : $# )) || true
SERVICES=("${@:-nginx}")
[ ${#SERVICES[@]} -eq 0 ] && SERVICES=(nginx)
NAME=tileops-target
IMAGE=tileops-target:latest

for s in "${SERVICES[@]}"; do
  [[ "$s" =~ ^[A-Za-z0-9@._-]+$ ]] || { echo "bad service name: $s" >&2; exit 1; }
done

echo "[*] building $IMAGE"
docker build -q -t "$IMAGE" deploy/target >/dev/null

if docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
  echo "[*] removing old $NAME"; docker rm -f "$NAME" >/dev/null
fi

# cgroup v2 host: systemd needs a writable cgroup tree. We use host cgroupns + rw bind
# (systemd only manages its own docker-<id>.scope subtree). No --privileged.
echo "[*] starting $NAME (ssh $LAN_IP:2222, http $LAN_IP:8088)"
docker run -d --name "$NAME" --hostname "$NAME" --restart unless-stopped \
  --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --tmpfs /run --tmpfs /run/lock \
  -p "$LAN_IP:2222:22" -p "$LAN_IP:8088:80" \
  "$IMAGE" >/dev/null

for i in $(seq 1 30); do
  st=$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)
  case "$st" in running|degraded) break ;; esac
  sleep 1
done
echo "[*] systemd state: $st"

SS=$(docker exec "$NAME" sh -c 'command -v ss')
SYSTEMCTL=$(docker exec "$NAME" sh -c 'command -v systemctl')
SUDOERS="Defaults:tileops !requiretty
Defaults:tileops env_reset
# TileOps: exact read-only commands + restart/status of allowlisted services only.
tileops ALL=(root) NOPASSWD: /usr/local/sbin/tileops-read crontabs, /usr/local/sbin/tileops-read authorized-keys, $SS -tlnpH"
for s in "${SERVICES[@]}"; do
  SUDOERS+=", $SYSTEMCTL status --no-pager $s, $SYSTEMCTL restart $s"
done

docker exec -i "$NAME" bash -s <<INNER
set -e
id tileops >/dev/null 2>&1 || useradd -m -s /bin/bash tileops
passwd -l tileops >/dev/null
install -d -m 700 -o tileops -g tileops /home/tileops/.ssh
cat > /home/tileops/.ssh/authorized_keys <<'K'
$(cat "$PUBKEY")
K
chown tileops:tileops /home/tileops/.ssh/authorized_keys; chmod 600 /home/tileops/.ssh/authorized_keys
cat > /etc/sudoers.d/tileops <<'S'
$SUDOERS
S
chmod 440 /etc/sudoers.d/tileops
visudo -cf /etc/sudoers.d/tileops >/dev/null
cat > /etc/ssh/sshd_config.d/10-tileops.conf <<'C'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
C
systemctl restart ssh
mkdir -p /var/www/html
INNER
echo "[*] done. test: ssh -i secrets/target_ed25519 -p 2222 -o UserKnownHostsFile=secrets/known_hosts tileops@$LAN_IP"
