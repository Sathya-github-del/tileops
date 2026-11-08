# TileOps demo target: systemd-enabled Ubuntu 24.04 with sshd, nginx, cron, sudo.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive container=docker
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus openssh-server nginx cron sudo iproute2 procps python3 ca-certificates \
 && apt-get clean && rm -rf /var/lib/apt/lists/*
# Container-friendly systemd: drop units that make no sense without real hardware/ttys.
RUN systemctl mask systemd-udevd.service systemd-udevd-kernel.socket systemd-udevd-control.socket \
        getty.target console-getty.service systemd-logind.service sys-kernel-config.mount \
        sys-kernel-debug.mount sys-kernel-tracing.mount systemd-remount-fs.service \
 && systemctl disable ssh.socket 2>/dev/null || true
RUN systemctl enable ssh.service nginx.service cron.service \
 && mkdir -p /run/sshd
COPY tileops-read /usr/local/sbin/tileops-read
RUN chown root:root /usr/local/sbin/tileops-read && chmod 0755 /usr/local/sbin/tileops-read
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
