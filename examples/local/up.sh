#!/usr/bin/env sh
# Starts two throwaway hosts Conn3x can configure: NAME-server on
# 127.0.0.1:$PORT (default 2222) and NAME-agent on 127.0.0.1:$AGENT_PORT
# (default PORT+1), with a fresh SSH key, their host keys in ./known_hosts
# and the ports and the server's container address in ./terraform.tfvars.
# CONTAINERFILE picks another image for the server, AGENT_CONTAINERFILE for
# the agent, such as Conn3x's test images.
# Needs rootful Podman, so the two containers can reach each other:
# CONTAINER_CONNECTION=podman-machine-default-root on a Mac, or
# PODMAN="sudo podman" on Linux.
set -eu
cd "$(dirname "$0")"
port=${PORT:-2222}
agent_port=${AGENT_PORT:-$((port + 1))}
containerfile=${CONTAINERFILE:-Containerfile}
agent_containerfile=${AGENT_CONTAINERFILE:-$containerfile}
name=${NAME:-circuit-wazuh}

podman=${PODMAN:-podman}
[ -f id_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -C "$name" -f id_ed25519
: > known_hosts

start() { # role, port, containerfile
  $podman build -q -f "$3" -t "$name-$1" "$(dirname "$3")" >/dev/null
  $podman rm -f -v "$name-$1" >/dev/null 2>&1 || true
  $podman run -d --name "$name-$1" --hostname "$name-$1" --systemd=always \
    -p "127.0.0.1:$2:22" "$name-$1" >/dev/null
  $podman exec -i "$name-$1" sh -c 'cat > /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys' < id_ed25519.pub
  $podman exec "$name-$1" timeout 60 systemctl is-system-running --wait >/dev/null 2>&1 || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    keys=$(ssh-keyscan -p "$2" 127.0.0.1 2>/dev/null) && [ -n "$keys" ] && { echo "$keys" >> known_hosts; return 0; }
    sleep 1
  done
  echo "The container started, but SSH didn't answer on 127.0.0.1:$2." >&2
  exit 1
}

start server "$port" "$containerfile"
start agent "$agent_port" "$agent_containerfile"

cat > terraform.tfvars <<VARS
port       = $port
agent_port = $agent_port
server_ip  = "$($podman inspect -f '{{.NetworkSettings.IPAddress}}' "$name-server")"
VARS
echo "Ready on 127.0.0.1:$port and 127.0.0.1:$agent_port. Now run: conn3x init && conn3x apply"
