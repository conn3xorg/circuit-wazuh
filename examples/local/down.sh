#!/usr/bin/env sh
# Removes the containers and everything up.sh and Conn3x created here.
set -eu
cd "$(dirname "$0")"
name=${NAME:-circuit-wazuh}
${PODMAN:-podman} rm -f -v "$name-server" "$name-agent" >/dev/null 2>&1 || true
rm -rf id_ed25519 id_ed25519.pub known_hosts terraform.tfvars .terraform .terraform.lock.hcl terraform.tfstate terraform.tfstate.backup
echo "Removed."
