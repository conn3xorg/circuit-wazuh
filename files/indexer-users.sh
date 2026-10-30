#!/bin/sh
# Replaces the package's demo users, whose passwords are public, before the
# security index is first made. Only the two users Wazuh needs stay. admin
# gets a random password here and its real one in the next step.
set -eu
dir=$1
export OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk
hash=/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh
umask 077
[ -f "$dir/kibanaserver-password" ] || openssl rand -hex 24 > "$dir/kibanaserver-password"
admin=$(PW=$(openssl rand -hex 24) "$hash" -env PW | tail -n 1)
kibana=$(PW=$(cat "$dir/kibanaserver-password") "$hash" -env PW | tail -n 1)
cat > /etc/wazuh-indexer/opensearch-security/internal_users.yml <<YAML
---
_meta:
  type: "internalusers"
  config_version: 2
admin:
  hash: "$admin"
  reserved: true
  backend_roles:
  - "admin"
  description: "Administrator"
kibanaserver:
  hash: "$kibana"
  reserved: true
  description: "The dashboard's own user"
YAML
chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/opensearch-security/internal_users.yml
chmod 600 /etc/wazuh-indexer/opensearch-security/internal_users.yml

# On a node that has only just started, the init can report success before
# the security index has loaded, so it counts only once the API answers.
certs=/etc/wazuh-indexer/certs
for _ in 1 2 3 4 5; do
  /usr/share/wazuh-indexer/bin/indexer-security-init.sh -ho 127.0.0.1 >/dev/null || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    curl -sf -o /dev/null --cacert "$certs/root-ca.pem" --cert "$certs/admin.pem" --key "$certs/admin-key.pem" \
      https://127.0.0.1:9200/_plugins/_security/api/internalusers/admin && exit 0
    sleep 3
  done
done
echo "The indexer's security index didn't load." >&2
exit 1
