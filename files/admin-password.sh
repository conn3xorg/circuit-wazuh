#!/bin/sh
# Sets admin's password through the security API, signed in with the admin
# certificate. It reaches curl on stdin, never on a command line. Runs as
# wazuh-indexer, with the password on file descriptor 3.
set -eu
export OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk
certs=/etc/wazuh-indexer/certs
hash=$(PW=$(cat <&3) /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -env PW | tail -n 1)
# The API answers 500 for a moment after a restart, while the security index loads.
for _ in $(seq 60); do
  printf '[{"op":"replace","path":"/hash","value":"%s"}]' "$hash" |
    curl -sSf -o /dev/null -X PATCH --cacert "$certs/root-ca.pem" --cert "$certs/admin.pem" --key "$certs/admin-key.pem" \
      -H 'Content-Type: application/json' -d @- https://127.0.0.1:9200/_plugins/_security/api/internalusers/admin && exit 0
  sleep 2
done
exit 1
