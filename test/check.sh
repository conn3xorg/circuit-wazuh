#!/usr/bin/env sh
# Checks a running server and agent: the API takes the right password and
# refuses a wrong one, the agent enrolled and is active, and a changed file
# on the agent turns into an alert in the indexer.
# Usage: PODMAN=... SERVER=name AGENT=name API_PASSWORD=... ADMIN_PASSWORD=... check.sh
set -eu
podman=${PODMAN:-podman}
server=${SERVER:-circuit-wazuh-server}
agent=${AGENT:-circuit-wazuh-agent}

id=$($podman exec -i -e API_PASSWORD="$API_PASSWORD" -e AGENT_NAME="$agent" "$server" sh -eu <<'INNER'
api=https://127.0.0.1:55000
[ "$(printf 'user = "wazuh:wrong-Password-1."\n' | curl -sk -K - -o /dev/null -w '%{http_code}' -X POST "$api/security/user/authenticate")" = 401 ]
[ "$(printf 'user = "wazuh:wazuh"\n' | curl -sk -K - -o /dev/null -w '%{http_code}' -X POST "$api/security/user/authenticate")" = 401 ]
token=$(printf 'user = "wazuh:%s"\n' "$API_PASSWORD" | curl -sSfk -K - -X POST "$api/security/user/authenticate?raw=true")
[ "$(printf 'user = "admin:admin"\n' | curl -sk -K - -o /dev/null -w '%{http_code}' https://127.0.0.1:9200/)" = 401 ]
for _ in $(seq 90); do
  out=$(curl -sSfk -H "Authorization: Bearer $token" "$api/agents?name=$AGENT_NAME&select=id,name,status,version")
  echo "$out" | grep -q '"status": *"active"' && break
  sleep 2
done
echo "$out" | grep -q '"status": *"active"' || { echo "$out" >&2; exit 1; }
echo "$out" >&2
echo "$out" | sed -n 's/.*"id": *"\([0-9]*\)".*/\1/p'
INNER
)
[ -n "$id" ]
echo "Agent $agent is active as $id."

# A file that appears during the agent's first scan only joins the baseline
# and raises no alert, so the file changes again on every try. An API token
# lasts 15 minutes, so each try signs in afresh.
marker=/etc/conn3x-fim-check-$$
for _ in $(seq 30); do
  $podman exec "$agent" sh -c "date >> $marker"
  if $podman exec -i -e API_PASSWORD="$API_PASSWORD" -e ADMIN_PASSWORD="$ADMIN_PASSWORD" -e ID="$id" -e MARKER="$marker" "$server" sh -eu <<'INNER'
api=https://127.0.0.1:55000
token=$(printf 'user = "wazuh:%s"\n' "$API_PASSWORD" | curl -sSfk -K - -X POST "$api/security/user/authenticate?raw=true")
curl -sSfk -o /dev/null -X PUT -H "Authorization: Bearer $token" "$api/syscheck?agents_list=$ID"
sleep 30
query="{\"size\":1,\"query\":{\"bool\":{\"must\":[{\"match\":{\"rule.groups\":\"syscheck\"}},{\"match_phrase\":{\"syscheck.path\":\"$MARKER\"}}]}}}"
out=$(printf 'user = "admin:%s"\n' "$ADMIN_PASSWORD" | curl -sk -K - -H 'Content-Type: application/json' -d "$query" "https://127.0.0.1:9200/wazuh-alerts-*/_search")
echo "$out" | grep -q "\"path\":\"$MARKER\"" || exit 1
echo "$out"
INNER
  then
    echo "The change to $marker reached the indexer as an alert."
    exit 0
  fi
done
echo "No alert for $marker reached the indexer." >&2
exit 1
