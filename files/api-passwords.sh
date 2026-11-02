#!/bin/sh
# Moves the Wazuh API's two users off their published default passwords.
# "applied" remembers the password in force, since the API wants the old one
# to set a new one. Passwords and the token reach curl on stdin or a file
# descriptor, never on a command line, and only a port held by root or the
# wazuh user gets them. That narrows the window, since the API could stop between
# the check and the send. What closes it is checking the certificate the API made
# for itself, which names localhost.
set -eu
dir=$1
url=https://localhost:55000
tls="--cacert /var/ossec/api/configuration/ssl/server.crt --resolve localhost:55000:127.0.0.1"
umask 077
applied=$dir/api-password.applied
[ -f "$dir/wazuh-wui-password" ] || printf 'Wui.%s' "$(openssl rand -hex 24)" > "$dir/wazuh-wui-password"

held() {
  p=$(printf ':%04X$' 55000)
  u=$(id -u wazuh)
  cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk -v p="$p" -v u="$u" \
    '$4 == "0A" && $2 ~ p { n++; if ($8 != u && $8 != 0) b = 1 } END { exit !(n && !b) }'
}
held_or_stop() { held || { echo "Port 55000 isn't held by the Wazuh API, so the password wasn't sent." >&2; exit 1; }; }

new=$(cat "$dir/api-password")
current=wazuh
[ ! -f "$applied" ] || current=$(cat "$applied")

held_or_stop
token=$(printf 'user = "wazuh:%s"\n' "$current" | curl -sSf $tls -K - -X POST "$url/security/user/authenticate?raw=true")
set_password() {
  held_or_stop
  printf 'header = "Authorization: Bearer %s"\n' "$token" | curl -sSf $tls -o /dev/null -X PUT -K - \
    -H 'Content-Type: application/json' -d @/dev/fd/3 "$url/security/users/$1" 3<<JSON
{"password":"$2"}
JSON
}

# wazuh-wui, user 2, goes first: changing wazuh, user 1, ends this token.
[ -f "$dir/wazuh-wui-password.applied" ] || {
  set_password 2 "$(cat "$dir/wazuh-wui-password")"
  touch "$dir/wazuh-wui-password.applied"
}
[ "$new" = "$current" ] || set_password 1 "$new"
cp "$dir/api-password" "$applied"
