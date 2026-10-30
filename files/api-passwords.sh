#!/bin/sh
# Moves the Wazuh API's two users off their published default passwords.
# "applied" remembers the password in force, since the API wants the old one
# to set a new one. Passwords reach curl on stdin, never on a command line.
set -eu
dir=$1
url=https://127.0.0.1:55000
umask 077
applied=$dir/api-password.applied
[ -f "$dir/wazuh-wui-password" ] || printf 'Wui.%s' "$(openssl rand -hex 24)" > "$dir/wazuh-wui-password"

new=$(cat "$dir/api-password")
current=wazuh
[ ! -f "$applied" ] || current=$(cat "$applied")

token=$(printf 'user = "wazuh:%s"\n' "$current" | curl -sSfk -K - -X POST "$url/security/user/authenticate?raw=true")
set_password() {
  printf '{"password":"%s"}' "$2" | curl -sSfk -o /dev/null -X PUT -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' -d @- "$url/security/users/$1"
}

# wazuh-wui, user 2, goes first: changing wazuh, user 1, ends this token.
[ -f "$dir/wazuh-wui-password.applied" ] || {
  set_password 2 "$(cat "$dir/wazuh-wui-password")"
  touch "$dir/wazuh-wui-password.applied"
}
[ "$new" = "$current" ] || set_password 1 "$new"
cp "$dir/api-password" "$applied"
