# Local example

Applies circuit-wazuh to two throwaway containers with systemd: a Rocky Linux 10 server and a Rocky Linux 10 agent that enrolls with it. You need Conn3x and rootful Podman, and a machine with memory to spare, since the indexer alone takes 1 GB of heap here. Wazuh asks for 8 GiB on a real server.

```sh
export CONTAINER_CONNECTION=podman-machine-default-root   # on a Mac
./up.sh
export TF_VAR_admin_password='Pick-an-admin-pass1.'
export TF_VAR_api_password='Pick-an-api-pass1.'
export TF_VAR_enrollment_password="$(openssl rand -hex 16)"
conn3x init
conn3x apply
conn3x plan
```

The apply takes several minutes. The second plan says `No changes.` Keep the same `TF_VAR_enrollment_password` for every run.

To check that it all works, from the circuit's root:

```sh
ADMIN_PASSWORD="$TF_VAR_admin_password" API_PASSWORD="$TF_VAR_api_password" test/check.sh
```

That signs in to the API, finds the agent active, adds a file under `/etc` on the agent, asks for a scan and waits for the alert in the indexer. It prints the alert, with the compliance references Wazuh's rule attached.

To open the dashboard, forward its port over SSH and browse to `https://127.0.0.1:8443/`, signing in as `admin`. The certificate comes from the server's own CA, so the browser warns about it.

```sh
ssh -p 2222 -i id_ed25519 -o UserKnownHostsFile=known_hosts -L 8443:127.0.0.1:443 root@127.0.0.1
```

`up.sh` listens on `127.0.0.1:2222` and `2223`. Set `PORT` and `AGENT_PORT` to use others. Set `CONTAINERFILE` and `AGENT_CONTAINERFILE` to test other distros, such as the images in Conn3x's `test/images`, which CI uses. Podman on Linux needs `PODMAN="sudo podman"`.

`./down.sh` removes the containers, their volumes, the key and the state.
