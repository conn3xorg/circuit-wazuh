# circuit-wazuh

A Conn3x circuit that runs [Wazuh](https://wazuh.com), the open-source security platform. One host runs the manager, the indexer and the dashboard together. Every other host runs the agent, which enrolls with the manager and starts reporting: files that changed, packages with known vulnerabilities, logins, whatever its rules catch. You get one place to ask what happened on your machines, in place of twenty log files.

The circuit installs a pinned 4.x release from Wazuh's own signed repositories. It makes a private CA on the server, so no key leaves that host, and it replaces every default password the packages ship with before anything listens off loopback. Passwords stay out of the plan and state.

## Compliance: what you get and what you don't

Wazuh maps what it finds to compliance frameworks. Here's a real alert from testing this circuit, rule 554, "File added to the system":

| Field on the alert | Framework | Values |
| --- | --- | --- |
| `rule.tsc` | SOC 2 Trust Services Criteria | `CC6.1`, `CC6.8`, `CC7.2`, `CC7.3`, `PI1.4`, `PI1.5` |
| `rule.hipaa` | HIPAA | `164.312.c.1`, `164.312.c.2` |
| `rule.pci_dss` | PCI DSS | `11.5` |
| `rule.nist_800_53` | NIST 800-53 | `SI.7` |
| `rule.gdpr` | GDPR | `II_5.1.f` |
| `rule.gpg13` | GPG 13 | `4.11` |

That's useful evidence for an auditor, and it's all it is. **Nothing here makes a host or a company compliant.** A framework asks for policies, people and processes that no module can install, and a tag on an alert only says which control the rule's authors thought it related to. Whether you meet SOC 2 or HIPAA is for you and your auditor to work out. The table lists the mappings we saw on that alert, not everything Wazuh's rules carry.

## Sizing

Wazuh is heavy, so check this before you pick a server. Its [quickstart](https://documentation.wazuh.com/current/quickstart.html) asks for this on an all-in-one host, with 90 days of alerts:

| Agents | CPU | Memory | Storage |
| --- | --- | --- | --- |
| 1-25 | 4 vCPU | 8 GiB | 50 GB |
| 26-50 | 8 vCPU | 8 GiB | 100 GB |
| 51-100 | 8 vCPU | 8 GiB | 200 GB |

Past 100 agents Wazuh recommends a distributed deployment, which this circuit doesn't build. We tested servers on DigitalOcean's `s-4vcpu-8gb`, which meets the first row. With two agents, about 5.8 GB of its memory was in use and 19 GB of disk, operating system included. Agents are light: `s-1vcpu-1gb` was plenty.

## Usage

```hcl
variable "wazuh_admin_password" {
  type      = string
  ephemeral = true
  sensitive = true
}

variable "wazuh_api_password" {
  type      = string
  ephemeral = true
  sensitive = true
}

variable "wazuh_enrollment_password" {
  type      = string
  ephemeral = true
  sensitive = true
}

module "wazuh" {
  source = "github.com/conn3xorg/circuit-wazuh?ref=v0.1.1"

  server               = { siem = "203.0.113.10" }
  agents               = { web1 = "203.0.113.21", web2 = "203.0.113.22", db1 = "203.0.113.30" }
  ssh_private_key_file = "~/.ssh/id_ed25519"

  admin_password      = var.wazuh_admin_password
  api_password        = var.wazuh_api_password
  enrollment_password = var.wazuh_enrollment_password
}
```

Then run `conn3x init` and `conn3x apply`, with the three values in `TF_VAR_wazuh_admin_password`, `TF_VAR_wazuh_api_password` and `TF_VAR_wazuh_enrollment_password`. The first apply took about seven minutes on our droplets, most of it package downloads. A second `conn3x plan` says `No changes.`

Agents need to reach the server on ports 1514 and 1515, and nobody else needs to. The circuit doesn't open them, so if you have a firewall, [circuit-firewall](https://github.com/conn3xorg/circuit-firewall) can. When agents reach the server by another address, such as a private one, set `manager_address`.

To try it on throwaway containers first, see [examples/local](examples/local).

### The dashboard

It listens on `127.0.0.1:443`, with a certificate from the server's own CA. Reach it through an SSH tunnel, or put a proxy on the same host in front of it.

```sh
ssh -L 8443:127.0.0.1:443 root@203.0.113.10
```

Then browse to `https://127.0.0.1:8443/` and sign in as `admin`. Your browser will warn about the certificate. To listen on the network directly, set `dashboard_address = "0.0.0.0"`.

### The API

The Wazuh API listens on `127.0.0.1:55000`, and `wazuh` is its administrator. From the server:

```sh
TOKEN=$(curl -sk -u wazuh:"$API_PASSWORD" -X POST 'https://127.0.0.1:55000/security/user/authenticate?raw=true')
curl -sk -H "Authorization: Bearer $TOKEN" 'https://127.0.0.1:55000/agents?select=name,status,version'
```

Set `api_address = "0.0.0.0"` to reach it from elsewhere.

### Seeing it work

Agents scan files every 12 hours by default, and what they find in their very first scan only becomes the baseline, without an alert. So give a new agent a few minutes, then add a file under `/etc` on it and ask for a scan through the API:

```sh
curl -sk -X PUT -H "Authorization: Bearer $TOKEN" 'https://127.0.0.1:55000/syscheck'
```

An alert turns up a minute or so later, in the dashboard and in `wazuh-alerts-*` in the indexer. Vulnerability detection needs no prompting. It downloads its feed and compares each agent's packages against it, and the results land in `wazuh-states-vulnerabilities-*`: we saw 1,338 entries and 3,940 on our two test sets, shortly after the first apply.

### What stays on the server, and what reaches state

`admin_password`, `api_password` and `enrollment_password` are ephemeral. They reach the hosts in write-only files, and the plan and state record only an HMAC. `enrollment_password` also sits in `/var/ossec/etc/authd.pass` on every agent, owned by the `wazuh` user and readable by it and its group, because that's where the agent reads it.

The server makes everything else itself, and keeps it in `/etc/conn3x/wazuh`, readable by root only:

- A private CA and certificates for the indexer, Filebeat and the dashboard, each good for ten years. Nothing renews them. Wazuh's own `wazuh-certs-tool.sh` isn't used, so the circuit doesn't have to run a downloaded script that changes under it.
- Random passwords for `kibanaserver`, which the dashboard signs in to the indexer with, and `wazuh-wui`, which it signs in to the API with.

The indexer package ships demo users with published passwords. The circuit removes them before the security index is first made, leaving `admin` and `kibanaserver`. `wazuh-passwords-tool.sh` expects the demo users and may complain about them. Use the inputs to change passwords instead. Enrollment without the right password is refused.

### Keeping versions together

An agent must not be newer than its manager, and Wazuh warns that upgrading one part alone can break the rest. On Debian and Ubuntu an apt pin keeps `apt upgrade` from moving anything. **The Red Hat family has no such pin**: `dnf upgrade` will take Wazuh's packages to the newest 4.x. Exclude `wazuh-*` and `filebeat` from whatever updates those hosts.

To upgrade, raise `wazuh_version`. The server goes first, then the agents. If Wazuh changed its Filebeat template in that release, `filebeat_template_sha256` has to change too, and the download fails until it does.

Wazuh's repository signing key, in `files/wazuh-release.asc`, expires on 15 May 2027. A new key needs a new release of this circuit.

## What it does

On the server, in order:

1. Adds Wazuh's repository and installs `wazuh-indexer`, `wazuh-manager`, Wazuh's build of `filebeat` and `wazuh-dashboard` at pinned versions.
2. Makes the CA and certificates once, and copies them to each part.
3. Binds the indexer to `127.0.0.1`, sets its heap, starts it, replaces the demo users and sets the `admin` password.
4. Turns on password enrollment, points the manager at the indexer, sets the API's address, starts the manager, and sets the API's passwords.
5. Writes Filebeat's config, downloads Wazuh's template and module and checks their SHA-256, and starts Filebeat, which carries alerts to the indexer.
6. Configures the dashboard, starts it, and waits for its login page.

On each agent, once the server is ready:

1. Adds the repository and installs `wazuh-agent` at the pinned version.
2. Sets the manager's address, writes the enrollment password, and starts the agent, which enrolls itself under the host's hostname.

### What it doesn't do

- It doesn't build a distributed deployment or a manager cluster. The indexer stays on loopback.
- It doesn't run the server on Debian or Fedora. Wazuh's list for the central components is Ubuntu, Amazon Linux and the Red Hat family, and the circuit stops with a message on anything else. Both work as agents.
- It doesn't let the server be an agent too. Wazuh's two packages conflict, and the manager already watches its own host, as agent `000`.
- It doesn't turn on realtime file monitoring, change which rules run, or send email. All of that is in `ossec.conf`, which the circuit only edits line by line.
- It doesn't install agents on Windows or macOS.
- It doesn't back up the indexer or expire old alerts.
- Two agents with the same hostname will fight over one enrollment. Give them different hostnames.
- Deleting an agent from `agents` leaves it installed and reporting. Deleting the module leaves everything as it was.

## Inputs

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `server` | any | Required | The server, as a map of one name to an address, such as `{ siem = "203.0.113.10" }`, or to a host object such as `{ address = "203.0.113.10", host_key = "ssh-ed25519 AAAA..." }`. A host object can also set `user`, `port`, `private_key_file`, `jump_hosts` and `os`, the distribution's ID, which a host created in the same plan needs. |
| `agents` | any | `{}` | Agents, by name, in the same form as `server`. The server can't be one. |
| `admin_password` | string | Required | Password of `admin`, who signs in to the dashboard and the indexer. 8 to 64 characters of letters, digits and `. * + ? -`, with at least one uppercase letter, lowercase letter, digit and symbol. Ephemeral and sensitive. Changing it sets the new one. |
| `api_password` | string | Required | Password of `wazuh`, the API's administrator, under the same rules. Ephemeral and sensitive. Changing it sets the new one. |
| `enrollment_password` | string | Required | Shared secret agents present to enroll, at least 8 of letters, digits, `+`, `/`, `=`, `_` and `-`, such as the output of `openssl rand -hex 16`. Ephemeral and sensitive. |
| `wazuh_version` | string | `"4.14.9"` | Wazuh 4.x release for the server and the agents. |
| `filebeat_template_sha256` | string | 4.14.9's | SHA-256 of `extensions/elasticsearch/7.x/wazuh-template.json` in the Wazuh source at `wazuh_version`. |
| `manager_address` | string | `null` | Address or name agents reach the manager on. When null, the server's address. |
| `dashboard_address` | string | `"127.0.0.1"` | Address the dashboard listens on. |
| `dashboard_port` | number | `443` | Port of the dashboard. |
| `api_address` | string | `"127.0.0.1"` | Address the API, on port 55000, listens on. |
| `indexer_heap` | string | `"4g"` | JVM heap of the indexer. Wazuh advises half the host's memory, and no more than 32g. |
| `ssh_user` | string | `"root"` | User to log in as. |
| `ssh_port` | number | `22` | SSH port. |
| `ssh_private_key_file` | string | `null` | Path to a private key. When null, Conn3x uses the SSH agent. |
| `ssh_known_hosts_file` | string | `null` | known_hosts file to check host keys against. When null, `~/.ssh/known_hosts`. Not used for a host object with `host_key`. |
| `ssh_become` | bool | `false` | Run commands as root through sudo. Set it when `ssh_user` isn't root. |

## Outputs

| Name | Description |
| --- | --- |
| `manager_address` | Address the agents reach the manager on. |
| `dashboard_url` | URL of the dashboard, such as `https://127.0.0.1:443/`, from the server itself when it listens on loopback. |

## Requirements

Requires Conn3x v0.6.9 or later and systemd on each host, with outbound HTTPS to packages.wazuh.com, and from the server to raw.githubusercontent.com. Wazuh's packages exist for amd64 and arm64.

## Tested on

Wazuh 4.14.9. Containers on arm64 (Podman, 8 GiB shared machine, 1 GB indexer heap): a server and an agent in two containers for Ubuntu 24.04 server with Debian 13 agent, Ubuntu 24.04 server with Rocky Linux 10 agent, Rocky Linux 10 server with Fedora 45 agent, and Rocky Linux 10 server with Ubuntu 24.04 agent. Each applied, had a clean second plan, and passed [test/check.sh](test/check.sh): the API refused a wrong password and the default one, took the right one, showed the agent active, and a changed file on the agent reached the indexer as an alert. The indexer runs fine in a container, so CI runs that same matrix on amd64, adding a dashboard sign-in, a password change by a second apply, and a check that state holds no secrets. On Ubuntu 24.04 containers we ran those by hand too: the old passwords got 401 and state had none of them.

Those four pairs also ran the whole CI job on arm64 containers against hosts first applied at v0.1.0 and then moved to this version. All of it ran on Conn3x v0.6.11 and on a newer development build. The move hasn't been run on a droplet.

CI can't show you what only real hosts did. On DigitalOcean, with `s-4vcpu-8gb` servers and `s-1vcpu-1gb` agents: an Ubuntu 24.04 server with Debian 13 and Rocky Linux 10 agents, and a Rocky Linux 10 server, SELinux enforcing, with Ubuntu 24.04 and Fedora 44 agents (DigitalOcean has no Fedora 45 image). Every agent showed active, file integrity alerts arrived from each, vulnerability detection filled its index, the dashboard took the admin's password, and a wrong enrollment password was refused on a container pair. From outside, 9200, 55000 and 443 were closed, and 1514 and 1515 open. After rebooting all of them, the plan had no changes and the checks passed again. On Rocky Linux the services ran as `unconfined_service_t` with no denials in the audit log. Upgrading an Ubuntu 24.04 server and a Rocky Linux 10 agent from 4.14.8 to 4.14.9 by raising `wazuh_version` also worked, with a clean plan and a new alert after it.

Not tested: Amazon Linux, RHEL or other Red Hat family servers, arm64 droplets, and more than two agents on one server.

## License

MPL-2.0. See [LICENSE](LICENSE). Wazuh itself is GPL-2.0.
