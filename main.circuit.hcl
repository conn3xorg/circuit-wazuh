# Facts give each host's distribution, which picks Wazuh's apt or yum
# repository. Wazuh lists fewer systems for the server than it does for agents.
data "conn3x_host" "facts" {
  for_each = merge(var.server, var.agents)

  ssh {
    host             = try(each.value.address, each.value)
    host_key         = try(each.value.host_key, null)
    user             = try(each.value.user, var.ssh_user)
    port             = try(each.value.port, var.ssh_port)
    private_key_file = try(each.value.private_key_file, var.ssh_private_key_file)
    jump_hosts       = try(each.value.jump_hosts, null)
    known_hosts_file = var.ssh_known_hosts_file
  }

  lifecycle {
    postcondition {
      condition     = try(each.value.os, self.os_id) == self.os_id
      error_message = "Host ${each.key} is ${self.os_id}, not the ${try(each.value.os, "")} its os says."
    }
    postcondition {
      condition     = !contains(keys(var.server), each.key) || contains(["ubuntu", "rocky", "almalinux", "rhel", "amzn"], self.os_id)
      error_message = "Host ${each.key} is ${self.os_id}. This circuit runs Wazuh's central components on Ubuntu, Amazon Linux, Rocky Linux, AlmaLinux or RHEL. It can still run the agent."
    }
  }
}

locals {
  # A host object's os stands in for the facts of a host created in the
  # same plan, which can't be read until it exists.
  hosts     = merge(var.server, var.agents)
  os        = { for name, h in local.hosts : name => try(h.os, data.conn3x_host.facts[name].os_id) }
  family    = { for name, o in local.os : name => contains(["debian", "ubuntu"], o) ? "debian" : "redhat" }
  deb_hosts = { for name, h in local.hosts : name => h if local.family[name] == "debian" }

  package_version = "${var.wazuh_version}-1"
  # Wazuh's build of Filebeat, the only one its module and template work with.
  filebeat_version = "7.10.2-2"
  module_url       = "https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.5.tar.gz"
  module_sha256    = "7a8c67c47b22f89ab271b7e35f108f18b2215b7aa411cdd23c9994393070d38d"

  server_name     = keys(var.server)[0]
  server_address  = try(var.server[local.server_name].address, var.server[local.server_name])
  manager_address = coalesce(var.manager_address, local.server_address)
  dashboard_url = format("https://%s:%d/",
    contains(["0.0.0.0", "::"], var.dashboard_address) ? local.server_address : var.dashboard_address,
  var.dashboard_port)

  # Root's alone: passwords and the CA's private key.
  dir      = "/etc/conn3x/wazuh"
  certs    = "${local.dir}/certs"
  repo_key = file("${path.module}/files/wazuh-release.asc")
  repo_url = "https://packages.wazuh.com/4.x"

  sans = join(",", concat(
    ["DNS:localhost", "IP:127.0.0.1"],
    [can(cidrhost("${local.server_address}/32", 0)) ? "IP:${local.server_address}" : "DNS:${local.server_address}"],
  ))

  ossec = "/var/ossec/etc/ossec.conf"

  # The dashboard's Wazuh plugin reads this. The password in it is random and
  # made on the host, so the file is built there rather than in a step's
  # content, which would put it in state.
  wazuh_yml = "/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"

  # Replaces a certs directory with what's on stdin, as the directory's owner.
  unpack_certs = "set -e; [ -L \"$1\" ] || [ ! -d \"$1\" ] || chmod 700 \"$1\"; rm -rf \"$1\"; mkdir -m 700 \"$1\"; tar --no-same-owner -xf - -C \"$1\"; chmod 400 \"$1\"/*; chmod 500 \"$1\""
}

# Debian and Ubuntu stay on the circuit's version through apt upgrade, since
# Wazuh warns that an upgrade of one part alone can break the rest. A pin
# rather than apt-mark hold: Conn3x reads a held package as not installed.
circuit "wazuh_pin" {
  hosts = local.deb_hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  step "pin" {
    file {
      path    = "/etc/apt/preferences.d/wazuh"
      content = "Package: wazuh-*\nPin: version ${local.package_version}\nPin-Priority: 1001\n\nPackage: filebeat\nPin: version ${local.filebeat_version}\nPin-Priority: 1001\n"
    }
  }
}

circuit "wazuh_server" {
  hosts = var.server

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  # One repository serves every 4.x release. Its signing key expires on
  # 15 May 2027.
  step "repo" {
    repository {
      name       = "wazuh"
      url        = local.family[each.key] == "debian" ? "${local.repo_url}/apt" : "${local.repo_url}/yum"
      key        = local.repo_key
      suites     = local.family[each.key] == "debian" ? ["stable"] : null
      components = ["main"]
    }
  }

  step "tools" {
    for_each = toset(["curl", "openssl", "tar"])
    package {
      name = item.value
    }
  }

  step "indexer_package" {
    package {
      name    = "wazuh-indexer"
      version = local.package_version
    }
  }

  step "manager_package" {
    package {
      name    = "wazuh-manager"
      version = local.package_version
    }
  }

  step "filebeat_package" {
    package {
      name    = "filebeat"
      version = local.filebeat_version
    }
  }

  step "dashboard_package" {
    package {
      name    = "wazuh-dashboard"
      version = local.package_version
    }
  }

  step "dir" {
    directory {
      path = local.dir
      mode = "0700"
    }
  }

  # Write-only: the plan and state record only an HMAC of each.
  step "admin_password" {
    file {
      path       = "${local.dir}/admin-password"
      content_wo = var.admin_password
      mode       = "0600"
    }
  }

  step "api_password" {
    file {
      path       = "${local.dir}/api-password"
      content_wo = var.api_password
      mode       = "0600"
    }
  }

  step "scripts" {
    for_each = toset(["make-certs.sh", "indexer-users.sh", "admin-password.sh", "api-passwords.sh"])
    file {
      path    = "${local.dir}/${item.value}"
      content = file("${path.module}/files/${item.value}")
      mode    = "0700"
    }
  }

  # Once only: a new CA would have the parts stop trusting each other.
  step "certs" {
    command {
      command = "${local.dir}/make-certs.sh ${local.certs} '${local.sans}'"
      creates = "${local.certs}/root-ca.pem"
    }
  }

  # Each part gets its own copy under the names its package's config expects.
  step "deploy_certs" {
    command {
      # The indexer and the dashboard own their config directories, so they
      # unpack their own copies. Filebeat's is root's.
      command = <<-EOT
        set -e
        cd ${local.certs}
        tar -cf - indexer.pem indexer-key.pem admin.pem admin-key.pem root-ca.pem | runuser -u wazuh-indexer -- sh -c '${local.unpack_certs}' sh /etc/wazuh-indexer/certs
        install -d -m 500 /etc/filebeat/certs
        install -m 400 filebeat.pem filebeat-key.pem root-ca.pem /etc/filebeat/certs/
        tar -cf - dashboard.pem dashboard-key.pem root-ca.pem | runuser -u wazuh-dashboard -- sh -c '${local.unpack_certs}' sh /etc/wazuh-dashboard/certs
      EOT
      triggers = {
        certs     = conn3x_command.wazuh_server__certs[each.key].revision
        indexer   = conn3x_package.wazuh_server__indexer_package[each.key].revision
        filebeat  = conn3x_package.wazuh_server__filebeat_package[each.key].revision
        dashboard = conn3x_package.wazuh_server__dashboard_package[each.key].revision
      }
    }
  }

  # The indexer has no business off this host: the manager, Filebeat and the
  # dashboard all reach it on loopback. The package's default is every address.
  step "indexer_address" {
    line {
      path   = "/etc/wazuh-indexer/opensearch.yml"
      regexp = "^network\\.host:"
      line   = "network.host: \"127.0.0.1\""
    }
  }

  step "heap_min" {
    line {
      path   = "/etc/wazuh-indexer/jvm.options"
      regexp = "^-Xms"
      line   = "-Xms${var.indexer_heap}"
    }
  }

  step "heap_max" {
    line {
      path   = "/etc/wazuh-indexer/jvm.options"
      regexp = "^-Xmx"
      line   = "-Xmx${var.indexer_heap}"
    }
  }

  # A step rather than a handler, so the steps below talk to the new one.
  step "indexer_restart" {
    command {
      command = "systemctl daemon-reload && systemctl restart wazuh-indexer"
      triggers = {
        package = conn3x_package.wazuh_server__indexer_package[each.key].revision
        certs   = conn3x_command.wazuh_server__deploy_certs[each.key].revision
        address = conn3x_line.wazuh_server__indexer_address[each.key].revision
        min     = conn3x_line.wazuh_server__heap_min[each.key].revision
        max     = conn3x_line.wazuh_server__heap_max[each.key].revision
      }
    }
  }

  step "indexer_running" {
    service {
      name    = "wazuh-indexer"
      state   = "started"
      enabled = true
    }
  }

  step "indexer_ready" {
    command {
      command  = "for _ in $(seq 120); do [ \"$(curl -sk -o /dev/null -w '%%{http_code}' https://127.0.0.1:9200/)\" != 000 ] && exit 0; sleep 2; done; exit 1"
      triggers = { restart = conn3x_command.wazuh_server__indexer_restart[each.key].revision }
    }
  }

  # Once only: running it again would throw away users and roles made since.
  step "indexer_security" {
    command {
      command = <<-EOT
        set -e
        (umask 077; [ -f ${local.dir}/kibanaserver-password ] || openssl rand -hex 24 > ${local.dir}/kibanaserver-password)
        cd /
        runuser -u wazuh-indexer -- sh -s 3< ${local.dir}/kibanaserver-password < ${local.dir}/indexer-users.sh
        touch ${local.dir}/indexer-security-done
      EOT
      creates = "${local.dir}/indexer-security-done"
    }
  }

  step "indexer_admin" {
    command {
      command = "cd / && runuser -u wazuh-indexer -- sh -s 3< ${local.dir}/admin-password < ${local.dir}/admin-password.sh"
      triggers = {
        security = conn3x_command.wazuh_server__indexer_security[each.key].revision
        password = conn3x_file.wazuh_server__admin_password[each.key].revision
      }
    }
  }

  # Without this file and the use_password below, anyone who can reach port
  # 1515 can enroll an agent.
  step "enrollment_password" {
    file {
      path       = "/var/ossec/etc/authd.pass"
      content_wo = var.enrollment_password
      owner      = "wazuh"
      group      = "wazuh"
      mode       = "0640"
    }
  }

  # The package gives /var/ossec/etc to the wazuh user but leaves ossec.conf
  # with root. An edit replaces the file from inside the directory, so the
  # two need one owner. A package upgrade can put root back.
  step "ossec_owner" {
    command {
      command  = "chown -h wazuh ${local.ossec}"
      unless   = "[ \"$(stat -c %U ${local.ossec})\" = wazuh ]"
      triggers = { package = conn3x_package.wazuh_server__manager_package[each.key].revision }
    }
  }

  step "use_password" {
    line {
      path   = local.ossec
      regexp = "<use_password>"
      line   = "    <use_password>yes</use_password>"
    }
  }

  step "manager_indexer" {
    line {
      path   = local.ossec
      regexp = "<host>https://[^<]*:9200</host>"
      line   = "      <host>https://127.0.0.1:9200</host>"
    }
  }

  step "api_host" {
    line {
      path   = "/var/ossec/api/configuration/api.yaml"
      regexp = "^#? *host:"
      line   = "host: ['${var.api_address}']"
    }
  }

  # The manager reads the indexer's credentials from its keystore to write
  # vulnerability state. The password stays off the command line.
  step "manager_keystore" {
    command {
      command = "printf admin | /var/ossec/bin/wazuh-keystore -f indexer -k username && /var/ossec/bin/wazuh-keystore -f indexer -k password -vp ${local.dir}/admin-password"
      triggers = {
        package  = conn3x_package.wazuh_server__manager_package[each.key].revision
        password = conn3x_file.wazuh_server__admin_password[each.key].revision
      }
    }
  }

  step "manager_restart" {
    command {
      command = "systemctl daemon-reload && systemctl restart wazuh-manager"
      triggers = {
        package    = conn3x_package.wazuh_server__manager_package[each.key].revision
        enrollment = conn3x_file.wazuh_server__enrollment_password[each.key].revision
        use        = conn3x_line.wazuh_server__use_password[each.key].revision
        indexer    = conn3x_line.wazuh_server__manager_indexer[each.key].revision
        api        = conn3x_line.wazuh_server__api_host[each.key].revision
        keystore   = conn3x_command.wazuh_server__manager_keystore[each.key].revision
      }
    }
  }

  step "manager_running" {
    service {
      name    = "wazuh-manager"
      state   = "started"
      enabled = true
    }
  }

  step "api_ready" {
    command {
      command  = "for _ in $(seq 120); do [ \"$(curl -sk -o /dev/null -w '%%{http_code}' https://127.0.0.1:55000/)\" = 401 ] && exit 0; sleep 2; done; exit 1"
      triggers = { restart = conn3x_command.wazuh_server__manager_restart[each.key].revision }
    }
  }

  step "api_passwords" {
    command {
      command = "${local.dir}/api-passwords.sh ${local.dir}"
      triggers = {
        ready    = conn3x_command.wazuh_server__api_ready[each.key].revision
        password = conn3x_file.wazuh_server__api_password[each.key].revision
      }
    }
  }

  step "filebeat_config" {
    file {
      path    = "/etc/filebeat/filebeat.yml"
      content = file("${path.module}/files/filebeat.yml")
      mode    = "0600"
    }
  }

  step "filebeat_template" {
    download {
      url    = "https://raw.githubusercontent.com/wazuh/wazuh/v${var.wazuh_version}/extensions/elasticsearch/7.x/wazuh-template.json"
      sha256 = var.filebeat_template_sha256
      dest   = "/etc/filebeat/wazuh-template.json"
      mode   = "0644"
    }
  }

  step "filebeat_module_archive" {
    download {
      url    = local.module_url
      sha256 = local.module_sha256
      dest   = "/etc/filebeat/wazuh-filebeat.tar.gz"
    }
  }

  step "filebeat_module" {
    command {
      command = "tar -xzf /etc/filebeat/wazuh-filebeat.tar.gz -C /usr/share/filebeat/module"
      creates = "/usr/share/filebeat/module/wazuh/module.yml"
    }
  }

  step "filebeat_keystore" {
    command {
      command = join(" && ", [
        "filebeat keystore create --force >/dev/null",
        "printf admin | filebeat keystore add username --stdin --force >/dev/null",
        "printf %s \"$(cat ${local.dir}/admin-password)\" | filebeat keystore add password --stdin --force >/dev/null",
      ])
      triggers = {
        package  = conn3x_package.wazuh_server__filebeat_package[each.key].revision
        password = conn3x_file.wazuh_server__admin_password[each.key].revision
      }
    }
  }

  step "filebeat_restart" {
    command {
      command = "systemctl daemon-reload && systemctl restart filebeat"
      triggers = {
        config   = conn3x_file.wazuh_server__filebeat_config[each.key].revision
        template = conn3x_download.wazuh_server__filebeat_template[each.key].revision
        module   = conn3x_command.wazuh_server__filebeat_module[each.key].revision
        keystore = conn3x_command.wazuh_server__filebeat_keystore[each.key].revision
        certs    = conn3x_command.wazuh_server__deploy_certs[each.key].revision
      }
    }
  }

  step "filebeat_running" {
    service {
      name    = "filebeat"
      state   = "started"
      enabled = true
    }
  }

  step "dashboard_host" {
    line {
      path   = "/etc/wazuh-dashboard/opensearch_dashboards.yml"
      regexp = "^server\\.host:"
      line   = "server.host: ${var.dashboard_address}"
    }
  }

  step "dashboard_port" {
    line {
      path   = "/etc/wazuh-dashboard/opensearch_dashboards.yml"
      regexp = "^server\\.port:"
      line   = "server.port: ${var.dashboard_port}"
    }
  }

  step "dashboard_indexer" {
    line {
      path   = "/etc/wazuh-dashboard/opensearch_dashboards.yml"
      regexp = "^opensearch\\.hosts:"
      line   = "opensearch.hosts: https://127.0.0.1:9200"
    }
  }

  step "dashboard_secrets" {
    command {
      # The package gives its directories to wazuh-dashboard, so all of this
      # runs as that user. The passwords arrive on file descriptors root opens.
      command = <<-EOT
        cd /
        runuser -u wazuh-dashboard -- sh -es 3< ${local.dir}/kibanaserver-password 4< ${local.dir}/wazuh-wui-password <<'SH'
        ks=/usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore
        printf kibanaserver | $ks add -f --stdin opensearch.username >/dev/null
        printf %s "$(cat <&3)" | $ks add -f --stdin opensearch.password >/dev/null
        c=${dirname(local.wazuh_yml)}
        for p in "$${c%/*}" "$c" ${local.wazuh_yml}; do [ ! -L "$p" ] || rm -f "$p"; done
        mkdir -p "$c"
        umask 077
        printf 'hosts:\n  - default:\n      url: https://127.0.0.1\n      port: 55000\n      username: wazuh-wui\n      password: "%s"\n      run_as: false\n' "$(cat <&4)" > ${local.wazuh_yml}
        SH
      EOT
      triggers = {
        package  = conn3x_package.wazuh_server__dashboard_package[each.key].revision
        security = conn3x_command.wazuh_server__indexer_security[each.key].revision
        api      = conn3x_command.wazuh_server__api_passwords[each.key].revision
      }
    }
  }

  step "dashboard_restart" {
    command {
      command = "systemctl daemon-reload && systemctl restart wazuh-dashboard"
      triggers = {
        host    = conn3x_line.wazuh_server__dashboard_host[each.key].revision
        port    = conn3x_line.wazuh_server__dashboard_port[each.key].revision
        indexer = conn3x_line.wazuh_server__dashboard_indexer[each.key].revision
        secrets = conn3x_command.wazuh_server__dashboard_secrets[each.key].revision
        certs   = conn3x_command.wazuh_server__deploy_certs[each.key].revision
      }
    }
  }

  step "dashboard_running" {
    service {
      name    = "wazuh-dashboard"
      state   = "started"
      enabled = true
    }
  }

  # The dashboard takes a minute or two to come up on its first start.
  step "dashboard_ready" {
    command {
      command  = "for _ in $(seq 150); do c=$(curl -sk -o /dev/null -w '%%{http_code}' https://127.0.0.1:${var.dashboard_port}/app/login); [ \"$c\" = 200 ] && exit 0; sleep 2; done; exit 1"
      triggers = { restart = conn3x_command.wazuh_server__dashboard_restart[each.key].revision }
    }
  }
}

circuit "wazuh_agents" {
  hosts = var.agents

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  # After the server, since an agent must not be newer than its manager,
  # which is also what makes a version change upgrade the manager first.
  step "repo" {
    repository {
      name       = "wazuh"
      url        = local.family[each.key] == "debian" ? "${local.repo_url}/apt" : "${local.repo_url}/yum"
      key        = local.repo_key
      suites     = local.family[each.key] == "debian" ? ["stable"] : null
      components = ["main"]
    }
    depends_on = [conn3x_command.wazuh_server__dashboard_ready]
  }

  step "package" {
    package {
      name    = "wazuh-agent"
      version = local.package_version
    }
    notify = [handler.restart]
  }

  # The package gives /var/ossec/etc to the wazuh user but leaves ossec.conf
  # with root. An edit replaces the file from inside the directory, so the
  # two need one owner. A package upgrade can put root back.
  step "ossec_owner" {
    command {
      command  = "chown -h wazuh ${local.ossec}"
      unless   = "[ \"$(stat -c %U ${local.ossec})\" = wazuh ]"
      triggers = { package = conn3x_package.wazuh_agents__package[each.key].revision }
    }
  }

  step "manager_address" {
    line {
      path   = local.ossec
      regexp = "<address>"
      line   = "      <address>${local.manager_address}</address>"
    }
    notify = [handler.restart]
  }

  step "enrollment_password" {
    file {
      path       = "/var/ossec/etc/authd.pass"
      content_wo = var.enrollment_password
      owner      = "wazuh"
      group      = "wazuh"
      mode       = "0640"
    }
    notify = [handler.restart]
  }

  step "running" {
    service {
      name    = "wazuh-agent"
      state   = "started"
      enabled = true
    }
  }

  handler "restart" {
    service {
      name = "wazuh-agent"
    }
  }
}
