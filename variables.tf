variable "server" {
  type        = any
  description = "The host that runs the Wazuh manager, indexer and dashboard together, as a map of one name to an address, or to a host object with an address and optional host_key, user, port, private_key_file, jump_hosts or os."

  validation {
    condition     = length(var.server) == 1
    error_message = "Give exactly one server."
  }
}

variable "agents" {
  type        = any
  default     = {}
  description = "Hosts that run the Wazuh agent, by name, in the same form as server. The server can't be one: Wazuh's manager and agent packages conflict, and the manager already watches its own host."

  validation {
    condition     = length(setintersection(keys(var.server), keys(var.agents))) == 0 && !contains([for a in values(var.agents) : "${try(a.address, a)}:${try(a.port, var.ssh_port)}"], "${try(values(var.server)[0].address, values(var.server)[0])}:${try(values(var.server)[0].port, var.ssh_port)}")
    error_message = "The server can't also be an agent, by name or by address. Wazuh's manager and agent packages conflict."
  }
}

variable "ssh_user" {
  type        = string
  default     = "root"
  description = "User to log in as."
}

variable "ssh_port" {
  type        = number
  default     = 22
  description = "SSH port."
}

variable "ssh_private_key_file" {
  type        = string
  default     = null
  description = "Path to a private key. When null, Conn3x uses the SSH agent."
}

variable "ssh_known_hosts_file" {
  type        = string
  default     = null
  description = "known_hosts file to check host keys against. When null, ~/.ssh/known_hosts."
}

variable "ssh_become" {
  type        = bool
  default     = false
  description = "Run commands as root through sudo."
}

variable "wazuh_version" {
  type        = string
  default     = "4.14.9"
  description = "Wazuh 4.x release to install on the server and the agents, without the package revision. Change filebeat_template_sha256 with it."

  validation {
    condition     = can(regex("^4\\.[0-9]+\\.[0-9]+$", var.wazuh_version))
    error_message = "wazuh_version must be a 4.x release number such as \"4.14.9\"."
  }
}

variable "filebeat_template_sha256" {
  type        = string
  default     = "b2d182f49cc68957849e77fd2d79528fd2273ebaec1106c9661c9e320577a089"
  description = "SHA-256 of extensions/elasticsearch/7.x/wazuh-template.json in the Wazuh source at wazuh_version."

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.filebeat_template_sha256))
    error_message = "filebeat_template_sha256 must be a SHA-256 in lowercase hex."
  }
}

variable "manager_address" {
  type        = string
  default     = null
  description = "Address or name agents reach the manager on. When null, the server's address."

  validation {
    condition     = var.manager_address == null || can(regex("^[A-Za-z0-9.:-]+$", coalesce(var.manager_address, "-")))
    error_message = "manager_address must be an IP address or a host name."
  }
}

variable "dashboard_address" {
  type        = string
  default     = "127.0.0.1"
  description = "Address the dashboard listens on. The default keeps it to the host itself, for a proxy or an SSH tunnel; \"0.0.0.0\" listens on every address."

  validation {
    condition     = can(cidrhost("${var.dashboard_address}/${strcontains(var.dashboard_address, ":") ? 128 : 32}", 0))
    error_message = "dashboard_address must be an IP address, such as \"127.0.0.1\"."
  }
}

variable "dashboard_port" {
  type        = number
  default     = 443
  description = "Port of the dashboard."

  validation {
    condition     = var.dashboard_port >= 1 && var.dashboard_port <= 65535 && floor(var.dashboard_port) == var.dashboard_port
    error_message = "dashboard_port must be a port number from 1 to 65535."
  }
}

variable "api_address" {
  type        = string
  default     = "127.0.0.1"
  description = "Address the Wazuh API, on port 55000, listens on. The default keeps it to the host itself; \"0.0.0.0\" listens on every address."

  validation {
    condition     = can(cidrhost("${var.api_address}/${strcontains(var.api_address, ":") ? 128 : 32}", 0))
    error_message = "api_address must be an IP address, such as \"127.0.0.1\"."
  }
}

variable "indexer_heap" {
  type        = string
  default     = "4g"
  description = "JVM heap of the indexer, as both -Xms and -Xmx, such as \"1g\" or \"4g\". Wazuh advises half the host's memory, and no more than 32g. The default suits the 8 GiB host Wazuh asks for."

  validation {
    condition     = can(regex("^[0-9]+[mg]$", var.indexer_heap))
    error_message = "indexer_heap must be a size such as \"512m\" or \"4g\"."
  }
}

variable "admin_password" {
  type        = string
  ephemeral   = true
  sensitive   = true
  description = "Password of admin, who signs in to the dashboard and the indexer. 8 to 64 characters with an uppercase letter, a lowercase letter, a digit and one of . * + ? -, and no other symbols. Pass it at run time with -var or TF_VAR_admin_password; it never reaches state or the plan. Changing it sets the new one."

  validation {
    condition     = can(regex("^[A-Za-z0-9.*+?-]{8,64}$", var.admin_password)) && can(regex("[A-Z]", var.admin_password)) && can(regex("[a-z]", var.admin_password)) && can(regex("[0-9]", var.admin_password)) && can(regex("[.*+?-]", var.admin_password))
    error_message = "admin_password must be 8 to 64 characters of letters, digits and . * + ? -, with at least one uppercase letter, lowercase letter, digit and symbol."
  }
}

variable "api_password" {
  type        = string
  ephemeral   = true
  sensitive   = true
  description = "Password of wazuh, the Wazuh API's administrator, under the same rules as admin_password. Ephemeral, like it. Changing it sets the new one."

  validation {
    condition     = can(regex("^[A-Za-z0-9.*+?-]{8,64}$", var.api_password)) && can(regex("[A-Z]", var.api_password)) && can(regex("[a-z]", var.api_password)) && can(regex("[0-9]", var.api_password)) && can(regex("[.*+?-]", var.api_password))
    error_message = "api_password must be 8 to 64 characters of letters, digits and . * + ? -, with at least one uppercase letter, lowercase letter, digit and symbol."
  }
}

variable "enrollment_password" {
  type        = string
  ephemeral   = true
  sensitive   = true
  description = "Shared secret agents present to the manager to enroll, such as the output of openssl rand -hex 16. Ephemeral, like admin_password. Keep it the same between runs, or every agent's file changes with it."

  validation {
    condition     = can(regex("^[A-Za-z0-9+/=_-]{8,}$", var.enrollment_password))
    error_message = "enrollment_password must be at least 8 characters of letters, digits, +, /, =, _ and -."
  }
}
