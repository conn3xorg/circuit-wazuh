# up.sh writes these to terraform.tfvars.
variable "port" {
  type = number
}

variable "agent_port" {
  type = number
}

variable "server_ip" {
  type = string
}

# Pass these at run time, such as with TF_VAR_admin_password.
variable "admin_password" {
  type      = string
  ephemeral = true
  sensitive = true
}

variable "api_password" {
  type      = string
  ephemeral = true
  sensitive = true
}

variable "enrollment_password" {
  type      = string
  ephemeral = true
  sensitive = true
}

# Two containers: the agent reaches the manager on the server container's
# address. The small heap suits a laptop, not a real deployment.
module "wazuh" {
  source = "../.."

  server               = { server = { address = "127.0.0.1", port = var.port } }
  agents               = { agent = { address = "127.0.0.1", port = var.agent_port } }
  manager_address      = var.server_ip
  indexer_heap         = "1g"
  ssh_private_key_file = "./id_ed25519"
  ssh_known_hosts_file = "./known_hosts"

  admin_password      = var.admin_password
  api_password        = var.api_password
  enrollment_password = var.enrollment_password
}

output "dashboard_url" {
  value = module.wazuh.dashboard_url
}
