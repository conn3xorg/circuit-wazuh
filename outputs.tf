output "manager_address" {
  description = "Address the agents reach the manager on."
  value       = local.manager_address
}

output "dashboard_url" {
  description = "URL of the dashboard, from the server itself when it listens on loopback."
  value       = local.dashboard_url
}
