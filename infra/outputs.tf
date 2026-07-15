output "active_gateway_matrix" {
  description = "Non-secret endpoint IDs and cloud regions used to generate root-owned deployment inventory."
  value       = local.active_gateway_matrix
}

output "monthly_budget_eur" {
  description = "Budget ceiling for external AWS and GCP budget configuration."
  value       = var.monthly_budget_eur
}

output "credentials_configured" {
  description = "Always false: this topology module never reads or provisions cloud credentials."
  value       = false
}
