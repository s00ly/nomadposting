variable "monthly_budget_eur" {
  description = "Provisional combined infrastructure ceiling. Provider budget resources are intentionally not created by this credential-free topology module."
  type        = number
  default     = 250

  validation {
    condition     = var.monthly_budget_eur > 0 && var.monthly_budget_eur <= 250
    error_message = "The initial monthly infrastructure budget must be between EUR 1 and EUR 250."
  }
}

variable "deployment_stage" {
  description = "Topology stage. Pilot exposes one endpoint per country; production exposes both providers."
  type        = string
  default     = "pilot"

  validation {
    condition     = contains(["pilot", "production"], var.deployment_stage)
    error_message = "deployment_stage must be pilot or production."
  }
}
