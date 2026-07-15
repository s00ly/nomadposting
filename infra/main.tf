locals {
  # Region identifiers and stable endpoint IDs are non-secret. Public IPs,
  # WireGuard keys, DNS addresses, and provider credentials must be injected by
  # a separate reviewed deployment layer and never committed here.
  gateway_matrix = {
    FR = {
      aws = { endpoint_id = "aws-fr-1", region = "eu-west-3" }
      gcp = { endpoint_id = "gcp-fr-1", region = "europe-west9" }
    }
    DE = {
      aws = { endpoint_id = "aws-de-1", region = "eu-central-1" }
      gcp = { endpoint_id = "gcp-de-1", region = "europe-west3" }
    }
    GB = {
      aws = { endpoint_id = "aws-gb-1", region = "eu-west-2" }
      gcp = { endpoint_id = "gcp-gb-1", region = "europe-west2" }
    }
    SE = {
      aws = { endpoint_id = "aws-se-1", region = "eu-north-1" }
      gcp = { endpoint_id = "gcp-se-1", region = "europe-north2" }
    }
    CH = {
      aws = { endpoint_id = "aws-ch-1", region = "eu-central-2" }
      gcp = { endpoint_id = "gcp-ch-1", region = "europe-west6" }
    }
  }

  active_gateway_matrix = {
    for country, providers in local.gateway_matrix : country => {
      for provider, gateway in providers : provider => gateway
      if var.deployment_stage == "production" || provider == "aws"
    }
  }
}

check "five_country_pool" {
  assert {
    condition     = length(local.gateway_matrix) == 5
    error_message = "The reviewed gateway matrix must contain exactly five countries."
  }
}

check "provider_diversity_before_production" {
  assert {
    condition = var.deployment_stage != "production" || alltrue([
      for _, providers in local.active_gateway_matrix : length(providers) == 2
    ])
    error_message = "Production requires both reviewed providers in every country."
  }
}
