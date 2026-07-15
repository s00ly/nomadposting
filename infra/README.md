# OpenTofu gateway topology

This directory is a credential-free, plan-safe topology manifest. It records the reviewed AWS and GCP region pair for France, Germany, the United Kingdom, Sweden, and Switzerland, plus the EUR 250 initial budget ceiling.

It does **not** provision VMs, addresses, DNS, WireGuard keys, firewall rules, IAM, or billing alarms. Those operations require provider credentials, account-specific decisions, current region validation, and a separate reviewed module. Keeping those operations out of this baseline prevents an unreviewed `tofu apply` from creating internet-facing infrastructure.

## Inspect

```sh
tofu init -backend=false
tofu validate
tofu plan -var deployment_stage=pilot
```

The pilot output contains one AWS endpoint per country. Production output contains AWS and GCP endpoint IDs for every country. The identifiers must exactly match `internal/egress.DefaultEndpointCatalog`.

No secrets or public IP addresses belong in Terraform variables, outputs, state, or version control. A production deployment must add encrypted remote state, least-privilege workload identity, AWS and GCP budget alarms, and static-address country verification before resources are created.
