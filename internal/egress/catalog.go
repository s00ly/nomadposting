package egress

// DefaultEndpointCatalog contains stable, non-secret identifiers and regions.
// It intentionally contains no IP addresses, WireGuard keys, DNS servers, or
// filesystem paths.
func DefaultEndpointCatalog() []Endpoint {
	return []Endpoint{
		{ID: "aws-fr-1", CountryCode: "FR", Provider: "aws", Region: "eu-west-3"},
		{ID: "gcp-fr-1", CountryCode: "FR", Provider: "gcp", Region: "europe-west9"},
		{ID: "aws-de-1", CountryCode: "DE", Provider: "aws", Region: "eu-central-1"},
		{ID: "gcp-de-1", CountryCode: "DE", Provider: "gcp", Region: "europe-west3"},
		{ID: "aws-gb-1", CountryCode: "GB", Provider: "aws", Region: "eu-west-2"},
		{ID: "gcp-gb-1", CountryCode: "GB", Provider: "gcp", Region: "europe-west2"},
		{ID: "aws-se-1", CountryCode: "SE", Provider: "aws", Region: "eu-north-1"},
		{ID: "gcp-se-1", CountryCode: "SE", Provider: "gcp", Region: "europe-north2"},
		{ID: "aws-ch-1", CountryCode: "CH", Provider: "aws", Region: "eu-central-2"},
		{ID: "gcp-ch-1", CountryCode: "CH", Provider: "gcp", Region: "europe-west6"},
	}
}
