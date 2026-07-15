package egress

import (
	"errors"
	"testing"
	"time"
)

func TestRegistryRejectsUnknownAndDuplicateEndpoints(t *testing.T) {
	_, err := NewRegistry([]Endpoint{
		{ID: "aws-fr-1", CountryCode: "FR", Provider: "aws", Region: "eu-west-3"},
		{ID: "aws-fr-1", CountryCode: "FR", Provider: "aws", Region: "eu-west-3"},
	})
	if err == nil {
		t.Fatal("expected duplicate endpoint error")
	}

	registry, err := NewRegistry(DefaultEndpointCatalog())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = registry.Resolve("attacker-endpoint")
	if !errors.Is(err, ErrUnknownEndpoint) {
		t.Fatalf("expected unknown endpoint rejection, got %v", err)
	}
}

func TestThreeProbeFailuresQuarantineEndpoint(t *testing.T) {
	registry, err := NewRegistry(DefaultEndpointCatalog())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		if err := registry.MarkProbe("aws-fr-1", false, now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	_, health, err := registry.Resolve("aws-fr-1")
	if err != nil {
		t.Fatal(err)
	}
	if !health.Quarantined || health.Failures != 3 {
		t.Fatalf("endpoint was not quarantined: %+v", health)
	}
}

func TestLeakOrCountryMismatchQuarantinesImmediately(t *testing.T) {
	registry, err := NewRegistry(DefaultEndpointCatalog())
	if err != nil {
		t.Fatal(err)
	}
	report := ProbeReport{
		EndpointID: "gcp-se-1", CheckedAt: time.Now().UTC(), Reachable: true,
		StaticIPMatch: true, CountryMatch: false, TLSValid: true,
	}
	if err := registry.ApplyProbe(report); err != nil {
		t.Fatal(err)
	}
	_, health, err := registry.Resolve("gcp-se-1")
	if err != nil {
		t.Fatal(err)
	}
	if !health.Quarantined || health.Healthy {
		t.Fatalf("hard failure did not fail closed: %+v", health)
	}
}
