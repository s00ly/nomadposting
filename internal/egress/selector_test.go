package egress

import (
	"errors"
	"math"
	"testing"
	"time"
)

func TestNostrSelectionNeverRepeatsPreviousCountry(t *testing.T) {
	now := time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)
	registry := healthyDefaultRegistry(t, now)
	selector, err := NewSelector(registry, DefaultSelectionPolicy())
	if err != nil {
		t.Fatal(err)
	}

	previous := "FR"
	for i := 0; i < 2_000; i++ {
		lease, selectErr := selector.Select("job_repeat_0001", PlatformNostr, previous, now)
		if selectErr != nil {
			t.Fatal(selectErr)
		}
		if lease.CountryCode == previous {
			t.Fatalf("selected adjacent repeated country %s", previous)
		}
		previous = lease.CountryCode
	}
}

func TestNostrSelectionRequiresThreeHealthyCountries(t *testing.T) {
	now := time.Now().UTC()
	registry, err := NewRegistry(DefaultEndpointCatalog())
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range registry.Snapshot() {
		if item.Endpoint.CountryCode == "FR" || item.Endpoint.CountryCode == "DE" {
			if err := registry.MarkProbe(item.Endpoint.ID, true, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	selector, err := NewSelector(registry, DefaultSelectionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	_, err = selector.Select("job_health_0001", PlatformNostr, "", now)
	if !errors.Is(err, ErrInsufficientCountries) {
		t.Fatalf("expected ErrInsufficientCountries, got %v", err)
	}
}

func TestSelectionIsByCountryNotEndpointCount(t *testing.T) {
	endpoints := []Endpoint{
		{ID: "aws-fr-1", CountryCode: "FR", Provider: "aws", Region: "eu-west-3"},
		{ID: "aws-fr-2", CountryCode: "FR", Provider: "aws", Region: "eu-west-3"},
		{ID: "gcp-fr-1", CountryCode: "FR", Provider: "gcp", Region: "europe-west9"},
		{ID: "aws-de-1", CountryCode: "DE", Provider: "aws", Region: "eu-central-1"},
		{ID: "aws-gb-1", CountryCode: "GB", Provider: "aws", Region: "eu-west-2"},
		{ID: "aws-se-1", CountryCode: "SE", Provider: "aws", Region: "eu-north-1"},
	}
	now := time.Now().UTC()
	registry, err := NewRegistry(endpoints)
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range endpoints {
		if err := registry.MarkProbe(endpoint.ID, true, now); err != nil {
			t.Fatal(err)
		}
	}
	policy := DefaultSelectionPolicy()
	policy.AllowedCountries = map[string]struct{}{"FR": {}, "DE": {}, "GB": {}, "SE": {}}
	selector, err := NewSelector(registry, policy)
	if err != nil {
		t.Fatal(err)
	}

	const samples = 12_000
	counts := map[string]int{}
	for i := 0; i < samples; i++ {
		lease, selectErr := selector.Select("job_uniform_001", PlatformNostr, "", now)
		if selectErr != nil {
			t.Fatal(selectErr)
		}
		counts[lease.CountryCode]++
	}
	expected := float64(samples) / 4
	for country, count := range counts {
		deviation := math.Abs(float64(count)-expected) / expected
		if deviation > 0.15 {
			t.Fatalf("country %s has implausible sampling deviation %.2f (count %d)", country, deviation, count)
		}
	}
}

func TestStableXUsesFranceAndRequiresFreshHealth(t *testing.T) {
	now := time.Now().UTC()
	registry := healthyDefaultRegistry(t, now)
	selector, err := NewSelector(registry, DefaultSelectionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := selector.Select("job_xstable_001", PlatformX, "CH", now)
	if err != nil {
		t.Fatal(err)
	}
	if lease.EndpointID != "aws-fr-1" || lease.CountryCode != "FR" {
		t.Fatalf("unexpected X lease: %+v", lease)
	}

	stale := now.Add(91 * time.Second)
	_, err = selector.Select("job_xstable_002", PlatformX, "", stale)
	if !errors.Is(err, ErrEndpointNotHealthy) {
		t.Fatalf("expected stale endpoint rejection, got %v", err)
	}
}

func TestSelectorRejectsMalformedPreviousCountry(t *testing.T) {
	now := time.Now().UTC()
	selector, err := NewSelector(healthyDefaultRegistry(t, now), DefaultSelectionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := selector.Select("job_country_001", PlatformNostr, "fr", now); err == nil {
		t.Fatal("expected lowercase previous country to be rejected")
	}
}

func healthyDefaultRegistry(t *testing.T, now time.Time) *Registry {
	t.Helper()
	registry, err := NewRegistry(DefaultEndpointCatalog())
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range registry.Snapshot() {
		if err := registry.MarkProbe(item.Endpoint.ID, true, now); err != nil {
			t.Fatal(err)
		}
	}
	return registry
}
