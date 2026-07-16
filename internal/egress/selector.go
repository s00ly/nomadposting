package egress

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"sort"
	"time"
)

type SelectionPolicy struct {
	AllowedCountries    map[string]struct{}
	MinHealthyCountries int
	MaxHealthAge        time.Duration
	LeaseTTL            time.Duration
	StableXEndpointID   EndpointID
}

func DefaultSelectionPolicy() SelectionPolicy {
	return SelectionPolicy{
		AllowedCountries: map[string]struct{}{
			"FR": {}, "DE": {}, "GB": {}, "SE": {}, "CH": {},
		},
		MinHealthyCountries: 3,
		MaxHealthAge:        90 * time.Second,
		LeaseTTL:            5 * time.Minute,
		StableXEndpointID:   "aws-fr-1",
	}
}

type Selector struct {
	registry *Registry
	policy   SelectionPolicy
	random   io.Reader
}

func NewSelector(registry *Registry, policy SelectionPolicy) (*Selector, error) {
	if registry == nil {
		return nil, fmt.Errorf("registry is required")
	}
	if policy.MinHealthyCountries < 3 {
		return nil, fmt.Errorf("minimum healthy countries cannot be less than 3")
	}
	if policy.MaxHealthAge <= 0 || policy.LeaseTTL <= 0 {
		return nil, fmt.Errorf("health age and lease TTL must be positive")
	}
	if len(policy.AllowedCountries) < policy.MinHealthyCountries {
		return nil, fmt.Errorf("allowed country set is smaller than minimum healthy countries")
	}
	for country := range policy.AllowedCountries {
		if !countryCodePattern.MatchString(country) {
			return nil, fmt.Errorf("invalid allowed country code %q", country)
		}
	}
	stableX, _, err := registry.Resolve(policy.StableXEndpointID)
	if err != nil {
		return nil, fmt.Errorf("stable X endpoint: %w", err)
	}
	if stableX.CountryCode != "FR" {
		return nil, fmt.Errorf("stable X endpoint must be in FR")
	}
	if !stableX.Supports(PlatformX) || stableX.Supports(PlatformNostr) {
		return nil, fmt.Errorf("stable X endpoint must be dedicated to X")
	}
	return &Selector{registry: registry, policy: policy, random: cryptorand.Reader}, nil
}

// Select chooses at dispatch time. Nostr selection is uniform by country first,
// then uniform by endpoint, so countries with more endpoints are not favored.
// The returned lease pins both endpoint and country across retries.
func (s *Selector) Select(jobID string, platform Platform, previousCountry string, now time.Time) (EgressLease, error) {
	if err := ValidateJobID(jobID); err != nil {
		return EgressLease{}, err
	}
	if err := platform.Validate(); err != nil {
		return EgressLease{}, err
	}
	if previousCountry != "" {
		if !countryCodePattern.MatchString(previousCountry) {
			return EgressLease{}, fmt.Errorf("invalid previous country code %q", previousCountry)
		}
		if _, allowed := s.policy.AllowedCountries[previousCountry]; !allowed {
			return EgressLease{}, fmt.Errorf("previous country %q is outside the allowed pool", previousCountry)
		}
	}
	now = now.UTC()
	if platform == PlatformX {
		return s.selectStableX(jobID, now)
	}

	byCountry := make(map[string][]Endpoint)
	for _, item := range s.registry.Snapshot() {
		if !item.Endpoint.Supports(PlatformNostr) {
			continue
		}
		if _, allowed := s.policy.AllowedCountries[item.Endpoint.CountryCode]; !allowed {
			continue
		}
		if !item.Health.Eligible(now, s.policy.MaxHealthAge) {
			continue
		}
		byCountry[item.Endpoint.CountryCode] = append(byCountry[item.Endpoint.CountryCode], item.Endpoint)
	}
	if len(byCountry) < s.policy.MinHealthyCountries {
		return EgressLease{}, fmt.Errorf("%w: got %d, require %d", ErrInsufficientCountries, len(byCountry), s.policy.MinHealthyCountries)
	}

	countries := make([]string, 0, len(byCountry))
	for country := range byCountry {
		if country != previousCountry {
			countries = append(countries, country)
		}
	}
	if len(countries) == 0 {
		return EgressLease{}, ErrNoEligibleAlternate
	}
	sort.Strings(countries)
	countryIndex, err := randomIndex(s.random, len(countries))
	if err != nil {
		return EgressLease{}, fmt.Errorf("select country: %w", err)
	}
	country := countries[countryIndex]
	endpoints := byCountry[country]
	sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].ID < endpoints[j].ID })
	endpointIndex, err := randomIndex(s.random, len(endpoints))
	if err != nil {
		return EgressLease{}, fmt.Errorf("select endpoint: %w", err)
	}
	return s.newLease(jobID, platform, endpoints[endpointIndex], now)
}

func (s *Selector) selectStableX(jobID string, now time.Time) (EgressLease, error) {
	endpoint, health, err := s.registry.Resolve(s.policy.StableXEndpointID)
	if err != nil {
		return EgressLease{}, err
	}
	if endpoint.CountryCode != "FR" {
		return EgressLease{}, fmt.Errorf("stable X endpoint must be in FR")
	}
	if !health.Eligible(now, s.policy.MaxHealthAge) {
		return EgressLease{}, ErrEndpointNotHealthy
	}
	return s.newLease(jobID, PlatformX, endpoint, now)
}

func (s *Selector) newLease(jobID string, platform Platform, endpoint Endpoint, now time.Time) (EgressLease, error) {
	raw := make([]byte, 16)
	if _, err := io.ReadFull(s.random, raw); err != nil {
		return EgressLease{}, fmt.Errorf("create lease ID: %w", err)
	}
	return EgressLease{
		ID:          hex.EncodeToString(raw),
		JobID:       jobID,
		Platform:    platform,
		EndpointID:  endpoint.ID,
		CountryCode: endpoint.CountryCode,
		IssuedAt:    now,
		ExpiresAt:   now.Add(s.policy.LeaseTTL),
	}, nil
}

func randomIndex(reader io.Reader, length int) (int, error) {
	if length <= 0 {
		return 0, fmt.Errorf("cannot sample an empty set")
	}
	n, err := cryptorand.Int(reader, big.NewInt(int64(length)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}
