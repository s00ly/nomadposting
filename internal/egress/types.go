// Package egress owns endpoint registration, health gating, country selection,
// and the narrow controller-to-network-broker contract.
package egress

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

type Platform string

const (
	PlatformX     Platform = "x"
	PlatformNostr Platform = "nostr"
)

func (p Platform) Validate() error {
	switch p {
	case PlatformX, PlatformNostr:
		return nil
	default:
		return fmt.Errorf("unsupported platform %q", p)
	}
}

type EndpointID string

var (
	endpointIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,63}$`)
	jobIDPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$`)
	countryCodePattern = regexp.MustCompile(`^[A-Z]{2}$`)
)

func (id EndpointID) Validate() error {
	if !endpointIDPattern.MatchString(string(id)) {
		return errors.New("endpoint ID must be 3-64 lowercase letters, digits, or hyphens")
	}
	return nil
}

func ValidateJobID(id string) error {
	if !jobIDPattern.MatchString(id) {
		return errors.New("job ID must be 8-128 URL-safe characters")
	}
	return nil
}

// Endpoint is deliberately metadata-only. Network addresses, key paths, route
// arguments, and commands belong to root-owned deployment configuration and
// cannot cross the broker request boundary. Platform is a compiled capability,
// not request-controlled policy.
type Endpoint struct {
	ID          EndpointID `json:"id"`
	CountryCode string     `json:"country_code"`
	Provider    string     `json:"provider"`
	Region      string     `json:"region"`
	Platform    Platform   `json:"platform"`
}

func (e Endpoint) Validate() error {
	if err := e.ID.Validate(); err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}
	if !countryCodePattern.MatchString(e.CountryCode) || e.CountryCode != strings.ToUpper(e.CountryCode) {
		return errors.New("country code must be an uppercase ISO 3166-1 alpha-2 code")
	}
	switch e.Provider {
	case "aws", "gcp":
	default:
		return fmt.Errorf("provider %q is not registered", e.Provider)
	}
	if strings.TrimSpace(e.Region) == "" || len(e.Region) > 64 {
		return errors.New("region must be 1-64 characters")
	}
	if err := e.Platform.Validate(); err != nil {
		return fmt.Errorf("endpoint platform: %w", err)
	}
	return nil
}

func (e Endpoint) Supports(platform Platform) bool {
	return e.Platform == platform
}

type Health struct {
	Healthy     bool      `json:"healthy"`
	Quarantined bool      `json:"quarantined"`
	CheckedAt   time.Time `json:"checked_at"`
	Failures    uint32    `json:"failures"`
}

func (h Health) Eligible(now time.Time, maxAge time.Duration) bool {
	if !h.Healthy || h.Quarantined || h.CheckedAt.IsZero() {
		return false
	}
	if maxAge <= 0 {
		return false
	}
	age := now.Sub(h.CheckedAt)
	return age >= 0 && age <= maxAge
}

type EgressLease struct {
	ID          string     `json:"id"`
	JobID       string     `json:"job_id"`
	Platform    Platform   `json:"platform"`
	EndpointID  EndpointID `json:"endpoint_id"`
	CountryCode string     `json:"country_code"`
	IssuedAt    time.Time  `json:"issued_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
}

var (
	ErrUnknownEndpoint          = errors.New("unknown endpoint")
	ErrEndpointNotHealthy       = errors.New("endpoint is not currently healthy")
	ErrEndpointPlatformMismatch = errors.New("endpoint is not allowed for platform")
	ErrInsufficientCountries    = errors.New("fewer than the required healthy countries")
	ErrNoEligibleAlternate      = errors.New("no eligible alternate country")
	ErrExecutionDisabled        = errors.New("privileged namespace execution is disabled")
)
