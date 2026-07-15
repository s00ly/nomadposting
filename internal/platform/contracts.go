// Package platform defines the narrow, auditable boundary between the control
// plane and remote publishing platforms.
package platform

import (
	"context"
	"time"
)

// Platform identifies a remote publishing system.
type Platform string

const (
	PlatformX     Platform = "x"
	PlatformNostr Platform = "nostr"
)

// PublicationState is the terminal state of one platform attempt.
type PublicationState string

const (
	StateComplete PublicationState = "COMPLETE"
	StatePartial  PublicationState = "PARTIAL"
	StateFailed   PublicationState = "FAILED"
	StateUnknown  PublicationState = "UNKNOWN"
)

// PublishCommand is an approved, immutable text publication. Routing metadata
// is deliberately absent: an egress lease belongs to the execution layer.
type PublishCommand struct {
	JobID          string
	Content        string
	PayloadHashHex string
	EgressPolicyID string
}

// RelayResult contains only a reviewed endpoint identifier and a normalized
// result. It never records relay URLs, IP addresses, or raw remote messages.
type RelayResult struct {
	EndpointID string
	Accepted   bool
	Code       string
}

// Receipt is the sanitized, durable result of one platform attempt.
type Receipt struct {
	Platform     Platform
	State        PublicationState
	ExternalID   string
	AttemptCount int
	CountryCode  string
	RelayResults []RelayResult
	CreatedAt    time.Time
}

// Connector publishes an already-approved command through an execution layer
// that has established the required fail-closed egress route.
type Connector interface {
	Publish(context.Context, PublishCommand) (Receipt, error)
}
