package domain

import "time"

type JobState string

const (
	StateDraft      JobState = "DRAFT"
	StateApproved   JobState = "APPROVED"
	StateRouting    JobState = "ROUTING"
	StatePublishing JobState = "PUBLISHING"
	StateComplete   JobState = "COMPLETE"
	StatePartial    JobState = "PARTIAL"
	StateFailed     JobState = "FAILED"
	StateUnknown    JobState = "UNKNOWN"
	StateCancelled  JobState = "CANCELLED"
)

type Platform string

const (
	PlatformX     Platform = "x"
	PlatformNostr Platform = "nostr"
)

type ReceiptState string

const (
	ReceiptPending ReceiptState = "PENDING"
	ReceiptSuccess ReceiptState = "SUCCESS"
	ReceiptPartial ReceiptState = "PARTIAL"
	ReceiptFailed  ReceiptState = "FAILED"
	ReceiptUnknown ReceiptState = "UNKNOWN"
)

type PostJob struct {
	ID               string
	EncryptedContent []byte
	PayloadHash      string
	PostToX          bool
	PostToNostr      bool
	State            JobState
	ApprovedAt       *time.Time
	ScheduledAt      *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
	LastNostrCountry string
	ContentDestroyed bool
}

type JobSummary struct {
	ID               string
	PayloadHash      string
	PostToX          bool
	PostToNostr      bool
	State            JobState
	ApprovedAt       *time.Time
	ScheduledAt      *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
	ContentDestroyed bool
	Receipts         []PlatformReceipt
}

type PlatformReceipt struct {
	ID             int64
	JobID          string
	Platform       Platform
	State          ReceiptState
	ExternalID     string
	CountryCode    string
	AttemptCount   int
	RelayAccepted  int
	RelayAttempted int
	SafeError      string
	CreatedAt      time.Time
}

type AuditEvent struct {
	ID        int64
	JobID     string
	Kind      string
	Detail    string
	CreatedAt time.Time
}

type EgressHealth struct {
	EndpointID string
	Country    string
	Provider   string
	Healthy    bool
	FreshUntil time.Time
	Failures   int
}

type SystemState struct {
	EmergencyStop bool
	Reason        string
	UpdatedAt     time.Time
}
