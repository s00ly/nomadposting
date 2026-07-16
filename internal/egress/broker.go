package egress

import (
	"context"
	"fmt"
	"runtime"
	"time"
)

type BrokerRequest struct {
	JobID      string     `json:"job_id"`
	Platform   Platform   `json:"platform"`
	EndpointID EndpointID `json:"endpoint_id"`
}

func (r BrokerRequest) Validate() error {
	if err := ValidateJobID(r.JobID); err != nil {
		return err
	}
	if err := r.Platform.Validate(); err != nil {
		return err
	}
	if err := r.EndpointID.Validate(); err != nil {
		return err
	}
	return nil
}

type BrokerResult struct {
	Accepted   bool       `json:"accepted"`
	DryRun     bool       `json:"dry_run"`
	EndpointID EndpointID `json:"endpoint_id"`
	Message    string     `json:"message"`
}

type BrokerStatus struct {
	PlatformExecution string `json:"platform_execution"`
	ExecutionEnabled  bool   `json:"execution_enabled"`
	RegisteredCount   int    `json:"registered_count"`
}

// NamespaceAttempt is the complete typed input to one isolated platform
// attempt. The executor never receives request-controlled commands, routes,
// addresses, key paths, resolver addresses, or worker paths.
type NamespaceAttempt struct {
	JobID    string
	Platform Platform
	Endpoint Endpoint
}

func (a NamespaceAttempt) Validate() error {
	if err := ValidateJobID(a.JobID); err != nil {
		return err
	}
	if err := a.Platform.Validate(); err != nil {
		return err
	}
	if err := a.Endpoint.Validate(); err != nil {
		return err
	}
	if !a.Endpoint.Supports(a.Platform) {
		return ErrEndpointPlatformMismatch
	}
	return nil
}

// NamespaceExecutor owns the full isolated attempt. Run must not return nil
// until the worker has stopped and all namespace, tunnel, firewall, resolver,
// tmpfs, and credential-handle state has been torn down. Cleanup failure is an
// execution failure.
type NamespaceExecutor interface {
	Run(context.Context, NamespaceAttempt) error
}

// DisabledNamespaceExecutor is intentional. Enabling real namespace changes
// requires a separately reviewed Linux implementation and packet-capture proof.
type DisabledNamespaceExecutor struct{}

func (DisabledNamespaceExecutor) Run(context.Context, NamespaceAttempt) error {
	return ErrExecutionDisabled
}

type BrokerPolicy struct {
	MaxHealthAge      time.Duration
	StableXEndpointID EndpointID
}

func DefaultBrokerPolicy() BrokerPolicy {
	selection := DefaultSelectionPolicy()
	return BrokerPolicy{
		MaxHealthAge:      selection.MaxHealthAge,
		StableXEndpointID: selection.StableXEndpointID,
	}
}

func (p BrokerPolicy) validate(registry *Registry) error {
	if p.MaxHealthAge <= 0 {
		return fmt.Errorf("maximum health age must be positive")
	}
	if err := p.StableXEndpointID.Validate(); err != nil {
		return fmt.Errorf("stable X endpoint: %w", err)
	}
	endpoint, _, err := registry.Resolve(p.StableXEndpointID)
	if err != nil {
		return fmt.Errorf("stable X endpoint: %w", err)
	}
	if endpoint.CountryCode != "FR" {
		return fmt.Errorf("stable X endpoint must be in FR")
	}
	if !endpoint.Supports(PlatformX) || endpoint.Supports(PlatformNostr) {
		return fmt.Errorf("stable X endpoint must be dedicated to X")
	}
	return nil
}

type GuardedBroker struct {
	registry *Registry
	executor NamespaceExecutor
	policy   BrokerPolicy
	enabled  bool
}

func NewGuardedBroker(registry *Registry, executor NamespaceExecutor, enabled bool, policy BrokerPolicy) (*GuardedBroker, error) {
	if registry == nil || executor == nil {
		return nil, fmt.Errorf("registry and executor are required")
	}
	if err := policy.validate(registry); err != nil {
		return nil, err
	}
	return &GuardedBroker{registry: registry, executor: executor, enabled: enabled, policy: policy}, nil
}

func (b *GuardedBroker) Status() BrokerStatus {
	return BrokerStatus{
		PlatformExecution: runtime.GOOS,
		ExecutionEnabled:  b.enabled,
		RegisteredCount:   len(b.registry.Snapshot()),
	}
}

func (b *GuardedBroker) validateEndpoint(platform Platform, endpoint Endpoint) error {
	if !endpoint.Supports(platform) {
		return fmt.Errorf("%w: endpoint %q does not support %q", ErrEndpointPlatformMismatch, endpoint.ID, platform)
	}
	if platform == PlatformX && endpoint.ID != b.policy.StableXEndpointID {
		return fmt.Errorf("%w: X requires the registered stable endpoint", ErrEndpointPlatformMismatch)
	}
	return nil
}

// DryRun validates the complete privilege-boundary request and resolves it only
// through the registry. It performs no network or filesystem operation.
func (b *GuardedBroker) DryRun(request BrokerRequest) (BrokerResult, error) {
	if err := request.Validate(); err != nil {
		return BrokerResult{}, err
	}
	endpoint, _, err := b.registry.Resolve(request.EndpointID)
	if err != nil {
		return BrokerResult{}, err
	}
	if err := b.validateEndpoint(request.Platform, endpoint); err != nil {
		return BrokerResult{}, err
	}
	return BrokerResult{Accepted: true, DryRun: true, EndpointID: endpoint.ID, Message: "registered platform endpoint accepted; no network changes made"}, nil
}

func (b *GuardedBroker) Execute(ctx context.Context, request BrokerRequest, now time.Time) (BrokerResult, error) {
	if err := request.Validate(); err != nil {
		return BrokerResult{}, err
	}
	endpoint, health, err := b.registry.Resolve(request.EndpointID)
	if err != nil {
		return BrokerResult{}, err
	}
	if err := b.validateEndpoint(request.Platform, endpoint); err != nil {
		return BrokerResult{}, err
	}
	if !b.enabled {
		return BrokerResult{}, ErrExecutionDisabled
	}
	if runtime.GOOS != "linux" {
		return BrokerResult{}, fmt.Errorf("%w: requires Linux", ErrExecutionDisabled)
	}
	if !health.Eligible(now.UTC(), b.policy.MaxHealthAge) {
		return BrokerResult{}, ErrEndpointNotHealthy
	}
	attempt := NamespaceAttempt{JobID: request.JobID, Platform: request.Platform, Endpoint: endpoint}
	if err := b.executor.Run(ctx, attempt); err != nil {
		return BrokerResult{}, err
	}
	return BrokerResult{Accepted: true, EndpointID: endpoint.ID, Message: "isolated attempt completed and teardown succeeded"}, nil
}
