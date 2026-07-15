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

type NamespaceExecutor interface {
	Activate(context.Context, string, Platform, Endpoint) error
}

// DisabledNamespaceExecutor is intentional. Enabling real namespace changes
// requires a separately reviewed Linux implementation and packet-capture proof.
type DisabledNamespaceExecutor struct{}

func (DisabledNamespaceExecutor) Activate(context.Context, string, Platform, Endpoint) error {
	return ErrExecutionDisabled
}

type GuardedBroker struct {
	registry     *Registry
	executor     NamespaceExecutor
	maxHealthAge time.Duration
	enabled      bool
}

func NewGuardedBroker(registry *Registry, executor NamespaceExecutor, enabled bool, maxHealthAge time.Duration) (*GuardedBroker, error) {
	if registry == nil || executor == nil {
		return nil, fmt.Errorf("registry and executor are required")
	}
	if maxHealthAge <= 0 {
		return nil, fmt.Errorf("maximum health age must be positive")
	}
	return &GuardedBroker{registry: registry, executor: executor, enabled: enabled, maxHealthAge: maxHealthAge}, nil
}

func (b *GuardedBroker) Status() BrokerStatus {
	return BrokerStatus{
		PlatformExecution: runtime.GOOS,
		ExecutionEnabled:  b.enabled,
		RegisteredCount:   len(b.registry.Snapshot()),
	}
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
	return BrokerResult{Accepted: true, DryRun: true, EndpointID: endpoint.ID, Message: "registered request accepted; no network changes made"}, nil
}

func (b *GuardedBroker) Execute(ctx context.Context, request BrokerRequest, now time.Time) (BrokerResult, error) {
	if err := request.Validate(); err != nil {
		return BrokerResult{}, err
	}
	endpoint, health, err := b.registry.Resolve(request.EndpointID)
	if err != nil {
		return BrokerResult{}, err
	}
	if !b.enabled {
		return BrokerResult{}, ErrExecutionDisabled
	}
	if runtime.GOOS != "linux" {
		return BrokerResult{}, fmt.Errorf("%w: requires Linux", ErrExecutionDisabled)
	}
	if !health.Eligible(now.UTC(), b.maxHealthAge) {
		return BrokerResult{}, ErrEndpointNotHealthy
	}
	if err := b.executor.Activate(ctx, request.JobID, request.Platform, endpoint); err != nil {
		return BrokerResult{}, err
	}
	return BrokerResult{Accepted: true, EndpointID: endpoint.ID, Message: "namespace activation completed"}, nil
}
