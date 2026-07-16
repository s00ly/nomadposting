package egress

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// NamespaceProvisioner creates the root-owned resources for an attempt. If
// Prepare returns a non-nil session with an error, the executor still tears the
// session down. If it returns a nil session, Prepare must have removed every
// partial resource itself.
type NamespaceProvisioner interface {
	Prepare(context.Context, NamespaceAttempt) (NamespaceSession, error)
}

// NamespaceSession exposes fixed lifecycle phases only. A concrete Linux
// implementation resolves root-owned endpoint configuration internally; none
// of these methods accepts a request-controlled command, path, address, or key.
type NamespaceSession interface {
	ConfigureWireGuard(context.Context) error
	ConfigureFirewall(context.Context) error
	ConfigureResolver(context.Context) error
	VerifyIsolation(context.Context) error
	RunWorker(context.Context) error
	Teardown(context.Context) error
}

// TransactionalNamespaceExecutor makes teardown part of the success condition.
// It is safe to compose with a future Linux backend, but the shipped broker
// remains wired to DisabledNamespaceExecutor until Linux capture gates pass.
type TransactionalNamespaceExecutor struct {
	provisioner    NamespaceProvisioner
	cleanupTimeout time.Duration
}

func NewTransactionalNamespaceExecutor(provisioner NamespaceProvisioner, cleanupTimeout time.Duration) (*TransactionalNamespaceExecutor, error) {
	if provisioner == nil {
		return nil, fmt.Errorf("namespace provisioner is required")
	}
	if cleanupTimeout <= 0 {
		return nil, fmt.Errorf("cleanup timeout must be positive")
	}
	return &TransactionalNamespaceExecutor{provisioner: provisioner, cleanupTimeout: cleanupTimeout}, nil
}

func (e *TransactionalNamespaceExecutor) Run(ctx context.Context, attempt NamespaceAttempt) (runErr error) {
	if ctx == nil {
		return fmt.Errorf("attempt context is required")
	}
	if err := attempt.Validate(); err != nil {
		return fmt.Errorf("validate namespace attempt: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("prepare namespace: %w", err)
	}

	session, prepareErr := e.provisioner.Prepare(ctx, attempt)
	if session == nil {
		if prepareErr != nil {
			return fmt.Errorf("prepare namespace: %w", prepareErr)
		}
		return fmt.Errorf("prepare namespace: provisioner returned no session")
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), e.cleanupTimeout)
		defer cancel()
		if err := session.Teardown(cleanupCtx); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("teardown namespace: %w", err))
		}
	}()

	if prepareErr != nil {
		return fmt.Errorf("prepare namespace: %w", prepareErr)
	}
	phases := []struct {
		name string
		run  func(context.Context) error
	}{
		{name: "configure WireGuard", run: session.ConfigureWireGuard},
		{name: "configure nftables", run: session.ConfigureFirewall},
		{name: "configure resolver", run: session.ConfigureResolver},
		{name: "verify isolation", run: session.VerifyIsolation},
		{name: "run worker", run: session.RunWorker},
	}
	for _, phase := range phases {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%s: %w", phase.name, err)
		}
		if err := phase.run(ctx); err != nil {
			return fmt.Errorf("%s: %w", phase.name, err)
		}
	}
	return nil
}
