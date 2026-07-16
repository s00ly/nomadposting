package egress

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

var (
	errLifecyclePhase    = errors.New("phase failed")
	errLifecycleTeardown = errors.New("teardown failed")
)

type fakeProvisioner struct {
	session      *fakeNamespaceSession
	err          error
	calls        *[]string
	afterPrepare func()
}

func (p fakeProvisioner) Prepare(context.Context, NamespaceAttempt) (NamespaceSession, error) {
	*p.calls = append(*p.calls, "prepare")
	if p.afterPrepare != nil {
		p.afterPrepare()
	}
	if p.session == nil {
		return nil, p.err
	}
	return p.session, p.err
}

type fakeNamespaceSession struct {
	calls              *[]string
	failPhase          string
	panicPhase         string
	teardownErr        error
	teardownContextErr error
}

func (s *fakeNamespaceSession) phase(ctx context.Context, name string) error {
	*s.calls = append(*s.calls, name)
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.panicPhase == name {
		panic(errLifecyclePhase)
	}
	if s.failPhase == name {
		return errLifecyclePhase
	}
	return nil
}

func (s *fakeNamespaceSession) ConfigureWireGuard(ctx context.Context) error {
	return s.phase(ctx, "wireguard")
}

func (s *fakeNamespaceSession) ConfigureFirewall(ctx context.Context) error {
	return s.phase(ctx, "nftables")
}

func (s *fakeNamespaceSession) ConfigureResolver(ctx context.Context) error {
	return s.phase(ctx, "resolver")
}

func (s *fakeNamespaceSession) VerifyIsolation(ctx context.Context) error {
	return s.phase(ctx, "verify")
}

func (s *fakeNamespaceSession) RunWorker(ctx context.Context) error {
	return s.phase(ctx, "worker")
}

func (s *fakeNamespaceSession) Teardown(ctx context.Context) error {
	*s.calls = append(*s.calls, "teardown")
	s.teardownContextErr = ctx.Err()
	return s.teardownErr
}

func TestTransactionalNamespaceExecutorTearsDownEveryPreparedPath(t *testing.T) {
	tests := []struct {
		name         string
		prepareErr   error
		failPhase    string
		teardownErr  error
		wantCalls    []string
		wantPhaseErr bool
		wantCleanErr bool
	}{
		{name: "success", wantCalls: []string{"prepare", "wireguard", "nftables", "resolver", "verify", "worker", "teardown"}},
		{name: "partial prepare", prepareErr: errLifecyclePhase, wantCalls: []string{"prepare", "teardown"}, wantPhaseErr: true},
		{name: "wireguard", failPhase: "wireguard", wantCalls: []string{"prepare", "wireguard", "teardown"}, wantPhaseErr: true},
		{name: "nftables", failPhase: "nftables", wantCalls: []string{"prepare", "wireguard", "nftables", "teardown"}, wantPhaseErr: true},
		{name: "resolver", failPhase: "resolver", wantCalls: []string{"prepare", "wireguard", "nftables", "resolver", "teardown"}, wantPhaseErr: true},
		{name: "verification", failPhase: "verify", wantCalls: []string{"prepare", "wireguard", "nftables", "resolver", "verify", "teardown"}, wantPhaseErr: true},
		{name: "worker", failPhase: "worker", wantCalls: []string{"prepare", "wireguard", "nftables", "resolver", "verify", "worker", "teardown"}, wantPhaseErr: true},
		{name: "teardown", teardownErr: errLifecycleTeardown, wantCalls: []string{"prepare", "wireguard", "nftables", "resolver", "verify", "worker", "teardown"}, wantCleanErr: true},
		{name: "worker and teardown", failPhase: "worker", teardownErr: errLifecycleTeardown, wantCalls: []string{"prepare", "wireguard", "nftables", "resolver", "verify", "worker", "teardown"}, wantPhaseErr: true, wantCleanErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := []string{}
			session := &fakeNamespaceSession{calls: &calls, failPhase: test.failPhase, teardownErr: test.teardownErr}
			executor, err := NewTransactionalNamespaceExecutor(fakeProvisioner{session: session, err: test.prepareErr, calls: &calls}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			runErr := executor.Run(context.Background(), validXAttempt())
			if test.wantPhaseErr != errors.Is(runErr, errLifecyclePhase) {
				t.Fatalf("phase error mismatch: %v", runErr)
			}
			if test.wantCleanErr != errors.Is(runErr, errLifecycleTeardown) {
				t.Fatalf("teardown error mismatch: %v", runErr)
			}
			if !test.wantPhaseErr && !test.wantCleanErr && runErr != nil {
				t.Fatalf("unexpected error: %v", runErr)
			}
			if !reflect.DeepEqual(calls, test.wantCalls) {
				t.Fatalf("calls = %v, want %v", calls, test.wantCalls)
			}
		})
	}
}

func TestTransactionalNamespaceExecutorTearsDownWhenBackendPanics(t *testing.T) {
	calls := []string{}
	session := &fakeNamespaceSession{calls: &calls, panicPhase: "nftables"}
	executor, err := NewTransactionalNamespaceExecutor(fakeProvisioner{session: session, calls: &calls}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_ = executor.Run(context.Background(), validXAttempt())
	}()
	if !errors.Is(recovered.(error), errLifecyclePhase) {
		t.Fatalf("unexpected panic: %v", recovered)
	}
	want := []string{"prepare", "wireguard", "nftables", "teardown"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func TestTransactionalNamespaceExecutorUsesIndependentCleanupContext(t *testing.T) {
	calls := []string{}
	session := &fakeNamespaceSession{calls: &calls}
	ctx, cancel := context.WithCancel(context.Background())
	executor, err := NewTransactionalNamespaceExecutor(fakeProvisioner{session: session, calls: &calls, afterPrepare: cancel}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	runErr := executor.Run(ctx, validXAttempt())
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", runErr)
	}
	if session.teardownContextErr != nil {
		t.Fatalf("cleanup inherited canceled context: %v", session.teardownContextErr)
	}
	want := []string{"prepare", "teardown"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func TestTransactionalNamespaceExecutorRejectsInvalidOrUnownedPreparation(t *testing.T) {
	calls := []string{}
	executor, err := NewTransactionalNamespaceExecutor(fakeProvisioner{calls: &calls}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := executor.Run(canceled, validXAttempt()); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected pre-canceled attempt rejection, got %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("provisioner called for pre-canceled attempt: %v", calls)
	}

	invalid := validXAttempt()
	invalid.JobID = "bad path"
	if err := executor.Run(context.Background(), invalid); err == nil {
		t.Fatal("expected invalid attempt rejection")
	}
	if len(calls) != 0 {
		t.Fatalf("provisioner called for invalid attempt: %v", calls)
	}

	if err := executor.Run(context.Background(), validXAttempt()); err == nil {
		t.Fatal("expected nil session rejection")
	}
	if !reflect.DeepEqual(calls, []string{"prepare"}) {
		t.Fatalf("unexpected calls: %v", calls)
	}
}

func validXAttempt() NamespaceAttempt {
	return NamespaceAttempt{JobID: "job_lifecycle_001", Platform: PlatformX, Endpoint: DefaultEndpointCatalog()[0]}
}
