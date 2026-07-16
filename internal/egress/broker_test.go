package egress

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBrokerDryRunAcceptsOnlyRegisteredTypedRequest(t *testing.T) {
	registry, err := NewRegistry(DefaultEndpointCatalog())
	if err != nil {
		t.Fatal(err)
	}
	broker, err := NewGuardedBroker(registry, DisabledNamespaceExecutor{}, false, DefaultBrokerPolicy())
	if err != nil {
		t.Fatal(err)
	}

	result, err := broker.DryRun(BrokerRequest{
		JobID: "job_broker_001", Platform: PlatformNostr, EndpointID: "gcp-ch-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted || !result.DryRun {
		t.Fatalf("unexpected result: %+v", result)
	}

	_, err = broker.DryRun(BrokerRequest{
		JobID: "job_broker_001", Platform: PlatformNostr, EndpointID: "arbitrary-address",
	})
	if !errors.Is(err, ErrUnknownEndpoint) {
		t.Fatalf("expected unknown endpoint error, got %v", err)
	}
	_, err = broker.DryRun(BrokerRequest{
		JobID: "bad path", Platform: PlatformNostr, EndpointID: "gcp-ch-1",
	})
	if err == nil {
		t.Fatal("expected invalid job ID rejection")
	}
}

func TestBrokerRejectsPlatformEndpointMismatchBeforeExecution(t *testing.T) {
	registry, err := NewRegistry(DefaultEndpointCatalog())
	if err != nil {
		t.Fatal(err)
	}
	broker, err := NewGuardedBroker(registry, DisabledNamespaceExecutor{}, false, DefaultBrokerPolicy())
	if err != nil {
		t.Fatal(err)
	}

	requests := []BrokerRequest{
		{JobID: "job_wrong_x_001", Platform: PlatformX, EndpointID: "gcp-de-1"},
		{JobID: "job_wrong_n_001", Platform: PlatformNostr, EndpointID: "aws-fr-1"},
	}
	for _, request := range requests {
		if _, err := broker.DryRun(request); !errors.Is(err, ErrEndpointPlatformMismatch) {
			t.Fatalf("dry run accepted mismatched request %+v: %v", request, err)
		}
		if _, err := broker.Execute(context.Background(), request, time.Now()); !errors.Is(err, ErrEndpointPlatformMismatch) {
			t.Fatalf("execute accepted mismatched request %+v: %v", request, err)
		}
	}
}

func TestBrokerPolicyRequiresDedicatedFranceXEndpoint(t *testing.T) {
	registry, err := NewRegistry(DefaultEndpointCatalog())
	if err != nil {
		t.Fatal(err)
	}
	policy := DefaultBrokerPolicy()
	policy.StableXEndpointID = "gcp-fr-1"
	if _, err := NewGuardedBroker(registry, DisabledNamespaceExecutor{}, false, policy); err == nil {
		t.Fatal("expected non-X endpoint policy rejection")
	}
}

func TestBrokerExecutionFailsClosedWhenDisabled(t *testing.T) {
	registry, err := NewRegistry(DefaultEndpointCatalog())
	if err != nil {
		t.Fatal(err)
	}
	broker, err := NewGuardedBroker(registry, DisabledNamespaceExecutor{}, false, DefaultBrokerPolicy())
	if err != nil {
		t.Fatal(err)
	}
	_, err = broker.Execute(context.Background(), BrokerRequest{
		JobID: "job_execute_01", Platform: PlatformX, EndpointID: "aws-fr-1",
	}, time.Now())
	if !errors.Is(err, ErrExecutionDisabled) {
		t.Fatalf("expected fail-closed disabled execution, got %v", err)
	}
}
