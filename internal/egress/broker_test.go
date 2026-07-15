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
	broker, err := NewGuardedBroker(registry, DisabledNamespaceExecutor{}, false, 90*time.Second)
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

func TestBrokerExecutionFailsClosedWhenDisabled(t *testing.T) {
	registry, err := NewRegistry(DefaultEndpointCatalog())
	if err != nil {
		t.Fatal(err)
	}
	broker, err := NewGuardedBroker(registry, DisabledNamespaceExecutor{}, false, 90*time.Second)
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
