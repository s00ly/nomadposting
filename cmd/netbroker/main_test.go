package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"testing"

	"ivpn/internal/egress"
)

func TestWireProtocolRejectsUnrecognizedFields(t *testing.T) {
	broker := testBroker(t)
	response := exchange(t, broker, `{"operation":"dry_run","request":{"job_id":"job_wire_0001","platform":"nostr","endpoint_id":"gcp-fr-1","address":"203.0.113.1"}}`)
	if response.OK || response.Code != "INVALID_REQUEST" {
		t.Fatalf("expected schema rejection, got %+v", response)
	}
}

func TestWireProtocolDryRunKnownEndpoint(t *testing.T) {
	broker := testBroker(t)
	response := exchange(t, broker, `{"operation":"dry_run","request":{"job_id":"job_wire_0002","platform":"nostr","endpoint_id":"gcp-fr-1"}}`)
	if !response.OK {
		t.Fatalf("expected dry-run success, got %+v", response)
	}
}

func TestWireProtocolRejectsPlatformEndpointMismatch(t *testing.T) {
	broker := testBroker(t)
	response := exchange(t, broker, `{"operation":"dry_run","request":{"job_id":"job_wire_0003","platform":"x","endpoint_id":"gcp-de-1"}}`)
	if response.OK || response.Code != "ENDPOINT_PLATFORM_MISMATCH" || response.Error != "endpoint is not allowed for the requested platform" {
		t.Fatalf("expected platform endpoint rejection, got %+v", response)
	}
}

func testBroker(t *testing.T) *egress.GuardedBroker {
	t.Helper()
	registry, err := egress.NewRegistry(egress.DefaultEndpointCatalog())
	if err != nil {
		t.Fatal(err)
	}
	broker, err := egress.NewGuardedBroker(registry, egress.DisabledNamespaceExecutor{}, false, egress.DefaultBrokerPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return broker
}

func exchange(t *testing.T, broker *egress.GuardedBroker, payload string) wireResponse {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		handleConnection(context.Background(), broker, server)
		close(done)
	}()
	if _, err := client.Write([]byte(payload + "\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(client).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	<-done
	var response wireResponse
	if err := json.Unmarshal(line, &response); err != nil {
		t.Fatal(err)
	}
	return response
}
