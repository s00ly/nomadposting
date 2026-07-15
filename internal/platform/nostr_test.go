package platform

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const testNostrPubKey = "0000000000000000000000000000000000000000000000000000000000000000"

func TestNostrCanonicalSerializationAndID(t *testing.T) {
	event := UnsignedNostrEvent{
		PubKey:    testNostrPubKey,
		CreatedAt: 0,
		Kind:      NostrKindTextNote,
		Tags:      []NostrTag{},
		Content:   "hello <>&",
	}
	serialized, err := event.CanonicalSerialize()
	if err != nil {
		t.Fatal(err)
	}
	want := `[0,"` + testNostrPubKey + `",0,1,[],"hello <>&"]`
	if string(serialized) != want {
		t.Fatalf("serialization\n got: %s\nwant: %s", serialized, want)
	}
	id, err := event.ID()
	if err != nil {
		t.Fatal(err)
	}
	if id != "e3f2dfe0bc776cd4ccc7589ff19ec56e1a3b7b04b00ac5261552dd561ea98fe4" {
		t.Fatalf("ID = %s", id)
	}
}

type fakeNIP46Signer struct {
	publicKey string
	mutate    func(*NostrEvent)
	calls     int
}

func (f *fakeNIP46Signer) PublicKey(context.Context) (string, error) { return f.publicKey, nil }

func (f *fakeNIP46Signer) SignEvent(_ context.Context, unsigned UnsignedNostrEvent) (NostrEvent, error) {
	f.calls++
	id, err := unsigned.ID()
	if err != nil {
		return NostrEvent{}, err
	}
	event := NostrEvent{
		ID:        id,
		PubKey:    unsigned.PubKey,
		CreatedAt: unsigned.CreatedAt,
		Kind:      unsigned.Kind,
		Tags:      unsigned.Tags,
		Content:   unsigned.Content,
		Sig:       strings.Repeat("0", 128),
	}
	if f.mutate != nil {
		f.mutate(&event)
	}
	return event, nil
}

func TestSignNostrEventAcceptsExactRemoteEnvelope(t *testing.T) {
	signer := &fakeNIP46Signer{publicKey: testNostrPubKey}
	unsigned := UnsignedNostrEvent{
		PubKey:    testNostrPubKey,
		CreatedAt: 42,
		Kind:      NostrKindTextNote,
		Tags:      []NostrTag{{"client", "ivpn"}},
		Content:   "approved text",
	}
	event, err := SignNostrEvent(context.Background(), signer, unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if event.Content != unsigned.Content || event.ID == "" || signer.calls != 1 {
		t.Fatalf("event=%+v calls=%d", event, signer.calls)
	}
}

func TestSignNostrEventRejectsMutation(t *testing.T) {
	signer := &fakeNIP46Signer{
		publicKey: testNostrPubKey,
		mutate: func(event *NostrEvent) {
			event.Content = "changed after approval"
		},
	}
	_, err := SignNostrEvent(context.Background(), signer, UnsignedNostrEvent{
		PubKey:    testNostrPubKey,
		CreatedAt: 42,
		Kind:      NostrKindTextNote,
		Tags:      []NostrTag{},
		Content:   "approved text",
	})
	if code, ok := ErrorCodeOf(err); !ok || code != ErrSigning {
		t.Fatalf("error = %v, code = %q", err, code)
	}
}

func TestSignNostrEventRejectsUnapprovedKindBeforeSigning(t *testing.T) {
	signer := &fakeNIP46Signer{publicKey: testNostrPubKey}
	_, err := SignNostrEvent(context.Background(), signer, UnsignedNostrEvent{
		PubKey:    testNostrPubKey,
		CreatedAt: 42,
		Kind:      4,
		Tags:      []NostrTag{},
		Content:   "encrypted direct message",
	})
	if code, ok := ErrorCodeOf(err); !ok || code != ErrForbidden {
		t.Fatalf("error = %v, code = %q", err, code)
	}
	if signer.calls != 0 {
		t.Fatalf("unapproved kind reached signer %d times", signer.calls)
	}
}

func TestNostrEventRejectsUppercasePublicKey(t *testing.T) {
	event := UnsignedNostrEvent{
		PubKey:    strings.Repeat("A", 64),
		CreatedAt: 1,
		Kind:      NostrKindTextNote,
		Tags:      []NostrTag{},
		Content:   "hello",
	}
	if _, err := event.ID(); err == nil {
		t.Fatal("uppercase public key was accepted")
	}
}

type fakeRelayPublisher struct {
	results map[string]RelayResult
	errors  map[string]error
	events  []NostrEvent
}

func (p *fakeRelayPublisher) PublishEvent(_ context.Context, endpointID string, event NostrEvent) (RelayResult, error) {
	p.events = append(p.events, event)
	if err := p.errors[endpointID]; err != nil {
		return RelayResult{}, err
	}
	return p.results[endpointID], nil
}

func TestNostrConnectorSignsOnceReusesIDAndRequiresTwoAcknowledgements(t *testing.T) {
	signer := &fakeNIP46Signer{publicKey: testNostrPubKey}
	publisher := &fakeRelayPublisher{
		results: map[string]RelayResult{
			"relay-a": {Accepted: true, Code: "untrusted remote message"},
			"relay-b": {Accepted: true},
		},
		errors: map[string]error{"relay-c": errors.New("raw secret-bearing error")},
	}
	connector, err := NewNostrConnector(signer, publisher, []string{"relay-a", "relay-b", "relay-c"})
	if err != nil {
		t.Fatal(err)
	}
	connector.now = func() time.Time { return time.Unix(42, 0).UTC() }
	receipt, err := connector.Publish(context.Background(), PublishCommand{JobID: "job", Content: "approved text"})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != StateComplete || receipt.AttemptCount != 3 || signer.calls != 1 || len(publisher.events) != 3 {
		t.Fatalf("unexpected publication receipt=%+v signer_calls=%d events=%d", receipt, signer.calls, len(publisher.events))
	}
	for _, event := range publisher.events {
		if event.ID != receipt.ExternalID || event.Content != "approved text" || event.CreatedAt != 42 {
			t.Fatalf("relay received a different signed event: %+v", event)
		}
	}
	if receipt.RelayResults[0].EndpointID != "relay-a" || receipt.RelayResults[0].Code != "ok" || receipt.RelayResults[2].Code != "transport_error" {
		t.Fatalf("relay results were not normalized: %+v", receipt.RelayResults)
	}
}

func TestNostrConnectorReturnsPartialBelowQuorum(t *testing.T) {
	signer := &fakeNIP46Signer{publicKey: testNostrPubKey}
	publisher := &fakeRelayPublisher{results: map[string]RelayResult{
		"relay-a": {Accepted: true}, "relay-b": {Code: "auth_required"}, "relay-c": {Code: "arbitrary raw text"},
	}, errors: map[string]error{}}
	connector, err := NewNostrConnector(signer, publisher, []string{"relay-a", "relay-b", "relay-c"})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := connector.Publish(context.Background(), PublishCommand{Content: "approved text"})
	if err == nil || receipt.State != StatePartial || receipt.RelayResults[2].Code != "rejected" {
		t.Fatalf("unexpected partial result receipt=%+v err=%v", receipt, err)
	}
	if strings.Contains(err.Error(), "arbitrary") {
		t.Fatalf("raw relay error leaked: %v", err)
	}
}

func TestNostrConnectorRequiresThreeUniqueReviewedRelayIDs(t *testing.T) {
	signer := &fakeNIP46Signer{publicKey: testNostrPubKey}
	publisher := &fakeRelayPublisher{}
	for _, relays := range [][]string{{"one", "two"}, {"one", "one", "three"}, {"one", "wss://unreviewed", "three"}} {
		if _, err := NewNostrConnector(signer, publisher, relays); err == nil {
			t.Fatalf("invalid relay set was accepted: %v", relays)
		}
	}
}

func TestNIP42AuthEventBindsChallengeAndReviewedRelay(t *testing.T) {
	signer := &fakeNIP46Signer{publicKey: testNostrPubKey}
	event, err := SignNIP42AuthEvent(context.Background(), signer, "challenge-value", "wss://relay.example:443/", time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	if event.Kind != NostrKindRelayAuth || event.Content != "" || event.CreatedAt != 100 || len(event.Tags) != 2 ||
		event.Tags[0][0] != "relay" || event.Tags[0][1] != "wss://relay.example:443/" ||
		event.Tags[1][0] != "challenge" || event.Tags[1][1] != "challenge-value" {
		t.Fatalf("NIP-42 event was not exactly bound: %+v", event)
	}
	for _, relayURL := range []string{"ws://relay.example", "wss://relay.example:444", "wss://user@relay.example", "wss://relay.example?target=other"} {
		if _, err := SignNIP42AuthEvent(context.Background(), signer, "challenge", relayURL, time.Now()); err == nil {
			t.Fatalf("unsafe relay URL was accepted: %s", relayURL)
		}
	}
}
