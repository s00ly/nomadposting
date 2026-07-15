package platform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	NostrKindTextNote  = 1
	NostrKindRelayAuth = 22242
	NostrMaxContent    = 64 << 10
)

// NostrTag is a NIP-01 tag. A distinct type prevents accidental use of an
// object, whose key ordering would not be part of the event format.
type NostrTag []string

// UnsignedNostrEvent contains exactly the fields committed by a NIP-01 event
// ID. It contains no private key or signing material.
type UnsignedNostrEvent struct {
	PubKey    string
	CreatedAt int64
	Kind      int
	Tags      []NostrTag
	Content   string
}

// NostrEvent is the signed NIP-01 wire object.
type NostrEvent struct {
	ID        string     `json:"id"`
	PubKey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      []NostrTag `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

// NIP46Signer represents remote signing only. Deliberately absent are nsec,
// private-key import/export, and arbitrary RPC methods.
type NIP46Signer interface {
	PublicKey(context.Context) (string, error)
	SignEvent(context.Context, UnsignedNostrEvent) (NostrEvent, error)
}

// NostrRelayPublisher sends an already-signed event to one reviewed endpoint
// selected by identifier. URL resolution stays outside this platform contract.
type NostrRelayPublisher interface {
	PublishEvent(context.Context, string, NostrEvent) (RelayResult, error)
}

type NostrConnector struct {
	signer    NIP46Signer
	publisher NostrRelayPublisher
	relays    []string
	now       func() time.Time
}

// NewNostrConnector requires exactly three pre-reviewed relay endpoint IDs.
// URLs remain in the egress registry and cannot be supplied by a post command.
func NewNostrConnector(signer NIP46Signer, publisher NostrRelayPublisher, relayEndpointIDs []string) (*NostrConnector, error) {
	if signer == nil || publisher == nil {
		return nil, errors.New("Nostr connector requires a remote signer and relay publisher")
	}
	if len(relayEndpointIDs) != 3 {
		return nil, errors.New("Nostr connector requires exactly three reviewed relays")
	}
	relays := append([]string(nil), relayEndpointIDs...)
	for _, relay := range relays {
		if strings.TrimSpace(relay) == "" || len(relay) > 128 || strings.ContainsAny(relay, "\r\n/\\: ") {
			return nil, errors.New("Nostr relay endpoint ID is invalid")
		}
	}
	sorted := append([]string(nil), relays...)
	sort.Strings(sorted)
	for index := 1; index < len(sorted); index++ {
		if sorted[index] == sorted[index-1] {
			return nil, errors.New("Nostr relay endpoint IDs must be unique")
		}
	}
	return &NostrConnector{signer: signer, publisher: publisher, relays: relays, now: time.Now}, nil
}

// Publish signs one kind-1 event exactly once and submits that immutable event
// to all three reviewed relays. Two acknowledgements are complete, one is
// partial, and none is failed.
func (c *NostrConnector) Publish(ctx context.Context, command PublishCommand) (Receipt, error) {
	receipt := Receipt{Platform: PlatformNostr, State: StateFailed, CreatedAt: c.now().UTC()}
	if strings.TrimSpace(command.Content) == "" || !utf8.ValidString(command.Content) || len(command.Content) > NostrMaxContent {
		return receipt, &PlatformError{Platform: PlatformNostr, Code: ErrInvalidPayload, Message: "Nostr text is invalid"}
	}
	pubkey, err := c.signer.PublicKey(ctx)
	if err != nil {
		return receipt, &PlatformError{Platform: PlatformNostr, Code: ErrSigning, Message: "remote signer public key lookup failed", cause: err}
	}
	unsigned := UnsignedNostrEvent{
		PubKey: pubkey, CreatedAt: receipt.CreatedAt.Unix(), Kind: NostrKindTextNote, Tags: []NostrTag{}, Content: command.Content,
	}
	event, err := SignNostrEvent(ctx, c.signer, unsigned)
	if err != nil {
		return receipt, err
	}
	receipt.ExternalID = event.ID
	accepted := 0
	for _, relayID := range c.relays {
		receipt.AttemptCount++
		result, publishErr := c.publisher.PublishEvent(ctx, relayID, event)
		if publishErr != nil {
			receipt.RelayResults = append(receipt.RelayResults, RelayResult{EndpointID: relayID, Code: "transport_error"})
			continue
		}
		result.EndpointID = relayID
		result.Code = normalizeRelayCode(result.Accepted, result.Code)
		if result.Accepted {
			accepted++
		}
		receipt.RelayResults = append(receipt.RelayResults, result)
	}
	switch accepted {
	case 3, 2:
		receipt.State = StateComplete
		return receipt, nil
	case 1:
		receipt.State = StatePartial
		return receipt, &PlatformError{Platform: PlatformNostr, Code: ErrRemoteRejected, Message: "Nostr relay quorum was not reached"}
	default:
		receipt.State = StateFailed
		return receipt, &PlatformError{Platform: PlatformNostr, Code: ErrRemoteRejected, Message: "Nostr publication was not acknowledged"}
	}
}

func normalizeRelayCode(accepted bool, code string) string {
	if accepted {
		return "ok"
	}
	switch code {
	case "rejected", "auth_required", "duplicate", "timeout", "protocol_error":
		return code
	default:
		return "rejected"
	}
}

// CanonicalSerialize returns the compact NIP-01 event-ID serialization:
// [0,pubkey,created_at,kind,tags,content]. HTML escaping is disabled because
// those substitutions change the event ID.
func (event UnsignedNostrEvent) CanonicalSerialize() ([]byte, error) {
	if err := event.Validate(); err != nil {
		return nil, err
	}
	payload := []any{0, event.PubKey, event.CreatedAt, event.Kind, event.Tags, event.Content}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		return nil, fmt.Errorf("encode NIP-01 event: %w", err)
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}

// ID computes the lowercase SHA-256 NIP-01 event ID.
func (event UnsignedNostrEvent) ID() (string, error) {
	serialized, err := event.CanonicalSerialize()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(serialized)
	return hex.EncodeToString(sum[:]), nil
}

func (event UnsignedNostrEvent) Validate() error {
	if !isLowerHex(event.PubKey, 64) {
		return &PlatformError{Platform: PlatformNostr, Code: ErrInvalidPayload, Message: "public key must be 32-byte lowercase hex"}
	}
	if event.CreatedAt < 0 {
		return &PlatformError{Platform: PlatformNostr, Code: ErrInvalidPayload, Message: "created_at is invalid"}
	}
	if event.Kind < 0 {
		return &PlatformError{Platform: PlatformNostr, Code: ErrInvalidPayload, Message: "event kind is invalid"}
	}
	if event.Tags == nil {
		return &PlatformError{Platform: PlatformNostr, Code: ErrInvalidPayload, Message: "event tags must be an array"}
	}
	if !utf8.ValidString(event.Content) || len(event.Content) > NostrMaxContent {
		return &PlatformError{Platform: PlatformNostr, Code: ErrInvalidPayload, Message: "event content is invalid"}
	}
	for _, tag := range event.Tags {
		if tag == nil {
			return &PlatformError{Platform: PlatformNostr, Code: ErrInvalidPayload, Message: "event contains a null tag"}
		}
		for _, value := range tag {
			if !utf8.ValidString(value) {
				return &PlatformError{Platform: PlatformNostr, Code: ErrInvalidPayload, Message: "event tag is not valid UTF-8"}
			}
		}
	}
	return nil
}

// SignNostrEvent permits only kind 1 publications and kind 22242 relay auth.
// It verifies the returned envelope is exactly the event that was requested.
// Cryptographic Schnorr verification belongs in the concrete NIP-46 adapter.
func SignNostrEvent(ctx context.Context, signer NIP46Signer, unsigned UnsignedNostrEvent) (NostrEvent, error) {
	if signer == nil {
		return NostrEvent{}, &PlatformError{Platform: PlatformNostr, Code: ErrSigning, Message: "remote signer is unavailable"}
	}
	if unsigned.Kind != NostrKindTextNote && unsigned.Kind != NostrKindRelayAuth {
		return NostrEvent{}, &PlatformError{Platform: PlatformNostr, Code: ErrForbidden, Message: "event kind is not permitted"}
	}
	publicKey, err := signer.PublicKey(ctx)
	if err != nil {
		return NostrEvent{}, &PlatformError{Platform: PlatformNostr, Code: ErrSigning, Message: "remote signer public key lookup failed", cause: err}
	}
	if !isLowerHex(publicKey, 64) || unsigned.PubKey != publicKey {
		return NostrEvent{}, &PlatformError{Platform: PlatformNostr, Code: ErrSigning, Message: "remote signer identity mismatch"}
	}
	expectedID, err := unsigned.ID()
	if err != nil {
		return NostrEvent{}, err
	}
	signed, err := signer.SignEvent(ctx, unsigned)
	if err != nil {
		return NostrEvent{}, &PlatformError{Platform: PlatformNostr, Code: ErrSigning, Message: "remote signing failed", cause: err}
	}
	if err := validateSignedEnvelope(unsigned, expectedID, signed); err != nil {
		return NostrEvent{}, err
	}
	return signed, nil
}

// SignNIP42AuthEvent binds a relay challenge to the exact reviewed wss://
// relay URL. It cannot authorize a different relay or an unapproved kind.
func SignNIP42AuthEvent(ctx context.Context, signer NIP46Signer, challenge, relayURL string, now time.Time) (NostrEvent, error) {
	if strings.TrimSpace(challenge) == "" || len(challenge) > 512 || strings.ContainsAny(challenge, "\r\n") {
		return NostrEvent{}, &PlatformError{Platform: PlatformNostr, Code: ErrInvalidPayload, Message: "relay authentication challenge is invalid"}
	}
	parsed, err := url.Parse(relayURL)
	if err != nil || parsed.Scheme != "wss" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Port() != "" && parsed.Port() != "443") {
		return NostrEvent{}, &PlatformError{Platform: PlatformNostr, Code: ErrInvalidPayload, Message: "relay authentication URL is invalid"}
	}
	if signer == nil {
		return NostrEvent{}, &PlatformError{Platform: PlatformNostr, Code: ErrSigning, Message: "remote signer is unavailable"}
	}
	publicKey, err := signer.PublicKey(ctx)
	if err != nil {
		return NostrEvent{}, &PlatformError{Platform: PlatformNostr, Code: ErrSigning, Message: "remote signer public key lookup failed", cause: err}
	}
	return SignNostrEvent(ctx, signer, UnsignedNostrEvent{
		PubKey: publicKey, CreatedAt: now.UTC().Unix(), Kind: NostrKindRelayAuth,
		Tags: []NostrTag{{"relay", relayURL}, {"challenge", challenge}}, Content: "",
	})
}

func validateSignedEnvelope(unsigned UnsignedNostrEvent, expectedID string, signed NostrEvent) error {
	if signed.ID != expectedID || signed.PubKey != unsigned.PubKey || signed.CreatedAt != unsigned.CreatedAt ||
		signed.Kind != unsigned.Kind || signed.Content != unsigned.Content || !reflect.DeepEqual(signed.Tags, unsigned.Tags) {
		return &PlatformError{Platform: PlatformNostr, Code: ErrSigning, Message: "remote signer changed the approved event"}
	}
	if !isLowerHex(signed.Sig, 128) {
		return &PlatformError{Platform: PlatformNostr, Code: ErrSigning, Message: "remote signer returned an invalid signature encoding"}
	}
	return nil
}

func isLowerHex(value string, length int) bool {
	if len(value) != length || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
