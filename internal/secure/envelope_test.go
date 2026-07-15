package secure

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestEnvelopeRoundTripAndContextBinding(t *testing.T) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	envelope, err := NewEnvelope(key)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := envelope.Seal([]byte("private post"), []byte("job-1"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := envelope.Open(sealed, []byte("job-1"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, []byte("private post")) {
		t.Fatalf("unexpected plaintext %q", opened)
	}
	if _, err := envelope.Open(sealed, []byte("job-2")); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("associated-data substitution was not rejected: %v", err)
	}
}

func TestEnvelopeRejectsTampering(t *testing.T) {
	key := make([]byte, keySize)
	_, _ = rand.Read(key)
	envelope, _ := NewEnvelope(key)
	sealed, _ := envelope.Seal([]byte("private post"), []byte("job-1"))
	sealed[len(sealed)-1] ^= 0xff
	if _, err := envelope.Open(sealed, []byte("job-1")); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("tampering was not rejected: %v", err)
	}
}
