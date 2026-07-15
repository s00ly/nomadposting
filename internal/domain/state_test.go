package domain

import (
	"errors"
	"testing"
)

func TestApprovalHashIsStableAndBindsDestinations(t *testing.T) {
	a, err := ApprovalHash("hello\r\nworld", true, true, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ApprovalHash("hello\nworld", true, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("line ending normalization changed hash: %s != %s", a, b)
	}
	c, err := ApprovalHash("hello\nworld", false, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if a == c {
		t.Fatal("destination change did not change approval hash")
	}
}

func TestApprovalHashRejectsUnsafeInput(t *testing.T) {
	if _, err := ApprovalHash("", true, true, ""); !errors.Is(err, ErrInvalidContent) {
		t.Fatalf("expected invalid content, got %v", err)
	}
	if _, err := ApprovalHash("hello\x00", true, true, ""); !errors.Is(err, ErrInvalidContent) {
		t.Fatalf("expected NUL rejection, got %v", err)
	}
	if _, err := ApprovalHash("hello", false, false, ""); !errors.Is(err, ErrNoDestination) {
		t.Fatalf("expected destination rejection, got %v", err)
	}
}

func TestStateMachineBlocksUnsafeRetry(t *testing.T) {
	if CanTransition(StateUnknown, StatePublishing) {
		t.Fatal("UNKNOWN must not be blindly republished")
	}
	if !CanTransition(StateUnknown, StateComplete) {
		t.Fatal("UNKNOWN must support reconciliation to COMPLETE")
	}
	if CanTransition(StateComplete, StatePublishing) {
		t.Fatal("completed jobs must be terminal")
	}
}
