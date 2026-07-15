package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"
)

var (
	ErrInvalidContent    = errors.New("content must be valid UTF-8, non-empty, and contain no NUL bytes")
	ErrNoDestination     = errors.New("at least one destination is required")
	ErrInvalidTransition = errors.New("invalid job state transition")
)

var transitions = map[JobState]map[JobState]bool{
	StateDraft:      {StateApproved: true, StateCancelled: true},
	StateApproved:   {StateRouting: true, StateCancelled: true},
	StateRouting:    {StatePublishing: true, StateFailed: true, StateCancelled: true},
	StatePublishing: {StateComplete: true, StatePartial: true, StateFailed: true, StateUnknown: true},
	StatePartial:    {StatePublishing: true, StateComplete: true, StateFailed: true, StateUnknown: true},
	StateFailed:     {StateRouting: true, StateCancelled: true},
	StateUnknown:    {StateComplete: true, StateFailed: true, StatePartial: true},
}

func CanTransition(from, to JobState) bool {
	return transitions[from][to]
}

func ValidateTransition(from, to JobState) error {
	if !CanTransition(from, to) {
		return ErrInvalidTransition
	}
	return nil
}

func NormalizeContent(content string) (string, error) {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")
	if !utf8.ValidString(content) || strings.ContainsRune(content, '\x00') || strings.TrimSpace(content) == "" {
		return "", ErrInvalidContent
	}
	return content, nil
}

func ApprovalHash(content string, postToX, postToNostr bool, scheduledAt string) (string, error) {
	if !postToX && !postToNostr {
		return "", ErrNoDestination
	}
	normalized, err := NormalizeContent(content)
	if err != nil {
		return "", err
	}
	payload := struct {
		Version     int    `json:"version"`
		Content     string `json:"content"`
		PostToX     bool   `json:"post_to_x"`
		PostToNostr bool   `json:"post_to_nostr"`
		ScheduledAt string `json:"scheduled_at"`
	}{1, normalized, postToX, postToNostr, scheduledAt}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
