package platform

import (
	"errors"
	"fmt"
	"time"
)

// ErrorCode is safe to persist. It is intentionally less detailed than a raw
// upstream error, which can contain post content, tokens, or infrastructure
// identifiers.
type ErrorCode string

const (
	ErrInvalidPayload   ErrorCode = "invalid_payload"
	ErrUnauthorized     ErrorCode = "unauthorized"
	ErrForbidden        ErrorCode = "forbidden"
	ErrRateLimited      ErrorCode = "rate_limited"
	ErrRemoteRejected   ErrorCode = "remote_rejected"
	ErrTemporary        ErrorCode = "temporary_failure"
	ErrAmbiguous        ErrorCode = "ambiguous_result"
	ErrResponseTooLarge ErrorCode = "response_too_large"
	ErrProtocol         ErrorCode = "protocol_error"
	ErrSigning          ErrorCode = "signing_failure"
)

// PlatformError is a normalized platform failure. Message must be a fixed,
// operator-safe string and must never contain raw response bodies or secrets.
type PlatformError struct {
	Platform   Platform
	Code       ErrorCode
	HTTPStatus int
	RetryAfter time.Duration
	Message    string
	Ambiguous  bool
	cause      error
}

func (e *PlatformError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Message != "" {
		return fmt.Sprintf("%s publish: %s", e.Platform, e.Message)
	}
	return fmt.Sprintf("%s publish: %s", e.Platform, e.Code)
}

// Unwrap supports errors.Is without exposing the cause in Error(). Callers
// must not persist or log the unwrapped transport error.
func (e *PlatformError) Unwrap() error { return e.cause }

// ErrorCodeOf extracts a normalized code without string matching.
func ErrorCodeOf(err error) (ErrorCode, bool) {
	var platformErr *PlatformError
	if !errors.As(err, &platformErr) {
		return "", false
	}
	return platformErr.Code, true
}
