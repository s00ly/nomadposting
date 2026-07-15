package platform

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func testTokenSource() BearerTokenSource {
	return BearerTokenSourceFunc(func(context.Context) (string, error) { return "test-token", nil })
}

func TestXConnectorDryRunUsesFixedEndpointAndNoGeo(t *testing.T) {
	transport := &DryRunTransport{}
	connector, err := NewXConnector(transport, testTokenSource())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := connector.Publish(context.Background(), PublishCommand{Content: "hello from a private route"})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != StateComplete || receipt.ExternalID != "dry-run" || receipt.AttemptCount != 1 {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	captures := transport.Captures()
	if len(captures) != 1 {
		t.Fatalf("got %d requests, want exactly 1", len(captures))
	}
	capture := captures[0]
	if capture.Method != http.MethodPost || capture.URL != XCreatePostEndpoint {
		t.Fatalf("unexpected target: %s %s", capture.Method, capture.URL)
	}
	if !capture.AuthorizationPresent {
		t.Fatal("authorization presence was not recorded")
	}
	if strings.Contains(string(capture.Body), "geo") {
		t.Fatalf("request unexpectedly contains geo: %s", capture.Body)
	}
	if got, want := string(capture.Body), `{"text":"hello from a private route"}`; got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
	if strings.Contains(string(capture.Body), "test-token") {
		t.Fatal("dry-run capture contains the bearer token")
	}
}

func TestXConnectorRejectsInvalidTextBeforeCredentialOrTransport(t *testing.T) {
	transport := &DryRunTransport{}
	tokenCalls := 0
	connector, err := NewXConnector(transport, BearerTokenSourceFunc(func(context.Context) (string, error) {
		tokenCalls++
		return "test-token", nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = connector.Publish(context.Background(), PublishCommand{Content: strings.Repeat("a", 281)})
	if code, ok := ErrorCodeOf(err); !ok || code != ErrInvalidPayload {
		t.Fatalf("error = %v, code = %q", err, code)
	}
	if tokenCalls != 0 || len(transport.Captures()) != 0 {
		t.Fatalf("invalid payload touched credential/network: tokens=%d requests=%d", tokenCalls, len(transport.Captures()))
	}
}

func TestXWeightedLength(t *testing.T) {
	if got := XWeightedLength("ascii"); got != 5 {
		t.Fatalf("ASCII weight = %d", got)
	}
	if got := XWeightedLength("🙂"); got != 2 {
		t.Fatalf("emoji weight = %d", got)
	}
	if got := XWeightedLength("see https://example.com/a/very/long/path"); got != 27 {
		t.Fatalf("URL weight = %d", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

type refreshingTokenSource struct {
	refreshCalls int
}

func (s *refreshingTokenSource) BearerToken(context.Context) (string, error) {
	return "expired-token", nil
}

func (s *refreshingTokenSource) RefreshBearerToken(context.Context) (string, error) {
	s.refreshCalls++
	return "refreshed-token", nil
}

func TestXConnectorRefreshesOnceAfterDefinitive401(t *testing.T) {
	tokens := &refreshingTokenSource{}
	calls := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		expected := "Bearer expired-token"
		status, body := http.StatusUnauthorized, `{}`
		if calls == 2 {
			expected = "Bearer refreshed-token"
			status, body = http.StatusCreated, `{"data":{"id":"post-id"}}`
		}
		if request.Header.Get("Authorization") != expected {
			t.Fatalf("call %d used unexpected credential", calls)
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
	})
	connector, err := NewXConnector(transport, tokens)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := connector.Publish(context.Background(), PublishCommand{Content: "safe retry"})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || tokens.refreshCalls != 1 || receipt.AttemptCount != 2 || receipt.ExternalID != "post-id" || receipt.State != StateComplete {
		t.Fatalf("unexpected retry outcome calls=%d refreshes=%d receipt=%+v", calls, tokens.refreshCalls, receipt)
	}
}

func TestXConnectorClassifiesStatusAndDoesNotRetry(t *testing.T) {
	calls := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Header:     http.Header{"Retry-After": []string{"12"}},
			Body:       io.NopCloser(strings.NewReader(`{"detail":"must not enter the error"}`)),
			Request:    request,
		}, nil
	})
	connector, _ := NewXConnector(transport, testTokenSource())
	_, err := connector.Publish(context.Background(), PublishCommand{Content: "hello"})
	var platformErr *PlatformError
	if !errors.As(err, &platformErr) || platformErr.Code != ErrRateLimited || platformErr.RetryAfter.Seconds() != 12 {
		t.Fatalf("unexpected error: %#v", err)
	}
	if calls != 1 {
		t.Fatalf("transport calls = %d, want 1", calls)
	}
	if strings.Contains(err.Error(), "detail") {
		t.Fatalf("raw response leaked into error: %v", err)
	}
}

func TestXRateLimitResetHeaderIsHonoredWithoutRetry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	header := make(http.Header)
	header.Set("x-rate-limit-reset", "1800000042")
	err := classifyXStatusAt(http.StatusTooManyRequests, header, now)
	var platformErr *PlatformError
	if !errors.As(err, &platformErr) || platformErr.RetryAfter != 42*time.Second {
		t.Fatalf("unexpected reset classification: %#v", err)
	}
}

func TestClassifyXStatus(t *testing.T) {
	tests := []struct {
		name   string
		status int
		code   ErrorCode
	}{
		{name: "invalid request", status: http.StatusBadRequest, code: ErrRemoteRejected},
		{name: "expired credential", status: http.StatusUnauthorized, code: ErrUnauthorized},
		{name: "credits exhausted", status: http.StatusPaymentRequired, code: ErrForbidden},
		{name: "account policy", status: http.StatusForbidden, code: ErrForbidden},
		{name: "rate limit", status: http.StatusTooManyRequests, code: ErrRateLimited},
		{name: "upstream unavailable", status: http.StatusBadGateway, code: ErrTemporary},
		{name: "unexpected", status: http.StatusTeapot, code: ErrProtocol},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, ok := ErrorCodeOf(classifyXStatus(test.status, make(http.Header)))
			if !ok || code != test.code {
				t.Fatalf("status %d classified as %q, want %q", test.status, code, test.code)
			}
		})
	}
}

func TestXConnectorBoundsResponse(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusCreated,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(strings.Repeat("x", XMaxResponseBytes+1))),
			Request:    request,
		}, nil
	})
	connector, _ := NewXConnector(transport, testTokenSource())
	receipt, err := connector.Publish(context.Background(), PublishCommand{Content: "hello"})
	if code, ok := ErrorCodeOf(err); !ok || code != ErrResponseTooLarge {
		t.Fatalf("error = %v, code = %q", err, code)
	}
	if receipt.State != StateUnknown {
		t.Fatalf("state = %s, want UNKNOWN", receipt.State)
	}
}

func TestXConnectorTreatsTransportFailureAsAmbiguous(t *testing.T) {
	calls := 0
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("secret-bearing transport detail")
	})
	connector, _ := NewXConnector(transport, testTokenSource())
	receipt, err := connector.Publish(context.Background(), PublishCommand{Content: "hello"})
	var platformErr *PlatformError
	if !errors.As(err, &platformErr) || !platformErr.Ambiguous || platformErr.Code != ErrAmbiguous {
		t.Fatalf("unexpected error: %#v", err)
	}
	if receipt.State != StateUnknown || calls != 1 {
		t.Fatalf("receipt=%+v calls=%d", receipt, calls)
	}
	if strings.Contains(err.Error(), "secret-bearing") {
		t.Fatalf("transport detail leaked into safe error: %v", err)
	}
}
