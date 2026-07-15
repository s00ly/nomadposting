package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	// XCreatePostEndpoint is fixed so configuration cannot redirect credentials
	// or approved content to an arbitrary host.
	XCreatePostEndpoint = "https://api.x.com/2/tweets"
	XMaxWeightedLength  = 280
	XMaxResponseBytes   = 32 << 10
	xTransformedURLLen  = 23
)

var xURLPattern = regexp.MustCompile(`https?://[^\s]+`)

// BearerTokenSource retrieves an OAuth 2.0 access token from secret custody.
// Implementations should return a short-lived in-memory value and never log it.
type BearerTokenSource interface {
	BearerToken(context.Context) (string, error)
}

// RefreshingBearerTokenSource permits the single safe retry allowed by the
// publication policy: a definitive 401 may refresh once and retry through the
// same connector transport and therefore the same pinned egress lease.
type RefreshingBearerTokenSource interface {
	BearerTokenSource
	RefreshBearerToken(context.Context) (string, error)
}

// BearerTokenSourceFunc adapts a function into a BearerTokenSource.
type BearerTokenSourceFunc func(context.Context) (string, error)

func (f BearerTokenSourceFunc) BearerToken(ctx context.Context) (string, error) {
	return f(ctx)
}

// XConnector performs one official API request per Publish call, except for a
// single refresh-and-retry after a definitive 401. It does not follow
// redirects, rotate egress, attach geo data, or persist raw remote errors.
type XConnector struct {
	client *http.Client
	tokens BearerTokenSource
	now    func() time.Time
}

// NewXConnector constructs a connector around an explicit transport. A nil
// transport uses http.DefaultTransport. Redirects are always rejected.
func NewXConnector(transport http.RoundTripper, tokens BearerTokenSource) (*XConnector, error) {
	if tokens == nil {
		return nil, errors.New("x connector requires a bearer token source")
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &XConnector{
		client: &http.Client{
			Transport: transport,
			Timeout:   20 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		tokens: tokens,
		now:    time.Now,
	}, nil
}

// xCreatePostRequest is intentionally closed: geo and all unrelated API
// fields cannot be represented by this connector.
type xCreatePostRequest struct {
	Text string `json:"text"`
}

type xCreatePostResponse struct {
	Data struct {
		ID string `json:"id"`
	} `json:"data"`
}

func (c *XConnector) Publish(ctx context.Context, command PublishCommand) (Receipt, error) {
	receipt := Receipt{
		Platform:     PlatformX,
		State:        StateFailed,
		AttemptCount: 0,
		CreatedAt:    c.now().UTC(),
	}
	if err := ValidateXText(command.Content); err != nil {
		return receipt, err
	}

	token, err := c.tokens.BearerToken(ctx)
	if err != nil {
		return receipt, &PlatformError{Platform: PlatformX, Code: ErrUnauthorized, Message: "credential retrieval failed", cause: err}
	}
	if strings.TrimSpace(token) == "" || strings.ContainsAny(token, "\r\n") {
		return receipt, &PlatformError{Platform: PlatformX, Code: ErrUnauthorized, Message: "credential is unavailable"}
	}
	err = c.publishOnce(ctx, command.Content, token, &receipt)
	var platformErr *PlatformError
	if !errors.As(err, &platformErr) || platformErr.HTTPStatus != http.StatusUnauthorized {
		return receipt, err
	}
	refresher, ok := c.tokens.(RefreshingBearerTokenSource)
	if !ok {
		return receipt, err
	}
	refreshed, refreshErr := refresher.RefreshBearerToken(ctx)
	if refreshErr != nil || strings.TrimSpace(refreshed) == "" || strings.ContainsAny(refreshed, "\r\n") {
		return receipt, &PlatformError{Platform: PlatformX, Code: ErrUnauthorized, HTTPStatus: http.StatusUnauthorized, Message: "credential refresh failed", cause: refreshErr}
	}
	err = c.publishOnce(ctx, command.Content, refreshed, &receipt)
	return receipt, err
}

func (c *XConnector) publishOnce(ctx context.Context, content, token string, receipt *Receipt) error {
	body, err := json.Marshal(xCreatePostRequest{Text: content})
	if err != nil {
		return &PlatformError{Platform: PlatformX, Code: ErrInvalidPayload, Message: "payload encoding failed", cause: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, XCreatePostEndpoint, bytes.NewReader(body))
	if err != nil {
		return &PlatformError{Platform: PlatformX, Code: ErrInvalidPayload, Message: "request construction failed", cause: err}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ivpn-crossposter/1")

	// A transport failure is ambiguous because net/http cannot prove whether the
	// remote service accepted the request.
	receipt.AttemptCount++
	resp, err := c.client.Do(req)
	if err != nil {
		receipt.State = StateUnknown
		return &PlatformError{Platform: PlatformX, Code: ErrAmbiguous, Message: "publication result is unknown", Ambiguous: true, cause: err}
	}
	defer resp.Body.Close()

	responseBody, tooLarge, err := readBounded(resp.Body, XMaxResponseBytes)
	if err != nil {
		receipt.State = StateUnknown
		return &PlatformError{Platform: PlatformX, Code: ErrAmbiguous, HTTPStatus: resp.StatusCode, Message: "response could not be read", Ambiguous: true, cause: err}
	}
	if tooLarge {
		receipt.State = StateUnknown
		return &PlatformError{Platform: PlatformX, Code: ErrResponseTooLarge, HTTPStatus: resp.StatusCode, Message: "response exceeded the safety limit", Ambiguous: true}
	}

	if resp.StatusCode != http.StatusCreated {
		return classifyXStatusAt(resp.StatusCode, resp.Header, c.now().UTC())
	}

	var decoded xCreatePostResponse
	if err := json.Unmarshal(responseBody, &decoded); err != nil || strings.TrimSpace(decoded.Data.ID) == "" {
		receipt.State = StateUnknown
		return &PlatformError{Platform: PlatformX, Code: ErrProtocol, HTTPStatus: resp.StatusCode, Message: "success response was invalid", Ambiguous: true, cause: err}
	}
	receipt.State = StateComplete
	receipt.ExternalID = decoded.Data.ID
	return nil
}

func classifyXStatus(status int, header http.Header) error {
	return classifyXStatusAt(status, header, time.Now().UTC())
}

func classifyXStatusAt(status int, header http.Header, now time.Time) error {
	platformErr := &PlatformError{Platform: PlatformX, HTTPStatus: status}
	switch status {
	case http.StatusBadRequest, http.StatusNotFound, http.StatusUnprocessableEntity:
		platformErr.Code = ErrRemoteRejected
		platformErr.Message = "request was rejected"
	case http.StatusUnauthorized:
		platformErr.Code = ErrUnauthorized
		platformErr.Message = "authorization was rejected"
	case http.StatusPaymentRequired:
		platformErr.Code = ErrForbidden
		platformErr.Message = "API credits are unavailable"
	case http.StatusForbidden:
		platformErr.Code = ErrForbidden
		platformErr.Message = "publication is forbidden"
	case http.StatusTooManyRequests:
		platformErr.Code = ErrRateLimited
		platformErr.Message = "rate limit reached"
		if seconds, err := strconv.ParseInt(header.Get("Retry-After"), 10, 64); err == nil && seconds > 0 {
			platformErr.RetryAfter = time.Duration(seconds) * time.Second
		} else if reset, err := strconv.ParseInt(header.Get("x-rate-limit-reset"), 10, 64); err == nil {
			resetAt := time.Unix(reset, 0).UTC()
			if resetAt.After(now) {
				platformErr.RetryAfter = resetAt.Sub(now)
			}
		}
	default:
		if status >= 500 && status <= 599 {
			platformErr.Code = ErrTemporary
			platformErr.Message = "remote service is unavailable"
		} else {
			platformErr.Code = ErrProtocol
			platformErr.Message = "unexpected remote response"
		}
	}
	return platformErr
}

func readBounded(reader io.Reader, maximum int64) ([]byte, bool, error) {
	limited := io.LimitReader(reader, maximum+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > maximum {
		return nil, true, nil
	}
	return data, false, nil
}

// ValidateXText performs deterministic local checks before credentials or the
// network are touched. X remains the final authority on its evolving rules.
func ValidateXText(text string) error {
	if !utf8.ValidString(text) {
		return &PlatformError{Platform: PlatformX, Code: ErrInvalidPayload, Message: "text is not valid UTF-8"}
	}
	if strings.TrimSpace(text) == "" {
		return &PlatformError{Platform: PlatformX, Code: ErrInvalidPayload, Message: "text is empty"}
	}
	for _, r := range text {
		if (r < 0x20 && r != '\n' && r != '\r' && r != '\t') || (r >= 0x7f && r <= 0x9f) {
			return &PlatformError{Platform: PlatformX, Code: ErrInvalidPayload, Message: "text contains a disallowed control character"}
		}
	}
	if XWeightedLength(text) > XMaxWeightedLength {
		return &PlatformError{Platform: PlatformX, Code: ErrInvalidPayload, Message: "text exceeds the weighted length limit"}
	}
	return nil
}

// XWeightedLength implements the public twitter-text v3 weighting ranges and
// the transformed HTTPS/HTTP URL length. It deliberately does not truncate.
func XWeightedLength(text string) int {
	weight := 0
	last := 0
	for _, location := range xURLPattern.FindAllStringIndex(text, -1) {
		weight += xRuneWeight(text[last:location[0]])
		weight += xTransformedURLLen
		last = location[1]
	}
	return weight + xRuneWeight(text[last:])
}

func xRuneWeight(text string) int {
	weight := 0
	for _, r := range text {
		switch {
		case r >= 0 && r <= 0x10ff:
			weight++
		case r >= 0x2000 && r <= 0x200d:
			weight++
		case r >= 0x2010 && r <= 0x201f:
			weight++
		case r >= 0x2032 && r <= 0x2037:
			weight++
		default:
			weight += 2
		}
	}
	return weight
}

// DryRunCapture is a sanitized snapshot of a dry-run request. Authorization
// records presence only and never retains the credential value.
type DryRunCapture struct {
	Method               string
	URL                  string
	ContentType          string
	AuthorizationPresent bool
	Body                 []byte
}

// DryRunTransport is an offline RoundTripper for previews and tests. It never
// opens a socket. Captures returns defensive copies of all observations.
type DryRunTransport struct {
	mu       sync.Mutex
	captures []DryRunCapture
}

func (d *DryRunTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(io.LimitReader(req.Body, XMaxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read dry-run request: %w", err)
	}
	if len(body) > XMaxResponseBytes {
		return nil, errors.New("dry-run request exceeded safety limit")
	}
	capture := DryRunCapture{
		Method:               req.Method,
		URL:                  req.URL.String(),
		ContentType:          req.Header.Get("Content-Type"),
		AuthorizationPresent: strings.HasPrefix(req.Header.Get("Authorization"), "Bearer "),
		Body:                 append([]byte(nil), body...),
	}
	d.mu.Lock()
	d.captures = append(d.captures, capture)
	d.mu.Unlock()

	return &http.Response{
		StatusCode: http.StatusCreated,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"data":{"id":"dry-run"}}`)),
		Request:    req,
	}, nil
}

func (d *DryRunTransport) Captures() []DryRunCapture {
	d.mu.Lock()
	defer d.mu.Unlock()
	result := make([]DryRunCapture, len(d.captures))
	for i, capture := range d.captures {
		result[i] = capture
		result[i].Body = append([]byte(nil), capture.Body...)
	}
	return result
}
