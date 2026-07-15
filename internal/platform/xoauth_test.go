package platform

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type memoryXVault struct {
	encoded []byte
	deleted bool
}

func (v *memoryXVault) SaveXOAuthTokens(_ context.Context, encoded []byte, _ time.Time) error {
	v.encoded = append([]byte(nil), encoded...)
	v.deleted = false
	return nil
}

func (v *memoryXVault) LoadXOAuthTokens(context.Context) ([]byte, bool, error) {
	return append([]byte(nil), v.encoded...), len(v.encoded) > 0, nil
}

func (v *memoryXVault) DeleteXOAuthTokens(context.Context) error {
	v.encoded = nil
	v.deleted = true
	return nil
}

func TestXOAuthPKCEExchangeIsBoundScopedAndSingleUse(t *testing.T) {
	vault := &memoryXVault{}
	var tokenForm url.Values
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != XTokenEndpoint || request.Method != http.MethodPost {
			t.Fatalf("unexpected token request %s %s", request.Method, request.URL)
		}
		body, _ := io.ReadAll(request.Body)
		tokenForm, _ = url.ParseQuery(string(body))
		return jsonResponse(http.StatusOK, `{"access_token":"access","refresh_token":"refresh","token_type":"bearer","expires_in":7200,"scope":"tweet.read tweet.write users.read offline.access"}`), nil
	})
	manager, err := NewXOAuthManager(XOAuthConfig{
		ClientID: "client-id", RedirectURI: "https://ivpn.internal/oauth/x/callback", Transport: transport, Vault: vault,
	})
	if err != nil {
		t.Fatal(err)
	}
	authorizeURL, err := manager.Begin("session-binding")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != XAuthorizeEndpoint {
		t.Fatalf("unexpected authorize endpoint %s", parsed)
	}
	if query.Get("code_challenge_method") != "S256" || query.Get("scope") != "offline.access tweet.read tweet.write users.read" {
		t.Fatalf("unexpected authorize policy %v", query)
	}
	if query.Get("state") == "" || query.Get("code_challenge") == "" {
		t.Fatal("PKCE state or challenge was empty")
	}
	if err := manager.Exchange(context.Background(), query.Get("state"), "session-binding", "authorization-code"); err != nil {
		t.Fatal(err)
	}
	if tokenForm.Get("code_verifier") == "" || tokenForm.Get("code_verifier") == query.Get("code_challenge") {
		t.Fatal("S256 verifier was absent or exposed as the challenge")
	}
	if tokenForm.Get("client_id") != "client-id" || tokenForm.Get("grant_type") != "authorization_code" {
		t.Fatalf("unexpected token form %v", tokenForm)
	}
	if !manager.Connected(context.Background()) || strings.Contains(string(vault.encoded), "authorization-code") {
		t.Fatal("token vault did not contain the normalized token record")
	}
	if err := manager.Exchange(context.Background(), query.Get("state"), "session-binding", "replay"); err == nil {
		t.Fatal("OAuth state was replayable")
	}
}

func TestXOAuthRejectsBindingAndScopeDrift(t *testing.T) {
	vault := &memoryXVault{}
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"access_token":"access","refresh_token":"refresh","token_type":"bearer","expires_in":7200,"scope":"tweet.read tweet.write users.read offline.access follows.write"}`), nil
	})
	manager, err := NewXOAuthManager(XOAuthConfig{
		ClientID: "client-id", RedirectURI: "https://ivpn.internal/oauth/x/callback", Transport: transport, Vault: vault,
	})
	if err != nil {
		t.Fatal(err)
	}
	authorizeURL, _ := manager.Begin("right-binding")
	parsed, _ := url.Parse(authorizeURL)
	state := parsed.Query().Get("state")
	if err := manager.Exchange(context.Background(), state, "wrong-binding", "code"); err == nil {
		t.Fatal("session-binding mismatch was accepted")
	}
	authorizeURL, _ = manager.Begin("right-binding")
	parsed, _ = url.Parse(authorizeURL)
	if err := manager.Exchange(context.Background(), parsed.Query().Get("state"), "right-binding", "code"); err == nil {
		t.Fatal("scope expansion was accepted")
	}
	if manager.Connected(context.Background()) {
		t.Fatal("rejected scope response was persisted")
	}
}

func TestXOAuthRefreshAndRevokeUseOfficialFixedEndpoints(t *testing.T) {
	vault := &memoryXVault{}
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	initial, _ := json.Marshal(XOAuthTokens{
		AccessToken: "old-access", RefreshToken: "old-refresh", TokenType: "Bearer",
		Scopes: append([]string(nil), xRequiredScopes...), ExpiresAt: now.Add(-time.Minute),
	})
	vault.encoded = initial
	calls := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		body, _ := io.ReadAll(request.Body)
		form, _ := url.ParseQuery(string(body))
		switch calls {
		case 1:
			if request.URL.String() != XTokenEndpoint || form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "old-refresh" {
				t.Fatalf("unexpected refresh request %s %v", request.URL, form)
			}
			return jsonResponse(http.StatusOK, `{"access_token":"new-access","refresh_token":"new-refresh","token_type":"bearer","expires_in":7200,"scope":"offline.access tweet.read tweet.write users.read"}`), nil
		case 2:
			if request.URL.String() != XRevokeEndpoint || form.Get("token") != "new-refresh" {
				t.Fatalf("unexpected revoke request %s %v", request.URL, form)
			}
			return jsonResponse(http.StatusOK, `{}`), nil
		default:
			t.Fatalf("unexpected OAuth call %d", calls)
			return nil, nil
		}
	})
	manager, err := NewXOAuthManager(XOAuthConfig{
		ClientID: "client-id", RedirectURI: "https://ivpn.internal/oauth/x/callback", Transport: transport, Vault: vault,
	})
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now }
	token, err := manager.BearerToken(context.Background())
	if err != nil || token != "new-access" {
		t.Fatalf("refresh failed: token=%q err=%v", token, err)
	}
	if err := manager.Revoke(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !vault.deleted || manager.Connected(context.Background()) || calls != 2 {
		t.Fatal("revocation did not clear the encrypted token record")
	}
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
