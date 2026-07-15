package platform

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	XAuthorizeEndpoint = "https://x.com/i/oauth2/authorize"
	XTokenEndpoint     = "https://api.x.com/2/oauth2/token"
	XRevokeEndpoint    = "https://api.x.com/2/oauth2/revoke"
	xOAuthBodyLimit    = 32 << 10
)

var xRequiredScopes = []string{"offline.access", "tweet.read", "tweet.write", "users.read"}

type XOAuthVault interface {
	SaveXOAuthTokens(context.Context, []byte, time.Time) error
	LoadXOAuthTokens(context.Context) ([]byte, bool, error)
	DeleteXOAuthTokens(context.Context) error
}

type XOAuthConfig struct {
	ClientID    string
	RedirectURI string
	Transport   http.RoundTripper
	Vault       XOAuthVault
}

type XOAuthTokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	Scopes       []string  `json:"scopes"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type xOAuthState struct {
	Verifier    string
	BindingHash [32]byte
	ExpiresAt   time.Time
}

type XOAuthManager struct {
	mu          sync.Mutex
	clientID    string
	redirectURI string
	client      *http.Client
	vault       XOAuthVault
	states      map[[32]byte]xOAuthState
	now         func() time.Time
}

type xTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
}

func NewXOAuthManager(cfg XOAuthConfig) (*XOAuthManager, error) {
	if strings.TrimSpace(cfg.ClientID) == "" || len(cfg.ClientID) > 256 || strings.ContainsAny(cfg.ClientID, "\r\n\t ") {
		return nil, errors.New("X OAuth client ID is invalid")
	}
	redirect, err := url.Parse(cfg.RedirectURI)
	if err != nil || redirect.Scheme != "https" || redirect.Host == "" || redirect.Fragment != "" {
		return nil, errors.New("X OAuth redirect URI must be an absolute HTTPS URL")
	}
	if cfg.Vault == nil {
		return nil, errors.New("X OAuth requires an encrypted token vault")
	}
	transport := cfg.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &XOAuthManager{
		clientID: cfg.ClientID, redirectURI: cfg.RedirectURI, vault: cfg.Vault,
		states: make(map[[32]byte]xOAuthState), now: time.Now,
		client: &http.Client{
			Transport: transport,
			Timeout:   20 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Begin creates a one-time S256 PKCE authorization URL bound to the current
// authenticated control-plane session. It never returns the verifier.
func (m *XOAuthManager) Begin(binding string) (string, error) {
	if binding == "" {
		return "", errors.New("X OAuth requires an authenticated session binding")
	}
	stateRaw, err := randomOAuthValue(32)
	if err != nil {
		return "", err
	}
	verifier, err := randomOAuthValue(32)
	if err != nil {
		return "", err
	}
	stateDecoded, err := base64.RawURLEncoding.DecodeString(stateRaw)
	if err != nil {
		return "", err
	}
	stateHash := sha256.Sum256(stateDecoded)
	challengeHash := sha256.Sum256([]byte(verifier))
	now := m.now()
	m.mu.Lock()
	for key, pending := range m.states {
		if !pending.ExpiresAt.After(now) {
			delete(m.states, key)
		}
	}
	m.states[stateHash] = xOAuthState{
		Verifier: verifier, BindingHash: sha256.Sum256([]byte(binding)), ExpiresAt: now.Add(5 * time.Minute),
	}
	m.mu.Unlock()

	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {m.clientID},
		"redirect_uri":          {m.redirectURI},
		"scope":                 {strings.Join(xRequiredScopes, " ")},
		"state":                 {stateRaw},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challengeHash[:])},
		"code_challenge_method": {"S256"},
	}
	return XAuthorizeEndpoint + "?" + query.Encode(), nil
}

func (m *XOAuthManager) Exchange(ctx context.Context, state, binding, code string) error {
	verifier, err := m.consumeState(state, binding)
	if err != nil {
		return err
	}
	if strings.TrimSpace(code) == "" || len(code) > 4096 || strings.ContainsAny(code, "\r\n") {
		return errors.New("X OAuth authorization code is invalid")
	}
	values := url.Values{
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"client_id":     {m.clientID},
		"redirect_uri":  {m.redirectURI},
		"code_verifier": {verifier},
	}
	tokens, err := m.tokenRequest(ctx, values)
	if err != nil {
		return err
	}
	if tokens.RefreshToken == "" {
		return errors.New("X OAuth did not return the offline refresh token")
	}
	return m.saveTokens(ctx, tokens)
}

func (m *XOAuthManager) Connected(ctx context.Context) bool {
	_, found, err := m.loadTokens(ctx)
	return err == nil && found
}

func (m *XOAuthManager) BearerToken(ctx context.Context) (string, error) {
	tokens, found, err := m.loadTokens(ctx)
	if err != nil {
		return "", err
	}
	if !found {
		return "", errors.New("X OAuth connection is not configured")
	}
	if tokens.ExpiresAt.After(m.now().Add(30 * time.Second)) {
		return tokens.AccessToken, nil
	}
	return m.RefreshBearerToken(ctx)
}

func (m *XOAuthManager) RefreshBearerToken(ctx context.Context) (string, error) {
	current, found, err := m.loadTokens(ctx)
	if err != nil {
		return "", err
	}
	if !found || current.RefreshToken == "" {
		return "", errors.New("X OAuth refresh token is unavailable")
	}
	values := url.Values{
		"refresh_token": {current.RefreshToken},
		"grant_type":    {"refresh_token"},
		"client_id":     {m.clientID},
	}
	updated, err := m.tokenRequest(ctx, values)
	if err != nil {
		return "", err
	}
	if updated.RefreshToken == "" {
		updated.RefreshToken = current.RefreshToken
	}
	if err := m.saveTokens(ctx, updated); err != nil {
		return "", err
	}
	return updated.AccessToken, nil
}

// Revoke calls X's official revocation endpoint through the injected transport
// and deletes the local encrypted token only after a successful response.
func (m *XOAuthManager) Revoke(ctx context.Context) error {
	tokens, found, err := m.loadTokens(ctx)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	token := tokens.RefreshToken
	if token == "" {
		token = tokens.AccessToken
	}
	values := url.Values{"token": {token}, "client_id": {m.clientID}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, XRevokeEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := m.client.Do(request)
	if err != nil {
		return errors.New("X OAuth revocation result is unknown")
	}
	defer response.Body.Close()
	_, tooLarge, readErr := readBounded(response.Body, xOAuthBodyLimit)
	if readErr != nil || tooLarge {
		return errors.New("X OAuth revocation response was invalid")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("X OAuth revocation failed with status %d", response.StatusCode)
	}
	return m.vault.DeleteXOAuthTokens(ctx)
}

func (m *XOAuthManager) consumeState(state, binding string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil || len(raw) != 32 || binding == "" {
		return "", errors.New("X OAuth state is invalid")
	}
	key := sha256.Sum256(raw)
	m.mu.Lock()
	pending, ok := m.states[key]
	delete(m.states, key)
	m.mu.Unlock()
	bindingHash := sha256.Sum256([]byte(binding))
	if !ok || !pending.ExpiresAt.After(m.now()) || subtle.ConstantTimeCompare(pending.BindingHash[:], bindingHash[:]) != 1 {
		return "", errors.New("X OAuth state is invalid or expired")
	}
	return pending.Verifier, nil
}

func (m *XOAuthManager) tokenRequest(ctx context.Context, values url.Values) (XOAuthTokens, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, XTokenEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return XOAuthTokens{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := m.client.Do(request)
	if err != nil {
		return XOAuthTokens{}, errors.New("X OAuth token exchange failed")
	}
	defer response.Body.Close()
	body, tooLarge, err := readBounded(response.Body, xOAuthBodyLimit)
	if err != nil || tooLarge {
		return XOAuthTokens{}, errors.New("X OAuth token response was invalid")
	}
	if response.StatusCode != http.StatusOK {
		return XOAuthTokens{}, fmt.Errorf("X OAuth token exchange failed with status %d", response.StatusCode)
	}
	var decoded xTokenResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return XOAuthTokens{}, errors.New("X OAuth token response was invalid")
	}
	if decoded.AccessToken == "" || !strings.EqualFold(decoded.TokenType, "bearer") || decoded.ExpiresIn < 1 || decoded.ExpiresIn > int64((24*time.Hour)/time.Second) {
		return XOAuthTokens{}, errors.New("X OAuth token response was incomplete")
	}
	scopes := strings.Fields(decoded.Scope)
	sort.Strings(scopes)
	if !hasExactlyRequiredScopes(scopes) {
		return XOAuthTokens{}, errors.New("X OAuth granted scopes do not match the least-privilege policy")
	}
	return XOAuthTokens{
		AccessToken: decoded.AccessToken, RefreshToken: decoded.RefreshToken, TokenType: "Bearer",
		Scopes: scopes, ExpiresAt: m.now().Add(time.Duration(decoded.ExpiresIn) * time.Second).UTC(),
	}, nil
}

func (m *XOAuthManager) saveTokens(ctx context.Context, tokens XOAuthTokens) error {
	encoded, err := json.Marshal(tokens)
	if err != nil {
		return err
	}
	return m.vault.SaveXOAuthTokens(ctx, encoded, m.now().UTC())
}

func (m *XOAuthManager) loadTokens(ctx context.Context) (XOAuthTokens, bool, error) {
	encoded, found, err := m.vault.LoadXOAuthTokens(ctx)
	if err != nil || !found {
		return XOAuthTokens{}, found, err
	}
	var tokens XOAuthTokens
	if err := json.Unmarshal(encoded, &tokens); err != nil {
		return XOAuthTokens{}, false, errors.New("stored X OAuth token record is invalid")
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" || !hasExactlyRequiredScopes(tokens.Scopes) {
		return XOAuthTokens{}, false, errors.New("stored X OAuth token record violates policy")
	}
	return tokens, true, nil
}

func hasExactlyRequiredScopes(scopes []string) bool {
	if len(scopes) != len(xRequiredScopes) {
		return false
	}
	copyOfScopes := append([]string(nil), scopes...)
	sort.Strings(copyOfScopes)
	for index := range xRequiredScopes {
		if copyOfScopes[index] != xRequiredScopes[index] {
			return false
		}
	}
	return true
}

func randomOAuthValue(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
