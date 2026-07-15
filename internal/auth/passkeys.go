package auth

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
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

type StateStore interface {
	LoadAuthState(context.Context) ([]byte, []byte, bool, error)
	SaveAuthState(context.Context, []byte, []byte, time.Time) error
	LoadRecoveryHash(context.Context) ([]byte, bool, error)
	SaveRecoveryHash(context.Context, []byte, time.Time) error
}

type Config struct {
	RPID           string
	Origin         string
	BootstrapToken string
	SessionTTL     time.Duration
	DevMode        bool
}

type Manager struct {
	mu            sync.RWMutex
	recoveryMu    sync.Mutex
	wa            *webauthn.WebAuthn
	store         StateStore
	user          *user
	bootstrapHash [32]byte
	sessions      map[[32]byte]session
	ceremonies    map[[32]byte]ceremony
	secureCookies bool
	sessionTTL    time.Duration
	devMode       bool
	devCSRF       string
	recoveryHash  [32]byte
	recoverySet   bool
	recoveryFails []time.Time
}

type user struct {
	ID          []byte                `json:"id"`
	Credentials []webauthn.Credential `json:"credentials"`
}

func (u *user) WebAuthnID() []byte                         { return u.ID }
func (u *user) WebAuthnName() string                       { return "operator" }
func (u *user) WebAuthnDisplayName() string                { return "iVPN Operator" }
func (u *user) WebAuthnIcon() string                       { return "" }
func (u *user) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

type session struct {
	Expires time.Time
	CSRF    string
}

type ceremony struct {
	Kind      string
	Expires   time.Time
	CSRF      string
	Session   *webauthn.SessionData
	Bootstrap bool
}

const (
	sessionCookie  = "ivpn_session"
	ceremonyCookie = "ivpn_ceremony"
)

func New(ctx context.Context, store StateStore, cfg Config) (*Manager, error) {
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 15 * time.Minute
	}
	origin, err := url.Parse(cfg.Origin)
	if err != nil || origin.Host == "" {
		return nil, errors.New("WebAuthn origin must be an absolute URL")
	}
	if !cfg.DevMode && origin.Scheme != "https" {
		return nil, errors.New("WebAuthn origin must use HTTPS outside development mode")
	}
	if cfg.RPID == "" {
		return nil, errors.New("WebAuthn relying-party ID is required")
	}
	if !cfg.DevMode && len(cfg.BootstrapToken) < 32 {
		return nil, errors.New("bootstrap token must contain at least 32 characters")
	}
	wa, err := webauthn.New(&webauthn.Config{RPDisplayName: "iVPN Private Posting Plane", RPID: cfg.RPID, RPOrigins: []string{cfg.Origin}})
	if err != nil {
		return nil, err
	}
	m := &Manager{
		wa: wa, store: store, sessions: make(map[[32]byte]session), ceremonies: make(map[[32]byte]ceremony),
		secureCookies: origin.Scheme == "https", sessionTTL: cfg.SessionTTL, devMode: cfg.DevMode,
		bootstrapHash: sha256.Sum256([]byte(cfg.BootstrapToken)),
	}
	m.devCSRF, err = randomToken(24)
	if err != nil {
		return nil, err
	}
	if err := m.load(ctx); err != nil {
		return nil, err
	}
	if err := m.loadRecovery(ctx); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) load(ctx context.Context) error {
	userID, encoded, found, err := m.store.LoadAuthState(ctx)
	if err != nil {
		return err
	}
	if !found {
		userID = make([]byte, 32)
		if _, err := rand.Read(userID); err != nil {
			return err
		}
		m.user = &user{ID: userID}
		return nil
	}
	var credentials []webauthn.Credential
	if err := json.Unmarshal(encoded, &credentials); err != nil {
		return fmt.Errorf("decode passkey credentials: %w", err)
	}
	m.user = &user{ID: append([]byte(nil), userID...), Credentials: credentials}
	return nil
}

func (m *Manager) loadRecovery(ctx context.Context) error {
	hash, found, err := m.store.LoadRecoveryHash(ctx)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if len(hash) != sha256.Size {
		return errors.New("stored recovery hash is invalid")
	}
	copy(m.recoveryHash[:], hash)
	m.recoverySet = true
	return nil
}

func (m *Manager) HasPasskeys() bool { return m.CredentialCount() > 0 }

func (m *Manager) CredentialCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.user.Credentials)
}

func (m *Manager) OperationallyReady() bool {
	if m.devMode {
		return true
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.user.Credentials) >= 2 && m.recoverySet
}

func (m *Manager) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/register/begin", m.registerBegin)
	mux.HandleFunc("POST /auth/register/finish", m.registerFinish)
	mux.HandleFunc("POST /auth/login/begin", m.loginBegin)
	mux.HandleFunc("POST /auth/login/finish", m.loginFinish)
	mux.HandleFunc("POST /auth/recovery", m.recoveryLogin)
	mux.HandleFunc("POST /auth/recovery/rotate", m.recoveryRotate)
	mux.HandleFunc("POST /auth/logout", m.logout)
}

func (m *Manager) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.devMode || m.authenticated(r) {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodGet && acceptsHTML(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		http.Error(w, "authentication required", http.StatusUnauthorized)
	})
}

func (m *Manager) CSRFToken(r *http.Request) string {
	if m.devMode {
		return m.devCSRF
	}
	value, ok := m.sessionForRequest(r)
	if !ok {
		return ""
	}
	return value.CSRF
}

func (m *Manager) ValidateCSRF(r *http.Request) bool {
	expected := m.CSRFToken(r)
	provided := r.Header.Get("X-CSRF-Token")
	if provided == "" {
		provided = r.FormValue("csrf_token")
	}
	return expected != "" && subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) == 1
}

func (m *Manager) registerBegin(w http.ResponseWriter, r *http.Request) {
	bootstrap := m.CredentialCount() == 0
	if bootstrap {
		if !m.validBootstrap(r.Header.Get("X-Bootstrap-Token")) {
			http.Error(w, "invalid bootstrap token", http.StatusUnauthorized)
			return
		}
	} else if !m.devMode && !m.authenticated(r) {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	m.mu.RLock()
	creation, data, err := m.wa.BeginRegistration(m.user)
	m.mu.RUnlock()
	if err != nil {
		http.Error(w, "could not begin passkey registration", http.StatusInternalServerError)
		return
	}
	m.beginCeremony(w, "register", data, bootstrap, creation)
}

func (m *Manager) registerFinish(w http.ResponseWriter, r *http.Request) {
	entry, ok := m.consumeCeremony(r, "register")
	if !ok {
		http.Error(w, "registration ceremony expired or invalid", http.StatusBadRequest)
		return
	}
	if entry.Bootstrap {
		if !m.validBootstrap(r.Header.Get("X-Bootstrap-Token")) {
			http.Error(w, "invalid bootstrap token", http.StatusUnauthorized)
			return
		}
	} else if !m.devMode && !m.authenticated(r) {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	m.mu.Lock()
	credential, err := m.wa.FinishRegistration(m.user, *entry.Session, r)
	if err == nil {
		m.user.Credentials = append(m.user.Credentials, *credential)
		err = m.persistLocked(r.Context())
	}
	m.mu.Unlock()
	if err != nil {
		http.Error(w, "passkey registration verification failed", http.StatusBadRequest)
		return
	}
	recoveryCode := ""
	if entry.Bootstrap {
		recoveryCode, err = m.rotateRecoveryCode(r.Context())
		if err != nil {
			http.Error(w, "passkey registered but recovery code creation failed; authenticate and rotate recovery", http.StatusInternalServerError)
			return
		}
	}
	if err := m.issueSession(w); err != nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	if recoveryCode != "" {
		m.writeRecoveryCode(w, recoveryCode)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (m *Manager) loginBegin(w http.ResponseWriter, _ *http.Request) {
	if !m.HasPasskeys() {
		http.Error(w, "no passkeys are registered", http.StatusConflict)
		return
	}
	m.mu.RLock()
	assertion, data, err := m.wa.BeginLogin(m.user)
	m.mu.RUnlock()
	if err != nil {
		http.Error(w, "could not begin authentication", http.StatusInternalServerError)
		return
	}
	m.beginCeremony(w, "login", data, false, assertion)
}

func (m *Manager) loginFinish(w http.ResponseWriter, r *http.Request) {
	entry, ok := m.consumeCeremony(r, "login")
	if !ok {
		http.Error(w, "authentication ceremony expired or invalid", http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	credential, err := m.wa.FinishLogin(m.user, *entry.Session, r)
	if err == nil {
		for i := range m.user.Credentials {
			if subtle.ConstantTimeCompare(m.user.Credentials[i].ID, credential.ID) == 1 {
				m.user.Credentials[i] = *credential
				break
			}
		}
		err = m.persistLocked(r.Context())
	}
	m.mu.Unlock()
	if err != nil {
		http.Error(w, "passkey authentication failed", http.StatusUnauthorized)
		return
	}
	if err := m.issueSession(w); err != nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (m *Manager) recoveryLogin(w http.ResponseWriter, r *http.Request) {
	if !m.HasPasskeys() {
		http.Error(w, "recovery is unavailable before passkey enrollment", http.StatusConflict)
		return
	}
	if !m.allowRecoveryAttempt(time.Now()) {
		http.Error(w, "recovery attempts are temporarily limited", http.StatusTooManyRequests)
		return
	}
	m.recoveryMu.Lock()
	defer m.recoveryMu.Unlock()
	provided := r.Header.Get("X-Recovery-Code")
	if !m.validRecoveryCode(provided) {
		m.recordRecoveryFailure(time.Now())
		http.Error(w, "recovery code is invalid", http.StatusUnauthorized)
		return
	}
	replacement, err := m.rotateRecoveryCode(r.Context())
	if err != nil {
		http.Error(w, "recovery code rotation failed", http.StatusInternalServerError)
		return
	}
	if err := m.issueSession(w); err != nil {
		http.Error(w, "could not create recovery session", http.StatusInternalServerError)
		return
	}
	m.writeRecoveryCode(w, replacement)
}

func (m *Manager) recoveryRotate(w http.ResponseWriter, r *http.Request) {
	if !m.devMode && !m.authenticated(r) {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	if !m.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	m.recoveryMu.Lock()
	defer m.recoveryMu.Unlock()
	replacement, err := m.rotateRecoveryCode(r.Context())
	if err != nil {
		http.Error(w, "recovery code rotation failed", http.StatusInternalServerError)
		return
	}
	m.writeRecoveryCode(w, replacement)
}

func (m *Manager) rotateRecoveryCode(ctx context.Context) (string, error) {
	raw, err := randomToken(32)
	if err != nil {
		return "", err
	}
	code := "ivpn-recovery-" + raw
	hash := sha256.Sum256([]byte(code))
	if err := m.store.SaveRecoveryHash(ctx, hash[:], time.Now().UTC()); err != nil {
		return "", err
	}
	m.mu.Lock()
	m.recoveryHash = hash
	m.recoverySet = true
	m.recoveryFails = nil
	m.mu.Unlock()
	return code, nil
}

func (m *Manager) validRecoveryCode(value string) bool {
	candidate := sha256.Sum256([]byte(value))
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.recoverySet && subtle.ConstantTimeCompare(candidate[:], m.recoveryHash[:]) == 1
}

func (m *Manager) allowRecoveryAttempt(now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := now.Add(-15 * time.Minute)
	kept := m.recoveryFails[:0]
	for _, failure := range m.recoveryFails {
		if failure.After(cutoff) {
			kept = append(kept, failure)
		}
	}
	m.recoveryFails = kept
	return len(m.recoveryFails) < 5
}

func (m *Manager) recordRecoveryFailure(now time.Time) {
	m.mu.Lock()
	m.recoveryFails = append(m.recoveryFails, now)
	m.mu.Unlock()
}

func (m *Manager) writeRecoveryCode(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"recoveryCode": code})
}

func (m *Manager) beginCeremony(w http.ResponseWriter, kind string, data *webauthn.SessionData, bootstrap bool, options any) {
	token, raw, err := randomTokenWithHash(32)
	if err != nil {
		http.Error(w, "entropy source unavailable", http.StatusInternalServerError)
		return
	}
	csrf, err := randomToken(24)
	if err != nil {
		http.Error(w, "entropy source unavailable", http.StatusInternalServerError)
		return
	}
	m.mu.Lock()
	m.purgeLocked(time.Now())
	m.ceremonies[token] = ceremony{Kind: kind, Expires: time.Now().Add(5 * time.Minute), CSRF: csrf, Session: data, Bootstrap: bootstrap}
	m.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: ceremonyCookie, Value: raw, Path: "/auth/", HttpOnly: true, Secure: m.secureCookies, SameSite: http.SameSiteStrictMode, MaxAge: 300})
	encoded, err := json.Marshal(options)
	if err != nil {
		http.Error(w, "could not encode ceremony", http.StatusInternalServerError)
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		http.Error(w, "could not encode ceremony", http.StatusInternalServerError)
		return
	}
	payload["csrfToken"] = csrf
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(payload)
}

func (m *Manager) consumeCeremony(r *http.Request, kind string) (ceremony, bool) {
	cookie, err := r.Cookie(ceremonyCookie)
	if err != nil {
		return ceremony{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return ceremony{}, false
	}
	hash := sha256.Sum256(raw)
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.ceremonies[hash]
	delete(m.ceremonies, hash)
	provided := r.Header.Get("X-CSRF-Token")
	if !ok || entry.Kind != kind || time.Now().After(entry.Expires) || subtle.ConstantTimeCompare([]byte(entry.CSRF), []byte(provided)) != 1 {
		return ceremony{}, false
	}
	return entry, true
}

func (m *Manager) issueSession(w http.ResponseWriter) error {
	hash, raw, err := randomTokenWithHash(32)
	if err != nil {
		return err
	}
	csrf, err := randomToken(24)
	if err != nil {
		return err
	}
	expires := time.Now().Add(m.sessionTTL)
	m.mu.Lock()
	m.sessions[hash] = session{Expires: expires, CSRF: csrf}
	m.purgeLocked(time.Now())
	m.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: raw, Path: "/", HttpOnly: true, Secure: m.secureCookies, SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: int(m.sessionTTL.Seconds())})
	return nil
}

func (m *Manager) authenticated(r *http.Request) bool {
	_, ok := m.sessionForRequest(r)
	return ok
}

func (m *Manager) sessionForRequest(r *http.Request) (session, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return session{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return session{}, false
	}
	hash := sha256.Sum256(raw)
	m.mu.RLock()
	entry, ok := m.sessions[hash]
	m.mu.RUnlock()
	return entry, ok && time.Now().Before(entry.Expires)
}

func (m *Manager) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		if raw, err := base64.RawURLEncoding.DecodeString(cookie.Value); err == nil {
			hash := sha256.Sum256(raw)
			m.mu.Lock()
			delete(m.sessions, hash)
			m.mu.Unlock()
		}
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: m.secureCookies, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (m *Manager) persistLocked(ctx context.Context) error {
	encoded, err := json.Marshal(m.user.Credentials)
	if err != nil {
		return err
	}
	return m.store.SaveAuthState(ctx, m.user.ID, encoded, time.Now().UTC())
}

func (m *Manager) validBootstrap(value string) bool {
	candidate := sha256.Sum256([]byte(value))
	return subtle.ConstantTimeCompare(candidate[:], m.bootstrapHash[:]) == 1
}

func (m *Manager) purgeLocked(now time.Time) {
	for key, value := range m.sessions {
		if now.After(value.Expires) {
			delete(m.sessions, key)
		}
	}
	for key, value := range m.ceremonies {
		if now.After(value.Expires) {
			delete(m.ceremonies, key)
		}
	}
}

func randomToken(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func randomTokenWithHash(size int) ([32]byte, string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return [32]byte{}, "", err
	}
	return sha256.Sum256(raw), base64.RawURLEncoding.EncodeToString(raw), nil
}

func acceptsHTML(r *http.Request) bool {
	return r.Header.Get("Accept") == "" || r.Header.Get("Accept") == "text/html" || r.Header.Get("Sec-Fetch-Dest") == "document"
}
