package auth

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

type memoryStateStore struct {
	userID      []byte
	credentials []byte
	found       bool
	recovery    []byte
}

func (s *memoryStateStore) LoadAuthState(context.Context) ([]byte, []byte, bool, error) {
	return append([]byte(nil), s.userID...), append([]byte(nil), s.credentials...), s.found, nil
}

func (s *memoryStateStore) SaveAuthState(_ context.Context, userID, credentials []byte, _ time.Time) error {
	s.userID = append([]byte(nil), userID...)
	s.credentials = append([]byte(nil), credentials...)
	s.found = true
	return nil
}

func (s *memoryStateStore) LoadRecoveryHash(context.Context) ([]byte, bool, error) {
	return append([]byte(nil), s.recovery...), len(s.recovery) > 0, nil
}

func (s *memoryStateStore) SaveRecoveryHash(_ context.Context, hash []byte, _ time.Time) error {
	s.recovery = append([]byte(nil), hash...)
	return nil
}

func TestProductionAuthPolicyRequiresHTTPSBootstrapAndTwoPasskeys(t *testing.T) {
	store := &memoryStateStore{}
	if _, err := New(context.Background(), store, Config{RPID: "ivpn.internal", Origin: "http://ivpn.internal", BootstrapToken: strings.Repeat("a", 32)}); err == nil {
		t.Fatal("expected an insecure origin to be rejected")
	}
	if _, err := New(context.Background(), store, Config{RPID: "ivpn.internal", Origin: "https://ivpn.internal", BootstrapToken: "short"}); err == nil {
		t.Fatal("expected a short bootstrap token to be rejected")
	}
	m, err := New(context.Background(), store, Config{
		RPID: "ivpn.internal", Origin: "https://ivpn.internal", BootstrapToken: strings.Repeat("b", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.OperationallyReady() {
		t.Fatal("production controls unlocked without two passkeys")
	}
	m.mu.Lock()
	m.user.Credentials = append(m.user.Credentials, webauthn.Credential{}, webauthn.Credential{})
	m.mu.Unlock()
	if m.OperationallyReady() {
		t.Fatal("production controls unlocked without an offline recovery code")
	}
	if _, err := m.rotateRecoveryCode(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !m.OperationallyReady() {
		t.Fatal("production controls remained locked after two passkeys and recovery enrollment")
	}
}

func TestCSRFValidationAndCeremonyReplayRejection(t *testing.T) {
	m, err := New(context.Background(), &memoryStateStore{}, Config{
		RPID: "localhost", Origin: "http://localhost", DevMode: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	valid := httptest.NewRequest("POST", "/", strings.NewReader(url.Values{"csrf_token": {m.devCSRF}}.Encode()))
	valid.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !m.ValidateCSRF(valid) {
		t.Fatal("valid CSRF token was rejected")
	}
	invalid := httptest.NewRequest("POST", "/", strings.NewReader("csrf_token=wrong"))
	invalid.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if m.ValidateCSRF(invalid) {
		t.Fatal("invalid CSRF token was accepted")
	}

	recorder := httptest.NewRecorder()
	m.beginCeremony(recorder, "login", &webauthn.SessionData{}, false, map[string]any{"publicKey": map[string]any{"challenge": "test"}})
	if recorder.Code != 200 {
		t.Fatalf("begin ceremony returned %d", recorder.Code)
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	csrf, _ := response["csrfToken"].(string)
	cookies := recorder.Result().Cookies()
	if csrf == "" || len(cookies) != 1 || cookies[0].Name != ceremonyCookie {
		t.Fatal("ceremony binding data was not issued")
	}
	finish := httptest.NewRequest("POST", "/auth/login/finish", nil)
	finish.AddCookie(cookies[0])
	finish.Header.Set("X-CSRF-Token", csrf)
	if _, ok := m.consumeCeremony(finish, "login"); !ok {
		t.Fatal("valid ceremony binding was rejected")
	}
	if _, ok := m.consumeCeremony(finish, "login"); ok {
		t.Fatal("consumed ceremony was replayable")
	}
}

func TestRecoveryCodeRotatesOnUseAndRateLimitsFailures(t *testing.T) {
	m, err := New(context.Background(), &memoryStateStore{}, Config{
		RPID: "ivpn.internal", Origin: "https://ivpn.internal", BootstrapToken: strings.Repeat("r", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.user.Credentials = append(m.user.Credentials, webauthn.Credential{})
	m.mu.Unlock()
	code, err := m.rotateRecoveryCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("POST", "/auth/recovery", nil)
	request.Header.Set("X-Recovery-Code", code)
	m.recoveryLogin(recorder, request)
	if recorder.Code != 200 || !strings.Contains(recorder.Body.String(), "ivpn-recovery-") || len(recorder.Result().Cookies()) != 1 {
		t.Fatalf("recovery failed: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	replay := httptest.NewRecorder()
	replayRequest := httptest.NewRequest("POST", "/auth/recovery", nil)
	replayRequest.Header.Set("X-Recovery-Code", code)
	m.recoveryLogin(replay, replayRequest)
	if replay.Code != 401 {
		t.Fatalf("used recovery code returned %d", replay.Code)
	}
	for index := 0; index < 4; index++ {
		failed := httptest.NewRecorder()
		failedRequest := httptest.NewRequest("POST", "/auth/recovery", nil)
		failedRequest.Header.Set("X-Recovery-Code", "wrong")
		m.recoveryLogin(failed, failedRequest)
		if failed.Code != 401 {
			t.Fatalf("failure %d returned %d", index, failed.Code)
		}
	}
	limited := httptest.NewRecorder()
	limitedRequest := httptest.NewRequest("POST", "/auth/recovery", nil)
	limitedRequest.Header.Set("X-Recovery-Code", "wrong")
	m.recoveryLogin(limited, limitedRequest)
	if limited.Code != 429 {
		t.Fatalf("recovery failures were not limited: %d", limited.Code)
	}
}
