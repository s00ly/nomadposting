package web

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"ivpn/internal/app"
	"ivpn/internal/auth"
	"ivpn/internal/secure"
	"ivpn/internal/store"
)

func testServer(t *testing.T) (*Server, *app.Service) {
	t.Helper()
	envelope, err := secure.NewEnvelope(bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatal(err)
	}
	database, err := store.OpenEncrypted(filepath.Join(t.TempDir(), "ivpn.db"), envelope)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	authn, err := auth.New(context.Background(), database, auth.Config{
		RPID: "localhost", Origin: "http://localhost", DevMode: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	service := app.NewService(database, envelope)
	server, err := New(service, authn, Config{DryRun: true, Timezone: "UTC"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return server, service
}

func TestDashboardSecurityHeadersAndPalette(t *testing.T) {
	server, _ := testServer(t)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("dashboard returned %d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") || !strings.Contains(got, "frame-ancestors 'none'") {
		t.Fatalf("CSP is incomplete: %q", got)
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("dashboard response was cacheable")
	}
	body := recorder.Body.String()
	for _, marker := range []string{"Compose encrypted draft", "FR / PINNED", "No public location claims", "DRY-RUN"} {
		if !strings.Contains(body, marker) {
			t.Fatalf("dashboard missing %q", marker)
		}
	}

	css := httptest.NewRecorder()
	server.Handler().ServeHTTP(css, httptest.NewRequest(http.MethodGet, "/assets/style.css", nil))
	for _, token := range []string{"#0d0d10", "#ff731a", "#9b6dff", "#eceaf0", "prefers-reduced-motion"} {
		if !strings.Contains(strings.ToLower(css.Body.String()), token) {
			t.Fatalf("stylesheet missing %q", token)
		}
	}
}

func TestPreviewHidesDispatchCountryAndBindsExactPayload(t *testing.T) {
	server, service := testServer(t)
	job, err := service.CreateDraft(context.Background(), app.CreateDraftInput{
		Content: "exact preview payload", PostToX: true, PostToNostr: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/drafts/"+job.ID+"/preview", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("preview returned %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, marker := range []string{"exact preview payload", "Public location", "None", "payload_hash"} {
		if !strings.Contains(body, marker) {
			t.Fatalf("preview missing %q", marker)
		}
	}
	for _, forbidden := range []string{"France", "Germany", "Sweden", "Switzerland", "United Kingdom", "selected country"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("pre-dispatch preview exposed %q", forbidden)
		}
	}
}

func TestStateChangingRequestRejectsMissingCSRF(t *testing.T) {
	server, _ := testServer(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/drafts", strings.NewReader("content=test&post_x=1"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF token returned %d", recorder.Code)
	}
}

func TestXOAuthFailsClosedWithoutPinnedEgressTransport(t *testing.T) {
	server, _ := testServer(t)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/oauth/x/start", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured OAuth start returned %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "dedicated France egress") {
		t.Fatal("OAuth readiness failure did not identify the pinned-egress gate")
	}
}

func TestDashboardRejectsUntrustedFlashText(t *testing.T) {
	server, _ := testServer(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/?msg=X%20published%20successfully", nil)
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("dashboard returned %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "X published successfully") {
		t.Fatal("untrusted query text was rendered as a status banner")
	}
}
