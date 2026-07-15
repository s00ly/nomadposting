package web

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
	_ "time/tzdata"

	"ivpn/internal/app"
	"ivpn/internal/auth"
	"ivpn/internal/domain"
	"ivpn/internal/platform"
)

//go:embed templates/*.html assets/*
var files embed.FS

type Config struct {
	DryRun          bool
	Timezone        string
	XConfigured     bool
	NostrConfigured bool
	XOAuth          *platform.XOAuthManager
}

type Server struct {
	service *app.Service
	auth    *auth.Manager
	config  Config
	zone    *time.Location
	tmpl    *template.Template
	log     *slog.Logger
}

type countryView struct {
	Code   string
	Name   string
	Status string
}

type dashboardData struct {
	CSRFToken        string
	Flash            string
	DryRun           bool
	System           domain.SystemState
	Jobs             []domain.JobSummary
	Audit            []domain.AuditEvent
	Countries        []countryView
	HealthyCountries int
	Queued           int
	Resolved         int
	XStatus          string
	NostrStatus      string
	PasskeyCount     int
	XOAuthAvailable  bool
}

type previewData struct {
	CSRFToken string
	Preview   app.Preview
}

type loginData struct {
	HasPasskeys bool
}

func New(service *app.Service, authn *auth.Manager, cfg Config, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Timezone == "" {
		cfg.Timezone = "Europe/Paris"
	}
	zone, err := time.LoadLocation(cfg.Timezone)
	if err != nil {
		return nil, fmt.Errorf("load timezone: %w", err)
	}
	funcs := template.FuncMap{
		"stateClass": func(state domain.JobState) string {
			switch state {
			case domain.StateComplete, domain.StateApproved:
				return "status-purple"
			case domain.StateFailed, domain.StatePartial, domain.StateUnknown:
				return "status-orange"
			default:
				return "status-neutral"
			}
		},
	}
	tmpl, err := template.New("root").Funcs(funcs).ParseFS(files, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{service: service, auth: authn, config: cfg, zone: zone, tmpl: tmpl, log: logger}, nil
}

func (s *Server) Handler() http.Handler {
	root := http.NewServeMux()
	assets, _ := fs.Sub(files, "assets")
	root.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(assets))))
	root.HandleFunc("GET /healthz", s.health)
	root.HandleFunc("GET /login", s.login)
	s.auth.Routes(root)

	protected := http.NewServeMux()
	protected.HandleFunc("GET /", s.dashboard)
	protected.HandleFunc("POST /drafts", s.requireCSRF(s.createDraft))
	protected.HandleFunc("GET /drafts/{id}/preview", s.preview)
	protected.HandleFunc("POST /drafts/{id}/approve", s.requireOperational(s.requireCSRF(s.approve)))
	protected.HandleFunc("POST /jobs/{id}/cancel", s.requireCSRF(s.cancel))
	protected.HandleFunc("POST /jobs/{id}/reconcile", s.requireOperational(s.requireCSRF(s.reconcile)))
	protected.HandleFunc("GET /jobs/{id}", s.jobJSON)
	protected.HandleFunc("GET /oauth/x/start", s.requireOperational(s.xOAuthStart))
	protected.HandleFunc("GET /oauth/x/callback", s.requireOperational(s.xOAuthCallback))
	protected.HandleFunc("POST /connections/{platform}/revoke", s.requireOperational(s.requireCSRF(s.revokeConnection)))
	protected.HandleFunc("POST /system/emergency-stop", s.requireCSRF(s.emergencyStop))
	root.Handle("/", s.auth.Require(protected))
	return securityHeaders(root)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := s.tmpl.ExecuteTemplate(w, "login", loginData{HasPasskeys: s.auth.HasPasskeys()}); err != nil {
		s.log.Error("render login", "error", err)
	}
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	jobs, err := s.service.Jobs(r.Context(), 100)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	audit, err := s.service.Audit(r.Context(), 30)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	system, err := s.service.SystemState(r.Context())
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	queued, resolved := 0, 0
	for _, job := range jobs {
		switch job.State {
		case domain.StateComplete, domain.StateFailed, domain.StateCancelled:
			resolved++
		default:
			queued++
		}
	}
	xStatus, nostrStatus := "NOT CONFIGURED", "NOT CONFIGURED"
	if s.config.DryRun {
		xStatus, nostrStatus = "DRY-RUN", "DRY-RUN"
	} else {
		if s.config.XConfigured {
			xStatus = "CONFIGURED"
		}
		if s.config.NostrConfigured {
			nostrStatus = "CONFIGURED"
		}
	}
	if s.config.XOAuth != nil && s.config.XOAuth.Connected(r.Context()) {
		xStatus = "CONNECTED"
	}
	data := dashboardData{
		CSRFToken: s.auth.CSRFToken(r), Flash: flashMessage(r.URL.Query().Get("msg")), DryRun: s.config.DryRun,
		System: system, Jobs: jobs, Audit: audit, Countries: defaultCountries(), Queued: queued, Resolved: resolved,
		XStatus: xStatus, NostrStatus: nostrStatus, PasskeyCount: s.auth.CredentialCount(), XOAuthAvailable: s.config.XOAuth != nil,
	}
	w.Header().Set("Cache-Control", "no-store")
	if err := s.tmpl.ExecuteTemplate(w, "dashboard", data); err != nil {
		s.log.Error("render dashboard", "error", err)
	}
}

func (s *Server) createDraft(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, err, http.StatusBadRequest)
		return
	}
	var scheduled *time.Time
	if raw := r.FormValue("scheduled_at"); raw != "" {
		parsed, err := time.ParseInLocation("2006-01-02T15:04", raw, s.zone)
		if err != nil {
			s.redirect(w, r, "Invalid schedule time")
			return
		}
		value := parsed.UTC()
		scheduled = &value
	}
	job, err := s.service.CreateDraft(r.Context(), app.CreateDraftInput{
		Content: r.FormValue("content"), PostToX: r.FormValue("post_x") == "1",
		PostToNostr: r.FormValue("post_nostr") == "1", ScheduledAt: scheduled,
	})
	if err != nil {
		s.redirect(w, r, safeMessage(err))
		return
	}
	http.Redirect(w, r, "/drafts/"+job.ID+"/preview", http.StatusSeeOther)
}

func (s *Server) preview(w http.ResponseWriter, r *http.Request) {
	preview, err := s.service.Preview(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if err := s.tmpl.ExecuteTemplate(w, "preview", previewData{CSRFToken: s.auth.CSRFToken(r), Preview: preview}); err != nil {
		s.log.Error("render preview", "error", err)
	}
}

func (s *Server) approve(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, err, http.StatusBadRequest)
		return
	}
	if err := s.service.Approve(r.Context(), r.PathValue("id"), r.FormValue("payload_hash")); err != nil {
		s.redirect(w, r, safeMessage(err))
		return
	}
	s.redirect(w, r, "Exact payload approved and queued")
}

func (s *Server) cancel(w http.ResponseWriter, r *http.Request) {
	if err := s.service.Cancel(r.Context(), r.PathValue("id")); err != nil {
		s.redirect(w, r, safeMessage(err))
		return
	}
	s.redirect(w, r, "Job cancelled")
}

func (s *Server) reconcile(w http.ResponseWriter, r *http.Request) {
	if err := s.service.Reconcile(r.Context(), r.PathValue("id")); err != nil {
		s.redirect(w, r, safeMessage(err))
		return
	}
	s.redirect(w, r, "Manual reconciliation recorded; no resend occurred")
}

func (s *Server) jobJSON(w http.ResponseWriter, r *http.Request) {
	jobs, err := s.service.Jobs(r.Context(), 500)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	for _, job := range jobs {
		if job.ID == r.PathValue("id") {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(job)
			return
		}
	}
	http.Error(w, "job not found", http.StatusNotFound)
}

func (s *Server) emergencyStop(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, err, http.StatusBadRequest)
		return
	}
	enabled := r.FormValue("enabled") == "1"
	reason := "operator activated emergency stop"
	if err := s.service.EmergencyStop(r.Context(), enabled, reason); err != nil {
		s.redirect(w, r, "Emergency control failed")
		return
	}
	message := "Emergency stop cleared"
	if enabled {
		message = "Emergency stop active"
	}
	s.redirect(w, r, message)
}

func (s *Server) xOAuthStart(w http.ResponseWriter, r *http.Request) {
	if s.config.XOAuth == nil {
		http.Error(w, "X OAuth is unavailable until the dedicated France egress transport is ready", http.StatusServiceUnavailable)
		return
	}
	authorizeURL, err := s.config.XOAuth.Begin(s.auth.CSRFToken(r))
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, authorizeURL, http.StatusSeeOther)
}

func (s *Server) xOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if s.config.XOAuth == nil {
		http.Error(w, "X OAuth is unavailable until the dedicated France egress transport is ready", http.StatusServiceUnavailable)
		return
	}
	if r.URL.Query().Get("error") != "" {
		s.redirect(w, r, "X authorization was declined")
		return
	}
	if err := s.config.XOAuth.Exchange(r.Context(), r.URL.Query().Get("state"), s.auth.CSRFToken(r), r.URL.Query().Get("code")); err != nil {
		s.redirect(w, r, "X authorization could not be verified")
		return
	}
	s.redirect(w, r, "X connection established through the pinned egress transport")
}

func (s *Server) revokeConnection(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("platform") != "x" {
		http.Error(w, "connection revocation is not implemented for this platform", http.StatusNotImplemented)
		return
	}
	if s.config.XOAuth == nil {
		http.Error(w, "X OAuth is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := s.config.XOAuth.Revoke(r.Context()); err != nil {
		s.redirect(w, r, "X token revocation could not be confirmed; local token retained")
		return
	}
	s.redirect(w, r, "X access revoked and local token deleted")
}

func (s *Server) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.auth.ValidateCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (s *Server) requireOperational(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.auth.OperationallyReady() {
			http.Error(w, "register two passkeys before enabling publication controls", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error, status int) {
	s.log.Error("request failed", "method", r.Method, "path", r.URL.Path, "error", err)
	http.Error(w, http.StatusText(status), status)
}

func (s *Server) redirect(w http.ResponseWriter, r *http.Request, message string) {
	http.Redirect(w, r, "/?msg="+url.QueryEscape(flashCode(message)), http.StatusSeeOther)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func defaultCountries() []countryView {
	return []countryView{
		{Code: "FR", Name: "France", Status: "UNPROVISIONED"},
		{Code: "DE", Name: "Germany", Status: "UNPROVISIONED"},
		{Code: "GB", Name: "United Kingdom", Status: "UNPROVISIONED"},
		{Code: "SE", Name: "Sweden", Status: "UNPROVISIONED"},
		{Code: "CH", Name: "Switzerland", Status: "UNPROVISIONED"},
	}
}

func safeMessage(err error) string {
	switch {
	case errors.Is(err, domain.ErrInvalidContent), errors.Is(err, domain.ErrNoDestination), errors.Is(err, domain.ErrInvalidTransition):
		return err.Error()
	case strings.Contains(err.Error(), "emergency stop"), strings.Contains(err.Error(), "approval hash"):
		return err.Error()
	default:
		return "Request could not be completed"
	}
}

func flashCode(message string) string {
	switch message {
	case "Invalid schedule time":
		return "invalid-schedule"
	case "Exact payload approved and queued":
		return "approved"
	case "Job cancelled":
		return "cancelled"
	case "Manual reconciliation recorded; no resend occurred":
		return "reconciled"
	case "Emergency control failed":
		return "emergency-failed"
	case "Emergency stop cleared":
		return "emergency-cleared"
	case "Emergency stop active":
		return "emergency-active"
	case "X authorization was declined":
		return "x-declined"
	case "X authorization could not be verified":
		return "x-auth-failed"
	case "X connection established through the pinned egress transport":
		return "x-connected"
	case "X token revocation could not be confirmed; local token retained":
		return "x-revoke-failed"
	case "X access revoked and local token deleted":
		return "x-revoked"
	}
	if strings.Contains(message, "approval hash") {
		return "approval-rejected"
	}
	if message == domain.ErrInvalidContent.Error() || message == domain.ErrNoDestination.Error() || message == domain.ErrInvalidTransition.Error() {
		return "invalid-request"
	}
	return "request-failed"
}

func flashMessage(code string) string {
	switch code {
	case "invalid-schedule":
		return "Invalid schedule time"
	case "approved":
		return "Exact payload approved and queued"
	case "cancelled":
		return "Job cancelled"
	case "reconciled":
		return "Manual reconciliation recorded; no resend occurred"
	case "emergency-failed":
		return "Emergency control failed"
	case "emergency-cleared":
		return "Emergency stop cleared"
	case "emergency-active":
		return "Emergency stop active"
	case "x-declined":
		return "X authorization was declined"
	case "x-auth-failed":
		return "X authorization could not be verified"
	case "x-connected":
		return "X connection established through the pinned egress transport"
	case "x-revoke-failed":
		return "X token revocation could not be confirmed; local token retained"
	case "x-revoked":
		return "X access revoked and local token deleted"
	case "approval-rejected":
		return "Approval rejected because the exact payload hash did not match"
	case "invalid-request":
		return "The request content, destination, or state was invalid"
	case "request-failed":
		return "Request could not be completed"
	default:
		return ""
	}
}
