package app

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"ivpn/internal/domain"
	"ivpn/internal/secure"
)

type Store interface {
	CreateJob(context.Context, domain.PostJob) error
	GetJob(context.Context, string) (domain.PostJob, error)
	ListJobs(context.Context, int) ([]domain.JobSummary, error)
	ApproveJob(context.Context, string, string, time.Time) error
	TransitionJob(context.Context, string, domain.JobState, domain.JobState, time.Time) error
	DestroyJobContent(context.Context, string, time.Time) error
	AddAudit(context.Context, domain.AuditEvent) error
	ListAudit(context.Context, int) ([]domain.AuditEvent, error)
	SystemState(context.Context) (domain.SystemState, error)
	SetEmergencyStop(context.Context, bool, string, time.Time) error
}

type Service struct {
	store            Store
	sealer           *secure.Envelope
	now              func() time.Time
	xEstimatedCharge string
}

type Option func(*Service)

// WithXEstimatedCharge sets an operator-supplied estimate from the account's
// current X developer billing terms. The application does not invent a price.
func WithXEstimatedCharge(value string) Option {
	return func(service *Service) {
		value = strings.TrimSpace(value)
		if value != "" && len(value) <= 80 {
			service.xEstimatedCharge = value
		}
	}
}

type CreateDraftInput struct {
	Content     string
	PostToX     bool
	PostToNostr bool
	ScheduledAt *time.Time
}

type Preview struct {
	Job     domain.PostJob
	Content string
	Hash    string
	XCost   string
}

type ApprovedPayload struct {
	Job     domain.PostJob
	Content string
}

func NewService(store Store, sealer *secure.Envelope, options ...Option) *Service {
	service := &Service{
		store: store, sealer: sealer, now: func() time.Time { return time.Now().UTC() },
		xEstimatedCharge: "UNAVAILABLE — configure from X billing portal",
	}
	for _, option := range options {
		option(service)
	}
	return service
}

func (s *Service) CreateDraft(ctx context.Context, input CreateDraftInput) (domain.PostJob, error) {
	content, err := domain.NormalizeContent(input.Content)
	if err != nil {
		return domain.PostJob{}, err
	}
	if !input.PostToX && !input.PostToNostr {
		return domain.PostJob{}, domain.ErrNoDestination
	}
	if input.ScheduledAt != nil {
		scheduled := input.ScheduledAt.UTC()
		input.ScheduledAt = &scheduled
	}
	id, err := randomID()
	if err != nil {
		return domain.PostJob{}, err
	}
	sealed, err := s.sealer.Seal([]byte(content), []byte(id))
	if err != nil {
		return domain.PostJob{}, err
	}
	now := s.now()
	job := domain.PostJob{
		ID: id, EncryptedContent: sealed, PostToX: input.PostToX, PostToNostr: input.PostToNostr,
		State: domain.StateDraft, ScheduledAt: input.ScheduledAt, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.CreateJob(ctx, job); err != nil {
		return domain.PostJob{}, err
	}
	_ = s.audit(ctx, id, "draft.created", destinationDetail(input.PostToX, input.PostToNostr))
	return job, nil
}

func (s *Service) Preview(ctx context.Context, id string) (Preview, error) {
	job, err := s.store.GetJob(ctx, id)
	if err != nil {
		return Preview{}, err
	}
	if job.ContentDestroyed || len(job.EncryptedContent) == 0 {
		return Preview{}, errors.New("post content has been cryptographically erased")
	}
	plaintext, err := s.sealer.Open(job.EncryptedContent, []byte(id))
	if err != nil {
		return Preview{}, err
	}
	scheduled := ""
	if job.ScheduledAt != nil {
		scheduled = job.ScheduledAt.UTC().Format(time.RFC3339Nano)
	}
	hash, err := domain.ApprovalHash(string(plaintext), job.PostToX, job.PostToNostr, scheduled)
	if err != nil {
		return Preview{}, err
	}
	return Preview{Job: job, Content: string(plaintext), Hash: hash, XCost: s.xEstimatedCharge}, nil
}

func (s *Service) Approve(ctx context.Context, id, expectedHash string) error {
	state, err := s.store.SystemState(ctx)
	if err != nil {
		return err
	}
	if state.EmergencyStop {
		return fmt.Errorf("emergency stop is active: %s", state.Reason)
	}
	preview, err := s.Preview(ctx, id)
	if err != nil {
		return err
	}
	if preview.Job.State != domain.StateDraft {
		return domain.ErrInvalidTransition
	}
	if expectedHash == "" || expectedHash != preview.Hash {
		return errors.New("approval hash does not match exact preview")
	}
	now := s.now()
	if err := s.store.ApproveJob(ctx, id, preview.Hash, now); err != nil {
		return err
	}
	return s.audit(ctx, id, "job.approved", "exact preview hash verified")
}

// PayloadForDispatch re-opens the approved record immediately before routing
// and rejects state, schedule, emergency-stop, or exact-hash drift.
func (s *Service) PayloadForDispatch(ctx context.Context, id string) (ApprovedPayload, error) {
	state, err := s.store.SystemState(ctx)
	if err != nil {
		return ApprovedPayload{}, err
	}
	if state.EmergencyStop {
		return ApprovedPayload{}, fmt.Errorf("emergency stop is active: %s", state.Reason)
	}
	preview, err := s.Preview(ctx, id)
	if err != nil {
		return ApprovedPayload{}, err
	}
	if preview.Job.State != domain.StateApproved {
		return ApprovedPayload{}, domain.ErrInvalidTransition
	}
	if preview.Job.ScheduledAt != nil && preview.Job.ScheduledAt.After(s.now()) {
		return ApprovedPayload{}, errors.New("approved job is not scheduled to run yet")
	}
	if len(preview.Job.PayloadHash) != len(preview.Hash) || subtle.ConstantTimeCompare([]byte(preview.Job.PayloadHash), []byte(preview.Hash)) != 1 {
		return ApprovedPayload{}, errors.New("approved payload hash changed before dispatch")
	}
	return ApprovedPayload{Job: preview.Job, Content: preview.Content}, nil
}

func (s *Service) Cancel(ctx context.Context, id string) error {
	job, err := s.store.GetJob(ctx, id)
	if err != nil {
		return err
	}
	if err := s.store.TransitionJob(ctx, id, job.State, domain.StateCancelled, s.now()); err != nil {
		return err
	}
	return s.audit(ctx, id, "job.cancelled", "operator cancelled before completion")
}

func (s *Service) Reconcile(ctx context.Context, id string) error {
	job, err := s.store.GetJob(ctx, id)
	if err != nil {
		return err
	}
	if job.State != domain.StateUnknown && job.State != domain.StatePartial {
		return domain.ErrInvalidTransition
	}
	return s.audit(ctx, id, "job.reconcile.requested", "manual reconciliation queued; no automatic resend")
}

func (s *Service) Jobs(ctx context.Context, limit int) ([]domain.JobSummary, error) {
	return s.store.ListJobs(ctx, limit)
}

func (s *Service) Audit(ctx context.Context, limit int) ([]domain.AuditEvent, error) {
	return s.store.ListAudit(ctx, limit)
}

func (s *Service) SystemState(ctx context.Context) (domain.SystemState, error) {
	return s.store.SystemState(ctx)
}

func (s *Service) EmergencyStop(ctx context.Context, stopped bool, reason string) error {
	if stopped && reason == "" {
		reason = "operator activated emergency stop"
	}
	if !stopped {
		reason = ""
	}
	now := s.now()
	if err := s.store.SetEmergencyStop(ctx, stopped, reason, now); err != nil {
		return err
	}
	kind := "system.emergency_stop.disabled"
	if stopped {
		kind = "system.emergency_stop.enabled"
	}
	return s.audit(ctx, "", kind, reason)
}

func (s *Service) audit(ctx context.Context, jobID, kind, detail string) error {
	return s.store.AddAudit(ctx, domain.AuditEvent{JobID: jobID, Kind: kind, Detail: detail, CreatedAt: s.now()})
}

func randomID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func destinationDetail(x, nostr bool) string {
	switch {
	case x && nostr:
		return "destinations=x,nostr"
	case x:
		return "destination=x"
	default:
		return "destination=nostr"
	}
}
