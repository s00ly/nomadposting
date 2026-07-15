package store

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"ivpn/internal/domain"
	"ivpn/internal/secure"
)

func TestSQLiteJobLifecycleAndCryptographicErasure(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "ivpn.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now().UTC().Truncate(time.Millisecond)
	job := domain.PostJob{
		ID: "job-1", EncryptedContent: []byte{1, 2, 3}, PostToX: true, PostToNostr: true,
		State: domain.StateDraft, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.CreateJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveJob(ctx, job.ID, "approved-hash", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.TransitionJob(ctx, job.ID, domain.StateApproved, domain.StateRouting, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.TransitionJob(ctx, job.ID, domain.StateRouting, domain.StatePublishing, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.TransitionJob(ctx, job.ID, domain.StatePublishing, domain.StateComplete, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.DestroyJobContent(ctx, job.ID, now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetJob(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.ContentDestroyed || len(got.EncryptedContent) != 0 {
		t.Fatalf("content was not destroyed: %+v", got)
	}
	if got.State != domain.StateComplete {
		t.Fatalf("unexpected state %s", got.State)
	}
}

func TestSQLiteRejectsStateRace(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "ivpn.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	if err := s.CreateJob(ctx, domain.PostJob{ID: "job-1", EncryptedContent: []byte{1}, PostToX: true, State: domain.StateDraft, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.TransitionJob(ctx, "job-1", domain.StateApproved, domain.StateRouting, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected compare-and-swap failure, got %v", err)
	}
}

func TestEmergencyStopPersists(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "ivpn.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := s.SetEmergencyStop(ctx, true, "operator", now); err != nil {
		t.Fatal(err)
	}
	state, err := s.SystemState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !state.EmergencyStop || state.Reason != "operator" || !state.UpdatedAt.Equal(now) {
		t.Fatalf("unexpected state %+v", state)
	}
}

func TestPurgeResolvedJobsBeforeKeepsReconciliationStates(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "ivpn.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	old := time.Now().UTC().Add(-8 * 24 * time.Hour).Truncate(time.Millisecond)
	for _, job := range []domain.PostJob{
		{ID: "complete-old", EncryptedContent: []byte{1}, PostToX: true, State: domain.StateComplete, CreatedAt: old, UpdatedAt: old},
		{ID: "unknown-old", EncryptedContent: []byte{2}, PostToX: true, State: domain.StateUnknown, CreatedAt: old, UpdatedAt: old},
		{ID: "partial-old", EncryptedContent: []byte{3}, PostToNostr: true, State: domain.StatePartial, CreatedAt: old, UpdatedAt: old},
	} {
		if err := s.CreateJob(ctx, job); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AddReceipt(ctx, domain.PlatformReceipt{
		JobID: "complete-old", Platform: domain.PlatformX, State: domain.ReceiptSuccess, CreatedAt: old,
	}); err != nil {
		t.Fatal(err)
	}

	removed, err := s.PurgeResolvedJobsBefore(ctx, time.Now().UTC().Add(-7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed %d jobs, want 1", removed)
	}
	if _, err := s.GetJob(ctx, "complete-old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("terminal job survived retention: %v", err)
	}
	for _, id := range []string{"unknown-old", "partial-old"} {
		if _, err := s.GetJob(ctx, id); err != nil {
			t.Fatalf("reconciliation job %s was deleted: %v", id, err)
		}
	}
	var receiptCount int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM receipts WHERE job_id=?`, "complete-old").Scan(&receiptCount); err != nil {
		t.Fatal(err)
	}
	if receiptCount != 0 {
		t.Fatalf("receipt cascade left %d rows", receiptCount)
	}
}

func TestEncryptedStoreSealsCredentialsReceiptsAndAuditDetails(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x42}, 32)
	envelope, err := secure.NewEnvelope(key)
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenEncrypted(filepath.Join(t.TempDir(), "ivpn.db"), envelope)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now().UTC().Truncate(time.Millisecond)
	job := domain.PostJob{ID: "job-encrypted", EncryptedContent: []byte{1}, PostToX: true, State: domain.StateDraft, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	receipt := domain.PlatformReceipt{
		JobID: "job-encrypted", Platform: domain.PlatformX, State: domain.ReceiptSuccess,
		ExternalID: "sensitive-external-id", CountryCode: "FR", AttemptCount: 1, CreatedAt: now,
	}
	if err := s.AddReceipt(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	audit := domain.AuditEvent{JobID: job.ID, Kind: "secret-kind", Detail: "sensitive-audit-detail", CreatedAt: now}
	if err := s.AddAudit(ctx, audit); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveAuthState(ctx, []byte("sensitive-user-id"), []byte(`[{"credential":"sensitive"}]`), now); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveXOAuthTokens(ctx, []byte(`{"access_token":"sensitive-access-token"}`), now); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRecoveryHash(ctx, []byte("sensitive-recovery-hash-value"), now); err != nil {
		t.Fatal(err)
	}

	var rawReceipt, rawAudit, rawUser, rawCredentials, rawTokens, rawRecovery []byte
	if err := s.db.QueryRowContext(ctx, `SELECT encrypted_payload FROM receipts WHERE job_id=?`, job.ID).Scan(&rawReceipt); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT encrypted_payload FROM audit_events LIMIT 1`).Scan(&rawAudit); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT user_id, credentials_json FROM auth_state WHERE id=1`).Scan(&rawUser, &rawCredentials); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT encrypted_payload FROM x_oauth_state WHERE id=1`).Scan(&rawTokens); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT encrypted_hash FROM auth_recovery_state WHERE id=1`).Scan(&rawRecovery); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{"receipt": rawReceipt, "audit": rawAudit, "user": rawUser, "credentials": rawCredentials, "tokens": rawTokens, "recovery": rawRecovery} {
		if len(raw) == 0 || bytes.Contains(raw, []byte("sensitive")) {
			t.Fatalf("%s was not sealed at rest", name)
		}
	}

	receipts, err := s.ListReceipts(ctx, job.ID)
	if err != nil || len(receipts) != 1 || receipts[0].ExternalID != receipt.ExternalID || receipts[0].CountryCode != "FR" {
		t.Fatalf("receipt round trip failed: %+v, %v", receipts, err)
	}
	auditEvents, err := s.ListAudit(ctx, 10)
	if err != nil || len(auditEvents) != 1 || auditEvents[0].Detail != audit.Detail {
		t.Fatalf("audit round trip failed: %+v, %v", auditEvents, err)
	}
	userID, credentials, found, err := s.LoadAuthState(ctx)
	if err != nil || !found || string(userID) != "sensitive-user-id" || !bytes.Contains(credentials, []byte("sensitive")) {
		t.Fatalf("auth state round trip failed: %q %q found=%t %v", userID, credentials, found, err)
	}
	tokens, found, err := s.LoadXOAuthTokens(ctx)
	if err != nil || !found || !bytes.Contains(tokens, []byte("sensitive-access-token")) {
		t.Fatalf("X token round trip failed: %q found=%t %v", tokens, found, err)
	}
	if err := s.DeleteXOAuthTokens(ctx); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.LoadXOAuthTokens(ctx); err != nil || found {
		t.Fatalf("X token deletion failed: found=%t %v", found, err)
	}
	recoveryHash, found, err := s.LoadRecoveryHash(ctx)
	if err != nil || !found || string(recoveryHash) != "sensitive-recovery-hash-value" {
		t.Fatalf("recovery hash round trip failed: %q found=%t %v", recoveryHash, found, err)
	}
}
