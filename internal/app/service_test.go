package app

import (
	"context"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"ivpn/internal/domain"
	"ivpn/internal/secure"
	"ivpn/internal/store"
)

func testService(t *testing.T) (*Service, *store.SQLite) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	envelope, err := secure.NewEnvelope(key)
	if err != nil {
		t.Fatal(err)
	}
	return NewService(db, envelope), db
}

func TestApprovalRequiresExactPreviewHash(t *testing.T) {
	ctx := context.Background()
	service, db := testService(t)
	defer db.Close()
	job, err := service.CreateDraft(ctx, CreateDraftInput{Content: "hello cypherpunk", PostToX: true, PostToNostr: true})
	if err != nil {
		t.Fatal(err)
	}
	preview, err := service.Preview(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Approve(ctx, job.ID, "wrong"); err == nil {
		t.Fatal("approval accepted a mismatched payload")
	}
	if err := service.Approve(ctx, job.ID, preview.Hash); err != nil {
		t.Fatal(err)
	}
	approved, err := db.GetJob(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if approved.State != domain.StateApproved || approved.PayloadHash != preview.Hash {
		t.Fatalf("job not approved correctly: %+v", approved)
	}
}

func TestEmergencyStopBlocksApproval(t *testing.T) {
	ctx := context.Background()
	service, db := testService(t)
	defer db.Close()
	job, err := service.CreateDraft(ctx, CreateDraftInput{Content: "hello", PostToX: true})
	if err != nil {
		t.Fatal(err)
	}
	preview, _ := service.Preview(ctx, job.ID)
	if err := service.EmergencyStop(ctx, true, "test"); err != nil {
		t.Fatal(err)
	}
	if err := service.Approve(ctx, job.ID, preview.Hash); err == nil {
		t.Fatal("approval was allowed during emergency stop")
	}
}

func TestPreviewCostSignal(t *testing.T) {
	ctx := context.Background()
	service, db := testService(t)
	defer db.Close()
	now := time.Now().Add(time.Hour)
	job, err := service.CreateDraft(ctx, CreateDraftInput{Content: "https://example.com", PostToX: true, ScheduledAt: &now})
	if err != nil {
		t.Fatal(err)
	}
	preview, err := service.Preview(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if preview.XCost != "UNAVAILABLE — configure from X billing portal" {
		t.Fatalf("unexpected cost %s", preview.XCost)
	}
}

func TestDispatchRevalidatesApprovalHashAndEmergencyState(t *testing.T) {
	ctx := context.Background()
	service, db := testService(t)
	defer db.Close()
	job, err := service.CreateDraft(ctx, CreateDraftInput{Content: "immutable approved content", PostToX: true, PostToNostr: true})
	if err != nil {
		t.Fatal(err)
	}
	preview, err := service.Preview(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Approve(ctx, job.ID, preview.Hash); err != nil {
		t.Fatal(err)
	}
	payload, err := service.PayloadForDispatch(ctx, job.ID)
	if err != nil || payload.Content != "immutable approved content" {
		t.Fatalf("approved payload was not dispatchable: %+v %v", payload, err)
	}
	service.store = &hashDriftStore{SQLite: db}
	if _, err := service.PayloadForDispatch(ctx, job.ID); err == nil {
		t.Fatal("dispatch accepted a changed approval hash")
	}
	service.store = db
	if err := service.EmergencyStop(ctx, true, "test dispatch stop"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.PayloadForDispatch(ctx, job.ID); err == nil {
		t.Fatal("dispatch proceeded during emergency stop")
	}
}

func TestDispatchWaitsForSchedule(t *testing.T) {
	ctx := context.Background()
	service, db := testService(t)
	defer db.Close()
	future := time.Now().UTC().Add(time.Hour)
	job, err := service.CreateDraft(ctx, CreateDraftInput{Content: "scheduled", PostToNostr: true, ScheduledAt: &future})
	if err != nil {
		t.Fatal(err)
	}
	preview, _ := service.Preview(ctx, job.ID)
	if err := service.Approve(ctx, job.ID, preview.Hash); err != nil {
		t.Fatal(err)
	}
	if _, err := service.PayloadForDispatch(ctx, job.ID); err == nil {
		t.Fatal("future scheduled job was dispatched early")
	}
}

type hashDriftStore struct {
	*store.SQLite
}

func (s *hashDriftStore) GetJob(ctx context.Context, id string) (domain.PostJob, error) {
	job, err := s.SQLite.GetJob(ctx, id)
	if err == nil && job.State == domain.StateApproved {
		job.PayloadHash = "changed-after-approval"
	}
	return job, err
}
