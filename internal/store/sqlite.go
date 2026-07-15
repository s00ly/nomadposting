package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"ivpn/internal/domain"
	"ivpn/internal/secure"
)

var ErrNotFound = errors.New("record not found")

type SQLite struct {
	db     *sql.DB
	sealer *secure.Envelope
}

func Open(path string) (*SQLite, error) {
	return open(path, nil)
}

// OpenEncrypted enables per-record envelope encryption for passkey material,
// platform receipts, and detailed audit events. Job content is already sealed
// by the application service before it reaches this layer.
func OpenEncrypted(path string, sealer *secure.Envelope) (*SQLite, error) {
	if sealer == nil {
		return nil, errors.New("encrypted store requires an envelope sealer")
	}
	return open(path, sealer)
}

func open(path string, sealer *secure.Envelope) (*SQLite, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dsn := "file:" + url.PathEscape(filepath.ToSlash(abs)) +
		"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=synchronous(FULL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	store := &SQLite{db: db, sealer: sealer}
	if err := store.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLite) Close() error { return s.db.Close() }

func (s *SQLite) migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS jobs (
			id TEXT PRIMARY KEY,
			encrypted_content BLOB,
			payload_hash TEXT NOT NULL DEFAULT '',
			post_to_x INTEGER NOT NULL CHECK (post_to_x IN (0,1)),
			post_to_nostr INTEGER NOT NULL CHECK (post_to_nostr IN (0,1)),
			state TEXT NOT NULL,
			approved_at INTEGER,
			scheduled_at INTEGER,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			last_nostr_country TEXT NOT NULL DEFAULT '',
			content_destroyed INTEGER NOT NULL DEFAULT 0 CHECK (content_destroyed IN (0,1))
		)`,
		`CREATE INDEX IF NOT EXISTS jobs_state_schedule_idx ON jobs(state, scheduled_at, created_at)`,
		`CREATE TABLE IF NOT EXISTS receipts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
			platform TEXT NOT NULL,
			state TEXT NOT NULL,
			external_id TEXT NOT NULL DEFAULT '',
			country_code TEXT NOT NULL DEFAULT '',
			attempt_count INTEGER NOT NULL DEFAULT 0,
			relay_accepted INTEGER NOT NULL DEFAULT 0,
			relay_attempted INTEGER NOT NULL DEFAULT 0,
			safe_error TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			encrypted_payload BLOB NOT NULL DEFAULT X''
		)`,
		`CREATE INDEX IF NOT EXISTS receipts_job_idx ON receipts(job_id, created_at)`,
		`CREATE TABLE IF NOT EXISTS audit_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			job_id TEXT NOT NULL DEFAULT '',
			kind TEXT NOT NULL,
			detail TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			encrypted_payload BLOB NOT NULL DEFAULT X''
		)`,
		`CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_events(created_at)`,
		`CREATE TABLE IF NOT EXISTS system_state (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			emergency_stop INTEGER NOT NULL CHECK (emergency_stop IN (0,1)),
			reason TEXT NOT NULL DEFAULT '',
			updated_at INTEGER NOT NULL
		)`,
		`INSERT OR IGNORE INTO system_state(id, emergency_stop, reason, updated_at) VALUES(1, 0, '', 0)`,
		`CREATE TABLE IF NOT EXISTS auth_state (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			user_id BLOB NOT NULL,
			credentials_json BLOB NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS auth_recovery_state (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			encrypted_hash BLOB NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS x_oauth_state (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			encrypted_payload BLOB NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("database migration: %w", err)
		}
	}
	for _, column := range []struct {
		table string
		name  string
	}{
		{"receipts", "encrypted_payload"},
		{"audit_events", "encrypted_payload"},
	} {
		if err := s.ensureBlobColumn(ctx, column.table, column.name); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLite) ensureBlobColumn(ctx context.Context, table, name string) error {
	rows, err := s.db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return fmt.Errorf("inspect %s schema: %w", table, err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var columnName, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &columnName, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return err
		}
		if columnName == name {
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if found {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, "ALTER TABLE "+table+" ADD COLUMN "+name+" BLOB NOT NULL DEFAULT X''"); err != nil {
		return fmt.Errorf("add encrypted column to %s: %w", table, err)
	}
	return nil
}

func (s *SQLite) CreateJob(ctx context.Context, job domain.PostJob) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO jobs(
		id, encrypted_content, payload_hash, post_to_x, post_to_nostr, state,
		approved_at, scheduled_at, created_at, updated_at, last_nostr_country, content_destroyed
	) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		job.ID, job.EncryptedContent, job.PayloadHash, boolInt(job.PostToX), boolInt(job.PostToNostr), job.State,
		nullTime(job.ApprovedAt), nullTime(job.ScheduledAt), millis(job.CreatedAt), millis(job.UpdatedAt),
		job.LastNostrCountry, boolInt(job.ContentDestroyed),
	)
	if err != nil {
		return fmt.Errorf("create job: %w", err)
	}
	return nil
}

func (s *SQLite) GetJob(ctx context.Context, id string) (domain.PostJob, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, encrypted_content, payload_hash, post_to_x, post_to_nostr,
		state, approved_at, scheduled_at, created_at, updated_at, last_nostr_country, content_destroyed
		FROM jobs WHERE id = ?`, id)
	job, err := scanJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.PostJob{}, ErrNotFound
	}
	return job, err
}

func (s *SQLite) ListJobs(ctx context.Context, limit int) ([]domain.JobSummary, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, encrypted_content, payload_hash, post_to_x, post_to_nostr,
		state, approved_at, scheduled_at, created_at, updated_at, last_nostr_country, content_destroyed
		FROM jobs ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var summaries []domain.JobSummary
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		receipts, err := s.ListReceipts(ctx, job.ID)
		if err != nil {
			return nil, err
		}
		summaries = append(summaries, domain.JobSummary{
			ID: job.ID, PayloadHash: job.PayloadHash, PostToX: job.PostToX, PostToNostr: job.PostToNostr,
			State: job.State, ApprovedAt: job.ApprovedAt, ScheduledAt: job.ScheduledAt, CreatedAt: job.CreatedAt,
			UpdatedAt: job.UpdatedAt, ContentDestroyed: job.ContentDestroyed, Receipts: receipts,
		})
	}
	return summaries, rows.Err()
}

func (s *SQLite) ApproveJob(ctx context.Context, id, expectedHash string, approvedAt time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE jobs SET payload_hash=?, state=?, approved_at=?, updated_at=?
		WHERE id=? AND state=? AND content_destroyed=0`, expectedHash, domain.StateApproved, millis(approvedAt), millis(approvedAt), id, domain.StateDraft)
	if err != nil {
		return err
	}
	return requireOne(result)
}

func (s *SQLite) TransitionJob(ctx context.Context, id string, from, to domain.JobState, at time.Time) error {
	if err := domain.ValidateTransition(from, to); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE jobs SET state=?, updated_at=? WHERE id=? AND state=?`, to, millis(at), id, from)
	if err != nil {
		return err
	}
	return requireOne(result)
}

func (s *SQLite) DestroyJobContent(ctx context.Context, id string, at time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE jobs SET encrypted_content=NULL, content_destroyed=1, updated_at=?
		WHERE id=? AND content_destroyed=0`, millis(at), id)
	if err != nil {
		return err
	}
	return requireOne(result)
}

func (s *SQLite) SetLastNostrCountry(ctx context.Context, id, country string, at time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE jobs SET last_nostr_country=?, updated_at=? WHERE id=?`, country, millis(at), id)
	if err != nil {
		return err
	}
	return requireOne(result)
}

func (s *SQLite) AddReceipt(ctx context.Context, receipt domain.PlatformReceipt) error {
	if s.sealer != nil {
		encoded, err := json.Marshal(receipt)
		if err != nil {
			return fmt.Errorf("encode receipt: %w", err)
		}
		aad := receiptAAD(receipt.JobID, receipt.CreatedAt)
		sealed, err := s.sealer.Seal(encoded, aad)
		if err != nil {
			return fmt.Errorf("encrypt receipt: %w", err)
		}
		_, err = s.db.ExecContext(ctx, `INSERT INTO receipts(job_id, platform, state, external_id, country_code,
			attempt_count, relay_accepted, relay_attempted, safe_error, created_at, encrypted_payload)
			VALUES(?,?,?,?,?,?,?,?,?,?,?)`, receipt.JobID, "", "", "", "", 0, 0, 0, "", millis(receipt.CreatedAt), sealed)
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO receipts(job_id, platform, state, external_id, country_code,
		attempt_count, relay_accepted, relay_attempted, safe_error, created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		receipt.JobID, receipt.Platform, receipt.State, receipt.ExternalID, receipt.CountryCode,
		receipt.AttemptCount, receipt.RelayAccepted, receipt.RelayAttempted, receipt.SafeError, millis(receipt.CreatedAt))
	return err
}

func (s *SQLite) ListReceipts(ctx context.Context, jobID string) ([]domain.PlatformReceipt, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, job_id, platform, state, external_id, country_code,
		attempt_count, relay_accepted, relay_attempted, safe_error, created_at, encrypted_payload
		FROM receipts WHERE job_id=? ORDER BY created_at ASC`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var receipts []domain.PlatformReceipt
	for rows.Next() {
		var r domain.PlatformReceipt
		var created int64
		var sealed []byte
		if err := rows.Scan(&r.ID, &r.JobID, &r.Platform, &r.State, &r.ExternalID, &r.CountryCode,
			&r.AttemptCount, &r.RelayAccepted, &r.RelayAttempted, &r.SafeError, &created, &sealed); err != nil {
			return nil, err
		}
		r.CreatedAt = fromMillis(created)
		if len(sealed) > 0 {
			if s.sealer == nil {
				return nil, errors.New("encrypted receipt requires encrypted store")
			}
			plaintext, err := s.sealer.Open(sealed, receiptAAD(r.JobID, r.CreatedAt))
			if err != nil {
				return nil, fmt.Errorf("decrypt receipt: %w", err)
			}
			id := r.ID
			if err := json.Unmarshal(plaintext, &r); err != nil {
				return nil, fmt.Errorf("decode receipt: %w", err)
			}
			r.ID = id
		}
		receipts = append(receipts, r)
	}
	return receipts, rows.Err()
}

func (s *SQLite) AddAudit(ctx context.Context, event domain.AuditEvent) error {
	if s.sealer != nil {
		encoded, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("encode audit event: %w", err)
		}
		sealed, err := s.sealer.Seal(encoded, auditAAD(event.CreatedAt))
		if err != nil {
			return fmt.Errorf("encrypt audit event: %w", err)
		}
		_, err = s.db.ExecContext(ctx, `INSERT INTO audit_events(job_id, kind, detail, created_at, encrypted_payload) VALUES(?,?,?,?,?)`,
			"", "", "", millis(event.CreatedAt), sealed)
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_events(job_id, kind, detail, created_at) VALUES(?,?,?,?)`,
		event.JobID, event.Kind, event.Detail, millis(event.CreatedAt))
	return err
}

func (s *SQLite) ListAudit(ctx context.Context, limit int) ([]domain.AuditEvent, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, job_id, kind, detail, created_at, encrypted_payload FROM audit_events ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []domain.AuditEvent
	for rows.Next() {
		var event domain.AuditEvent
		var created int64
		var sealed []byte
		if err := rows.Scan(&event.ID, &event.JobID, &event.Kind, &event.Detail, &created, &sealed); err != nil {
			return nil, err
		}
		event.CreatedAt = fromMillis(created)
		if len(sealed) > 0 {
			if s.sealer == nil {
				return nil, errors.New("encrypted audit event requires encrypted store")
			}
			plaintext, err := s.sealer.Open(sealed, auditAAD(event.CreatedAt))
			if err != nil {
				return nil, fmt.Errorf("decrypt audit event: %w", err)
			}
			id := event.ID
			if err := json.Unmarshal(plaintext, &event); err != nil {
				return nil, fmt.Errorf("decode audit event: %w", err)
			}
			event.ID = id
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *SQLite) PurgeAuditBefore(ctx context.Context, before time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, `DELETE FROM audit_events WHERE created_at < ?`, millis(before))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// PurgeResolvedJobsBefore removes terminal operational metadata. Receipts are
// deleted by the foreign-key cascade. UNKNOWN and PARTIAL are deliberately
// retained because they still require reconciliation.
func (s *SQLite) PurgeResolvedJobsBefore(ctx context.Context, before time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, `DELETE FROM jobs
		WHERE updated_at < ? AND state IN (?,?,?)`, millis(before), domain.StateComplete, domain.StateFailed, domain.StateCancelled)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *SQLite) SystemState(ctx context.Context) (domain.SystemState, error) {
	var stopped int
	var state domain.SystemState
	var updated int64
	err := s.db.QueryRowContext(ctx, `SELECT emergency_stop, reason, updated_at FROM system_state WHERE id=1`).Scan(&stopped, &state.Reason, &updated)
	state.EmergencyStop = stopped == 1
	state.UpdatedAt = fromMillis(updated)
	return state, err
}

func (s *SQLite) SetEmergencyStop(ctx context.Context, stopped bool, reason string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE system_state SET emergency_stop=?, reason=?, updated_at=? WHERE id=1`, boolInt(stopped), reason, millis(at))
	return err
}

func (s *SQLite) LoadAuthState(ctx context.Context) ([]byte, []byte, bool, error) {
	var userID, credentials []byte
	err := s.db.QueryRowContext(ctx, `SELECT user_id, credentials_json FROM auth_state WHERE id=1`).Scan(&userID, &credentials)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, false, nil
	}
	if err != nil || s.sealer == nil {
		return userID, credentials, err == nil, err
	}
	userID, err = s.sealer.Open(userID, []byte("auth:user-id:v1"))
	if err != nil {
		return nil, nil, false, fmt.Errorf("decrypt auth user ID: %w", err)
	}
	credentials, err = s.sealer.Open(credentials, []byte("auth:credentials:v1"))
	if err != nil {
		return nil, nil, false, fmt.Errorf("decrypt passkey credentials: %w", err)
	}
	return userID, credentials, true, nil
}

func (s *SQLite) SaveAuthState(ctx context.Context, userID, credentials []byte, at time.Time) error {
	if s.sealer != nil {
		var err error
		userID, err = s.sealer.Seal(userID, []byte("auth:user-id:v1"))
		if err != nil {
			return fmt.Errorf("encrypt auth user ID: %w", err)
		}
		credentials, err = s.sealer.Seal(credentials, []byte("auth:credentials:v1"))
		if err != nil {
			return fmt.Errorf("encrypt passkey credentials: %w", err)
		}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO auth_state(id, user_id, credentials_json, updated_at) VALUES(1,?,?,?)
		ON CONFLICT(id) DO UPDATE SET user_id=excluded.user_id, credentials_json=excluded.credentials_json, updated_at=excluded.updated_at`,
		userID, credentials, millis(at))
	return err
}

func (s *SQLite) LoadRecoveryHash(ctx context.Context) ([]byte, bool, error) {
	var sealed []byte
	err := s.db.QueryRowContext(ctx, `SELECT encrypted_hash FROM auth_recovery_state WHERE id=1`).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if s.sealer == nil {
		return nil, false, errors.New("encrypted recovery hash requires encrypted store")
	}
	hash, err := s.sealer.Open(sealed, []byte("auth:recovery-hash:v1"))
	if err != nil {
		return nil, false, fmt.Errorf("decrypt recovery hash: %w", err)
	}
	return hash, true, nil
}

func (s *SQLite) SaveRecoveryHash(ctx context.Context, hash []byte, at time.Time) error {
	if s.sealer == nil {
		return errors.New("recovery hash storage requires encrypted store")
	}
	sealed, err := s.sealer.Seal(hash, []byte("auth:recovery-hash:v1"))
	if err != nil {
		return fmt.Errorf("encrypt recovery hash: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO auth_recovery_state(id, encrypted_hash, updated_at) VALUES(1,?,?)
		ON CONFLICT(id) DO UPDATE SET encrypted_hash=excluded.encrypted_hash, updated_at=excluded.updated_at`, sealed, millis(at))
	return err
}

// SaveXOAuthTokens persists only an already-normalized token envelope. The
// SQLite implementation adds per-record encryption and refuses plaintext mode.
func (s *SQLite) SaveXOAuthTokens(ctx context.Context, encoded []byte, at time.Time) error {
	if s.sealer == nil {
		return errors.New("X OAuth token storage requires encrypted store")
	}
	sealed, err := s.sealer.Seal(encoded, []byte("x:oauth-tokens:v1"))
	if err != nil {
		return fmt.Errorf("encrypt X OAuth tokens: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO x_oauth_state(id, encrypted_payload, updated_at) VALUES(1,?,?)
		ON CONFLICT(id) DO UPDATE SET encrypted_payload=excluded.encrypted_payload, updated_at=excluded.updated_at`,
		sealed, millis(at))
	return err
}

func (s *SQLite) LoadXOAuthTokens(ctx context.Context) ([]byte, bool, error) {
	var sealed []byte
	err := s.db.QueryRowContext(ctx, `SELECT encrypted_payload FROM x_oauth_state WHERE id=1`).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if s.sealer == nil {
		return nil, false, errors.New("encrypted X OAuth tokens require encrypted store")
	}
	plaintext, err := s.sealer.Open(sealed, []byte("x:oauth-tokens:v1"))
	if err != nil {
		return nil, false, fmt.Errorf("decrypt X OAuth tokens: %w", err)
	}
	return plaintext, true, nil
}

func (s *SQLite) DeleteXOAuthTokens(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM x_oauth_state WHERE id=1`)
	return err
}

type scanner interface {
	Scan(...any) error
}

func scanJob(row scanner) (domain.PostJob, error) {
	var job domain.PostJob
	var postX, postNostr, destroyed int
	var approved, scheduled sql.NullInt64
	var created, updated int64
	err := row.Scan(&job.ID, &job.EncryptedContent, &job.PayloadHash, &postX, &postNostr, &job.State,
		&approved, &scheduled, &created, &updated, &job.LastNostrCountry, &destroyed)
	if err != nil {
		return domain.PostJob{}, err
	}
	job.PostToX = postX == 1
	job.PostToNostr = postNostr == 1
	job.ContentDestroyed = destroyed == 1
	job.CreatedAt = fromMillis(created)
	job.UpdatedAt = fromMillis(updated)
	job.ApprovedAt = timePtr(approved)
	job.ScheduledAt = timePtr(scheduled)
	return job, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func millis(value time.Time) int64 { return value.UTC().UnixMilli() }

func fromMillis(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.UnixMilli(value).UTC()
}

func receiptAAD(jobID string, created time.Time) []byte {
	return []byte(fmt.Sprintf("receipt:v1:%s:%d", jobID, millis(created)))
}

func auditAAD(created time.Time) []byte {
	return []byte(fmt.Sprintf("audit:v1:%d", millis(created)))
}

func nullTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return millis(*value)
}

func timePtr(value sql.NullInt64) *time.Time {
	if !value.Valid {
		return nil
	}
	parsed := fromMillis(value.Int64)
	return &parsed
}

func requireOne(result sql.Result) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrNotFound
	}
	return nil
}
