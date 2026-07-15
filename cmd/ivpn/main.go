package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ivpn/internal/app"
	"ivpn/internal/auth"
	"ivpn/internal/secure"
	"ivpn/internal/store"
	webui "ivpn/internal/web"
)

var version = "dev"

type config struct {
	Listen           string
	Origin           string
	RPID             string
	DatabasePath     string
	MasterKey        string
	BootstrapToken   string
	TLSCert          string
	TLSKey           string
	DryRun           bool
	DevMode          bool
	Timezone         string
	XEstimatedCharge string
}

func main() {
	generateKey := flag.Bool("generate-master-key", false, "print a new base64 master key and exit")
	check := flag.Bool("check", false, "validate configuration and database access, then exit")
	flag.Parse()

	if *generateKey {
		value, err := secure.GenerateMasterKey()
		if err != nil {
			fatal("generate master key", err)
		}
		fmt.Println(value)
		return
	}

	cfg, err := loadConfig()
	if err != nil {
		fatal("configuration rejected", err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := os.MkdirAll(filepath.Dir(cfg.DatabasePath), 0o700); err != nil {
		fatal("create data directory", err)
	}
	key, err := secure.DecodeMasterKey(cfg.MasterKey)
	if err != nil {
		fatal("decode master key", err)
	}
	envelope, err := secure.NewEnvelope(key)
	zero(key)
	if err != nil {
		fatal("initialize envelope encryption", err)
	}
	database, err := store.OpenEncrypted(cfg.DatabasePath, envelope)
	if err != nil {
		fatal("open encrypted job store", err)
	}
	defer database.Close()

	authn, err := auth.New(context.Background(), database, auth.Config{
		RPID: cfg.RPID, Origin: cfg.Origin, BootstrapToken: cfg.BootstrapToken,
		SessionTTL: 15 * time.Minute, DevMode: cfg.DevMode,
	})
	if err != nil {
		fatal("initialize passkey authentication", err)
	}
	service := app.NewService(database, envelope, app.WithXEstimatedCharge(cfg.XEstimatedCharge))
	ui, err := webui.New(service, authn, webui.Config{DryRun: cfg.DryRun, Timezone: cfg.Timezone}, logger)
	if err != nil {
		fatal("initialize web interface", err)
	}

	if *check {
		logger.Info("configuration check passed", "version", version, "dry_run", cfg.DryRun, "listen", cfg.Listen)
		return
	}

	server := &http.Server{
		Addr: cfg.Listen, Handler: ui.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go retentionLoop(ctx, database, logger)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
		}
	}()

	logger.Info("control plane starting", "version", version, "listen", cfg.Listen, "dry_run", cfg.DryRun, "dev_mode", cfg.DevMode)
	if cfg.TLSCert != "" {
		err = server.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal("server failed", err)
	}
}

func loadConfig() (config, error) {
	masterKey, err := secretValue("IVPN_MASTER_KEY")
	if err != nil {
		return config{}, err
	}
	bootstrapToken, err := secretValue("IVPN_BOOTSTRAP_TOKEN")
	if err != nil {
		return config{}, err
	}
	cfg := config{
		Listen:       value("IVPN_LISTEN", "127.0.0.1:8443"),
		Origin:       value("IVPN_ORIGIN", "https://ivpn.internal"),
		DatabasePath: value("IVPN_DATABASE", filepath.Join("data", "ivpn.db")),
		MasterKey:    masterKey, BootstrapToken: bootstrapToken,
		TLSCert: os.Getenv("IVPN_TLS_CERT"), TLSKey: os.Getenv("IVPN_TLS_KEY"),
		DryRun: boolValue("IVPN_DRY_RUN", true), DevMode: boolValue("IVPN_DEV_MODE", false),
		Timezone:         value("IVPN_TIMEZONE", "Europe/Paris"),
		XEstimatedCharge: os.Getenv("IVPN_X_ESTIMATED_CHARGE"),
	}
	parsed, err := url.Parse(cfg.Origin)
	if err != nil || parsed.Hostname() == "" {
		return config{}, errors.New("IVPN_ORIGIN must be an absolute URL")
	}
	cfg.RPID = value("IVPN_RPID", parsed.Hostname())
	if cfg.MasterKey == "" {
		return config{}, errors.New("IVPN_MASTER_KEY is required; run ivpn --generate-master-key")
	}
	if !cfg.DevMode {
		if parsed.Scheme != "https" {
			return config{}, errors.New("production origin must use HTTPS")
		}
		if cfg.TLSCert == "" || cfg.TLSKey == "" {
			return config{}, errors.New("production requires IVPN_TLS_CERT and IVPN_TLS_KEY")
		}
		if len(cfg.BootstrapToken) < 32 {
			return config{}, errors.New("IVPN_BOOTSTRAP_TOKEN must contain at least 32 characters")
		}
	}
	if !cfg.DryRun {
		return config{}, errors.New("live mode is disabled until the broker, X OAuth, and NIP-46 readiness checks all pass")
	}
	return cfg, nil
}

func secretValue(name string) (string, error) {
	direct := strings.TrimSpace(os.Getenv(name))
	path := strings.TrimSpace(os.Getenv(name + "_FILE"))
	if direct != "" && path != "" {
		return "", fmt.Errorf("%s and %s_FILE cannot both be set", name, name)
	}
	if path == "" {
		return direct, nil
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s_FILE must be an absolute path", name)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect %s_FILE: %w", name, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 4096 {
		return "", fmt.Errorf("%s_FILE must be a small regular non-symlink file", name)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s_FILE must not be accessible by group or other users", name)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s_FILE: %w", name, err)
	}
	value := strings.TrimSpace(string(encoded))
	for index := range encoded {
		encoded[index] = 0
	}
	return value, nil
}

func retentionLoop(ctx context.Context, database *store.SQLite, logger *slog.Logger) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().UTC().Add(-7 * 24 * time.Hour)
			removed, err := database.PurgeAuditBefore(ctx, cutoff)
			if err != nil {
				logger.Error("audit retention failed", "error", err)
				continue
			}
			jobsRemoved, err := database.PurgeResolvedJobsBefore(ctx, cutoff)
			if err != nil {
				logger.Error("job retention failed", "error", err)
				continue
			}
			logger.Info("retention complete", "audit_records_removed", removed, "resolved_jobs_removed", jobsRemoved)
		}
	}
}

func value(name, fallback string) string {
	if current := strings.TrimSpace(os.Getenv(name)); current != "" {
		return current
	}
	return fallback
}

func boolValue(name string, fallback bool) bool {
	current := strings.TrimSpace(os.Getenv(name))
	if current == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(current)
	if err != nil {
		return fallback
	}
	return parsed
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func fatal(message string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", message, err)
	os.Exit(1)
}
