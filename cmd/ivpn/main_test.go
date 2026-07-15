package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretValueRejectsAmbiguousOrRelativeSources(t *testing.T) {
	t.Setenv("IVPN_TEST_SECRET", "direct")
	t.Setenv("IVPN_TEST_SECRET_FILE", "relative.secret")
	if _, err := secretValue("IVPN_TEST_SECRET"); err == nil {
		t.Fatal("ambiguous secret sources were accepted")
	}
	t.Setenv("IVPN_TEST_SECRET", "")
	if _, err := secretValue("IVPN_TEST_SECRET"); err == nil {
		t.Fatal("relative secret file was accepted")
	}
}

func TestSecretValueReadsSmallNonSymlinkFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("  secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IVPN_TEST_SECRET", "")
	t.Setenv("IVPN_TEST_SECRET_FILE", path)
	value, err := secretValue("IVPN_TEST_SECRET")
	if err != nil || value != "secret-value" {
		t.Fatalf("unexpected secret read value=%q err=%v", value, err)
	}
}

func TestLoadConfigRefusesLiveModeUntilReadinessGatesPass(t *testing.T) {
	t.Setenv("IVPN_MASTER_KEY", strings.Repeat("A", 43))
	t.Setenv("IVPN_BOOTSTRAP_TOKEN", "")
	t.Setenv("IVPN_DEV_MODE", "true")
	t.Setenv("IVPN_ORIGIN", "http://localhost:8443")
	t.Setenv("IVPN_DRY_RUN", "false")
	if _, err := loadConfig(); err == nil {
		t.Fatal("live mode was accepted")
	}
}
