package macosproxy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoverRestoresManagedProxy(t *testing.T) {
	dir := t.TempDir()

	original := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Enabled: false,
			Server:  "proxy.example.com",
			Port:    8080,
		},
	}

	if _, err := saveSnapshotToDir(dir, original); err != nil {
		t.Fatal(err)
	}

	current := managedHTTPSSettings()

	read := func(string) (HTTPSSettings, error) {
		return current, nil
	}

	run := func(args ...string) error {
		switch args[0] {
		case "-setsecurewebproxy":
			current.Server = original.Settings.Server
			current.Port = original.Settings.Port
			current.Enabled = true
			return nil

		case "-setsecurewebproxystate":
			if args[2] != "off" {
				t.Fatalf("unexpected proxy state: %v", args)
			}
			current.Enabled = false
			return nil

		default:
			t.Fatalf("unexpected networksetup command: %v", args)
			return nil
		}
	}

	if err := recoverFromDir(dir, read, run); err != nil {
		t.Fatalf("recoverFromDir(): %v", err)
	}

	if current != original.Settings {
		t.Fatalf("settings = %+v, want %+v", current, original.Settings)
	}

	_, err := os.Stat(filepath.Join(dir, backupFileName))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected recovery backup to be removed, got %v", err)
	}
}

func TestRecoverAlreadyRestored(t *testing.T) {
	dir := t.TempDir()

	original := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Enabled: false,
			Server:  "proxy.example.com",
			Port:    8080,
		},
	}

	if _, err := saveSnapshotToDir(dir, original); err != nil {
		t.Fatal(err)
	}

	read := func(string) (HTTPSSettings, error) {
		return original.Settings, nil
	}

	run := func(args ...string) error {
		t.Fatalf("must not modify already restored settings: %v", args)
		return nil
	}

	if err := recoverFromDir(dir, read, run); err != nil {
		t.Fatalf("recoverFromDir(): %v", err)
	}

	_, err := os.Stat(filepath.Join(dir, backupFileName))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected recovery backup to be removed, got %v", err)
	}
}

func TestRecoverPreservesConflictingSettings(t *testing.T) {
	dir := t.TempDir()

	original := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Enabled: false,
			Server:  "proxy.example.com",
			Port:    8080,
		},
	}

	if _, err := saveSnapshotToDir(dir, original); err != nil {
		t.Fatal(err)
	}

	conflicting := HTTPSSettings{
		Enabled: true,
		Server:  "other.example.com",
		Port:    3128,
	}

	read := func(string) (HTTPSSettings, error) {
		return conflicting, nil
	}

	run := func(args ...string) error {
		t.Fatalf("must not overwrite conflicting settings: %v", args)
		return nil
	}

	if err := recoverFromDir(dir, read, run); err == nil {
		t.Fatal("expected recovery conflict")
	}

	if _, err := os.Stat(filepath.Join(dir, backupFileName)); err != nil {
		t.Fatalf("recovery backup must remain: %v", err)
	}
}

func TestRecoverRejectsMissingBackup(t *testing.T) {
	dir := t.TempDir()

	read := func(string) (HTTPSSettings, error) {
		t.Fatal("must not inspect system settings without a backup")
		return HTTPSSettings{}, nil
	}

	run := func(args ...string) error {
		t.Fatal("must not change system settings without a backup")
		return nil
	}

	err := recoverFromDir(dir, read, run)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected missing backup error, got %v", err)
	}
}

func TestRecoverAlreadyRestoredOnMacOS(t *testing.T) {
	service := os.Getenv("PACKETSAIL_TEST_NETWORK_SERVICE")
	if service == "" {
		t.Skip("set PACKETSAIL_TEST_NETWORK_SERVICE to run")
	}

	// Read the actual configuration without changing it.
	settings, err := ReadHTTPSSettings(service)
	if err != nil {
		t.Fatalf("read current HTTPS proxy settings: %v", err)
	}

	original := HTTPSProxySnapshot{
		Service:  service,
		Settings: settings,
	}

	dir := t.TempDir()

	// Store a real snapshot in an isolated temporary directory.
	if _, err := saveSnapshotToDir(dir, original); err != nil {
		t.Fatalf("save temporary recovery backup: %v", err)
	}

	// No networksetup write should be needed because the actual configuration already matches the snapshot.
	run := func(args ...string) error {
		t.Errorf("unexpected networksetup modification: %v", args)
		return errors.New("network modification forbidden in this test")
	}

	err = recoverFromDir(dir, ReadHTTPSSettings, run)
	if err != nil {
		t.Fatalf("recover already restored configuration: %v", err)
	}

	// Recovery should remove only the temporary test backup.
	path := filepath.Join(dir, backupFileName)

	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary recovery backup was not removed: %v", err)
	}

	// Verify that the actual macOS settings remain unchanged.
	after, err := ReadHTTPSSettings(service)
	if err != nil {
		t.Fatalf("read HTTPS proxy settings after recovery: %v", err)
	}

	if after != settings {
		t.Fatalf(
			"HTTPS proxy settings changed: before=%+v after=%+v",
			settings,
			after,
		)
	}
}
