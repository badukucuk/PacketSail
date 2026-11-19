package macosproxy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyHTTPSProxyState(t *testing.T) {
	original := HTTPSSettings{
		Enabled: false,
		Server:  "127.0.0.1",
		Port:    9877,
	}

	tests := []struct {
		name     string
		original HTTPSSettings
		current  HTTPSSettings
		want     RecoveryState
	}{
		{
			name:     "original settings unchanged",
			original: original,
			current:  original,
			want:     RecoveryOriginal,
		},
		{
			name:     "PacketSail settings active",
			original: original,
			current:  managedHTTPSSettings(),
			want:     RecoveryManaged,
		},
		{
			name:     "user changed proxy server",
			original: original,
			current: HTTPSSettings{
				Enabled: true,
				Server:  "proxy.example.com",
				Port:    8080,
			},
			want: RecoveryConflict,
		},
		{
			name:     "user disabled PacketSail proxy",
			original: original,
			current: HTTPSSettings{
				Enabled: false,
				Server:  "127.0.0.1",
				Port:    9877,
			},
			want: RecoveryOriginal,
		},
		{
			name:     "original already matches PacketSail",
			original: managedHTTPSSettings(),
			current:  managedHTTPSSettings(),
			want:     RecoveryOriginal,
		},
		{
			name: "original proxy was enabled",
			original: HTTPSSettings{
				Enabled: true,
				Server:  "corporate.example.com",
				Port:    8080,
			},
			current: managedHTTPSSettings(),
			want:    RecoveryManaged,
		},
		{
			name:     "authentication unexpectedly enabled",
			original: original,
			current: HTTPSSettings{
				Enabled:       true,
				Server:        "127.0.0.1",
				Port:          9877,
				Authenticated: true,
			},
			want: RecoveryConflict,
		},
		{
			name:     "user changed saved port",
			original: original,
			current: HTTPSSettings{
				Enabled: false,
				Server:  "127.0.0.1",
				Port:    8080,
			},
			want: RecoveryConflict,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyHTTPSProxyState(
				tt.original,
				tt.current,
			)

			if got != tt.want {
				t.Errorf(
					"classifyHTTPSProxyState() = %q, want %q",
					got,
					tt.want,
				)
			}
		})
	}
}

func TestRestoreHTTPSProxyIfSafe(t *testing.T) {
	original := HTTPSSettings{
		Server: "127.0.0.1",
		Port:   9877,
	}

	snapshot := HTTPSProxySnapshot{
		Service:  "Wi-Fi",
		Settings: original,
	}

	current := managedHTTPSSettings()
	commands := 0

	read := func(service string) (HTTPSSettings, error) {
		if service != "Wi-Fi" {
			t.Fatalf("unexpected service: %q", service)
		}

		return current, nil
	}

	run := func(args ...string) error {
		commands++

		switch args[0] {
		case "-setsecurewebproxy":
			current.Server = args[2]
			current.Port = 9877
			current.Enabled = true

		case "-setsecurewebproxystate":
			current.Enabled = false

		default:
			t.Fatalf("unexpected command: %q", args[0])
		}

		return nil
	}

	if err := restoreHTTPSProxyIfSafe(snapshot, read, run); err != nil {
		t.Fatalf("restoreHTTPSProxyIfSafe() error = %v", err)
	}

	if current != original {
		t.Errorf("restored settings = %+v, want %+v", current, original)
	}

	if commands != 2 {
		t.Errorf("command count = %d, want 2", commands)
	}
}

func TestRestoreHTTPSProxyIfSafeAlreadyOriginal(t *testing.T) {
	original := HTTPSSettings{
		Server: "127.0.0.1",
		Port:   9877,
	}

	snapshot := HTTPSProxySnapshot{
		Service:  "Wi-Fi",
		Settings: original,
	}

	read := func(string) (HTTPSSettings, error) {
		return original, nil
	}

	run := func(args ...string) error {
		t.Fatal("networksetup must not run when settings are original")
		return nil
	}

	if err := restoreHTTPSProxyIfSafe(snapshot, read, run); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreHTTPSProxyIfSafeRejectsConflict(t *testing.T) {
	snapshot := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Server: "127.0.0.1",
			Port:   9877,
		},
	}

	read := func(string) (HTTPSSettings, error) {
		return HTTPSSettings{
			Enabled: true,
			Server:  "another-proxy.example.com",
			Port:    8080,
		}, nil
	}

	run := func(args ...string) error {
		t.Fatal("networksetup must not run when settings conflict")
		return nil
	}

	if err := restoreHTTPSProxyIfSafe(snapshot, read, run); err == nil {
		t.Fatal("expected a conflict error")
	}
}

func TestRestoreHTTPSProxyIfSafePropagatesCommandError(t *testing.T) {
	expected := errors.New("permission denied")

	snapshot := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Server: "127.0.0.1",
			Port:   9877,
		},
	}

	read := func(string) (HTTPSSettings, error) {
		return managedHTTPSSettings(), nil
	}

	run := func(args ...string) error {
		return expected
	}

	err := restoreHTTPSProxyIfSafe(snapshot, read, run)

	if !errors.Is(err, expected) {
		t.Fatalf("expected wrapped error, got %v", err)
	}
}

func TestRestoreHTTPSProxyIfSafeVerifiesResult(t *testing.T) {
	snapshot := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Server: "127.0.0.1",
			Port:   9877,
		},
	}

	read := func(string) (HTTPSSettings, error) {
		// Simulate a system that never applies the restoration.
		return managedHTTPSSettings(), nil
	}

	run := func(args ...string) error {
		return nil
	}

	if err := restoreHTTPSProxyIfSafe(snapshot, read, run); err == nil {
		t.Fatal("expected restoration verification to fail")
	}
}

func TestRecoverRestoresEmptyHTTPSProxySettings(t *testing.T) {
	dir := t.TempDir()

	original := HTTPSProxySnapshot{
		Service:  "Wi-Fi",
		Settings: HTTPSSettings{},
	}

	if _, err := saveSnapshotToDir(dir, original); err != nil {
		t.Fatalf("saveSnapshotToDir(): %v", err)
	}

	current := managedHTTPSSettings()

	read := func(string) (HTTPSSettings, error) {
		return current, nil
	}

	run := func(args ...string) error {
		switch args[0] {
		case "-setsecurewebproxy":
			if args[1] != "Wi-Fi" ||
				args[2] != "" ||
				args[3] != "0" {
				t.Fatalf("unexpected restore command: %v", args)
			}

			current = HTTPSSettings{Enabled: true}

		case "-setsecurewebproxystate":
			if args[1] != "Wi-Fi" || args[2] != "off" {
				t.Fatalf("unexpected state command: %v", args)
			}

			current.Enabled = false

		default:
			t.Fatalf("unexpected command: %v", args)
		}

		return nil
	}

	if err := recoverFromDir(dir, read, run); err != nil {
		t.Fatalf("recoverFromDir(): %v", err)
	}

	if current != original.Settings {
		t.Fatalf("settings = %+v, want %+v", current, original.Settings)
	}

	backupPath := filepath.Join(dir, backupFileName)
	if _, err := os.Stat(backupPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected recovery backup to be removed: %v", err)
	}
}
