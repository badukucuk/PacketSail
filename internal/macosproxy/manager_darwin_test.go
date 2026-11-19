package macosproxy

import (
	"errors"
	"testing"
)

func TestStartProxySession(t *testing.T) {
	snapshot := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Server: "127.0.0.1",
			Port:   9877,
		},
	}

	current := snapshot.Settings
	saved := false
	commands := 0

	read := func(service string) (HTTPSSettings, error) {
		if service != snapshot.Service {
			t.Fatalf("unexpected service: %q", service)
		}
		return current, nil
	}

	save := func(got HTTPSProxySnapshot) (string, error) {
		if got != snapshot {
			t.Fatal("unexpected snapshot")
		}

		saved = true
		return "backup.json", nil
	}

	run := func(args ...string) error {
		if !saved {
			t.Fatal("proxy modified before backup")
		}

		commands++

		if args[0] != "-setsecurewebproxy" {
			t.Fatalf("unexpected command: %q", args[0])
		}

		current = managedHTTPSSettings()
		return nil
	}

	activated, err := startProxySession(snapshot, read, save, run)
	if err != nil {
		t.Fatalf("startProxySession() error = %v", err)
	}

	if !activated {
		t.Fatal("expected PacketSail to activate the HTTPS proxy")
	}

	if !saved || commands != 1 {
		t.Fatalf("saved=%t, commands=%d", saved, commands)
	}
}

func TestStartProxySessionRejectsChangedSettings(t *testing.T) {
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
			Server:  "another.example.com",
			Port:    8080,
		}, nil
	}

	save := func(HTTPSProxySnapshot) (string, error) {
		t.Fatal("must not save a stale snapshot")
		return "", nil
	}

	run := func(args ...string) error {
		t.Fatal("must not modify unexpected settings")
		return nil
	}

	if _, err := startProxySession(snapshot, read, save, run); err == nil {
		t.Fatal("expected changed settings error")
	}
}

func TestStartProxySessionStopsWhenBackupFails(t *testing.T) {
	snapshot := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Server: "127.0.0.1",
			Port:   9877,
		},
	}

	expected := errors.New("backup already exists")

	read := func(string) (HTTPSSettings, error) {
		return snapshot.Settings, nil
	}

	save := func(HTTPSProxySnapshot) (string, error) {
		return "", expected
	}

	run := func(args ...string) error {
		t.Fatal("proxy must not change after backup failure")
		return nil
	}

	_, err := startProxySession(snapshot, read, save, run)
	if !errors.Is(err, expected) {
		t.Fatalf("expected backup error, got %v", err)
	}
}

func TestStartProxySessionPreservesBackupOnFailure(t *testing.T) {
	snapshot := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Server: "127.0.0.1",
			Port:   9877,
		},
	}

	saved := false
	expected := errors.New("permission denied")

	read := func(string) (HTTPSSettings, error) {
		return snapshot.Settings, nil
	}

	save := func(HTTPSProxySnapshot) (string, error) {
		saved = true
		return "backup.json", nil
	}

	run := func(args ...string) error {
		return expected
	}

	_, err := startProxySession(snapshot, read, save, run)

	if !errors.Is(err, expected) {
		t.Fatalf("expected permission error, got %v", err)
	}

	if !saved {
		t.Fatal("backup must exist before the modification attempt")
	}
}

func TestStartProxySessionAlreadyManaged(t *testing.T) {
	snapshot := HTTPSProxySnapshot{
		Service:  "Wi-Fi",
		Settings: managedHTTPSSettings(),
	}

	read := func(service string) (HTTPSSettings, error) {
		if service != snapshot.Service {
			t.Fatalf("unexpected network service: %q", service)
		}

		return snapshot.Settings, nil
	}

	save := func(HTTPSProxySnapshot) (string, error) {
		t.Fatal("existing proxy settings must not be backed up")
		return "", nil
	}

	run := func(args ...string) error {
		t.Fatal("networksetup must not modify an existing configuration")
		return nil
	}

	activated, err := startProxySession(snapshot, read, save, run)
	if err != nil {
		t.Fatalf("startProxySession() error = %v", err)
	}

	if activated {
		t.Fatal("expected an unchanged HTTPS proxy configuration")
	}
}

func TestStartProxySessionWithEmptyInitialSettings(t *testing.T) {
	snapshot := HTTPSProxySnapshot{
		Service:  "Wi-Fi",
		Settings: HTTPSSettings{},
	}

	current := snapshot.Settings
	saved := false

	read := func(service string) (HTTPSSettings, error) {
		if service != snapshot.Service {
			t.Fatalf("unexpected service: %q", service)
		}
		return current, nil
	}

	save := func(got HTTPSProxySnapshot) (string, error) {
		if got != snapshot {
			t.Fatalf("unexpected snapshot: %+v", got)
		}

		saved = true
		return "backup.json", nil
	}

	run := func(args ...string) error {
		if !saved {
			t.Fatal("proxy modified before backup")
		}

		if len(args) != 4 ||
			args[0] != "-setsecurewebproxy" ||
			args[1] != "Wi-Fi" ||
			args[2] != "127.0.0.1" ||
			args[3] != "9877" {
			t.Fatalf("unexpected command: %v", args)
		}

		current = managedHTTPSSettings()
		return nil
	}

	activated, err := startProxySession(
		snapshot,
		read,
		save,
		run,
	)
	if err != nil {
		t.Fatalf("startProxySession(): %v", err)
	}

	if !activated {
		t.Fatal("expected HTTPS proxy activation")
	}

	if !saved {
		t.Fatal("expected original empty settings to be backed up")
	}

	if current != managedHTTPSSettings() {
		t.Fatalf("unexpected settings: %+v", current)
	}
}

func TestStartProxySessionRollbackUnchangedSettings(t *testing.T) {
	original := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Enabled: false,
			Server:  "127.0.0.1",
			Port:    9877,
		},
	}

	current := original.Settings
	activationErr := errors.New("networksetup failed")
	saved := false
	removed := false

	read := func(string) (HTTPSSettings, error) {
		return current, nil
	}

	save := func(HTTPSProxySnapshot) (string, error) {
		saved = true
		return "backup.json", nil
	}

	remove := func(HTTPSProxySnapshot) error {
		if !saved {
			t.Fatal("cannot remove a backup that was not saved")
		}

		removed = true
		return nil
	}

	run := func(args ...string) error {
		return activationErr
	}

	activated, err := startProxySessionWithRollback(original, read, save, remove, run)

	if activated {
		t.Fatal("activation must fail")
	}

	if !errors.Is(err, activationErr) {
		t.Fatalf("expected activation error, got %v", err)
	}

	if !saved || !removed {
		t.Fatal("unchanged settings should allow backup cleanup")
	}
}

func TestStartProxySessionRollbackManagedSettings(t *testing.T) {
	original := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Enabled: false,
			Server:  "proxy.example.com",
			Port:    8080,
		},
	}

	current := original.Settings
	activationErr := errors.New("activation command failed")
	removed := false

	read := func(string) (HTTPSSettings, error) {
		return current, nil
	}

	save := func(HTTPSProxySnapshot) (string, error) {
		return "backup.json", nil
	}

	remove := func(HTTPSProxySnapshot) error {
		if current != original.Settings {
			t.Fatal("backup removed before original settings restored")
		}

		removed = true
		return nil
	}

	run := func(args ...string) error {
		switch args[0] {
		case "-setsecurewebproxy":
			if args[2] == "127.0.0.1" && args[3] == "9877" {
				// Simulate a command that modified the settings but still returned an error.
				current = managedHTTPSSettings()
				return activationErr
			}

			// Simulate restoration of the original server and port.
			current = HTTPSSettings{
				Enabled: true,
				Server:  original.Settings.Server,
				Port:    original.Settings.Port,
			}
			return nil

		case "-setsecurewebproxystate":
			if args[2] != "off" {
				t.Fatalf("unexpected proxy state: %q", args[2])
			}

			current.Enabled = false
			return nil

		default:
			t.Fatalf("unexpected networksetup command: %q", args[0])
			return nil
		}
	}

	activated, err := startProxySessionWithRollback(original, read, save, remove, run)

	if activated {
		t.Fatal("activation must fail")
	}

	if !errors.Is(err, activationErr) {
		t.Fatalf("expected activation error, got %v", err)
	}

	if current != original.Settings {
		t.Fatalf("settings not restored: %+v", current)
	}

	if !removed {
		t.Fatal("verified rollback should remove the backup")
	}
}

func TestStartProxySessionRollbackPreservesConflict(t *testing.T) {
	original := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Enabled: false,
			Server:  "proxy.example.com",
			Port:    8080,
		},
	}

	current := original.Settings
	removed := false
	calls := 0

	read := func(string) (HTTPSSettings, error) {
		return current, nil
	}

	save := func(HTTPSProxySnapshot) (string, error) {
		return "backup.json", nil
	}

	remove := func(HTTPSProxySnapshot) error {
		removed = true
		return nil
	}

	run := func(args ...string) error {
		calls++

		// The settings changed to an unexpected configuration.
		// A real system may have been modified externally.
		current = HTTPSSettings{
			Enabled: true,
			Server:  "other.example.com",
			Port:    8080,
		}

		return errors.New("activation failed")
	}

	activated, err := startProxySessionWithRollback(original, read, save, remove, run)

	if activated || err == nil {
		t.Fatalf("expected activation failure, got %v", err)
	}

	if calls != 1 {
		t.Fatalf("expected one command, got %d", calls)
	}

	if removed {
		t.Fatal("conflicting settings must preserve the recovery backup")
	}

	if current.Server != "other.example.com" {
		t.Fatal("conflicting settings must not be overwritten")
	}
}

func TestStopProxySessionRestoresOriginalSettings(t *testing.T) {
	original := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Enabled: false,
			Server:  "proxy.example.com",
			Port:    8080,
		},
	}

	current := managedHTTPSSettings()
	removed := false

	read := func(service string) (HTTPSSettings, error) {
		if service != original.Service {
			t.Fatalf("unexpected service: %q", service)
		}

		return current, nil
	}

	run := func(args ...string) error {
		switch args[0] {
		case "-setsecurewebproxy":
			if args[1] != original.Service ||
				args[2] != original.Settings.Server ||
				args[3] != "8080" {
				t.Fatalf("unexpected restore command: %v", args)
			}

			current.Server = original.Settings.Server
			current.Port = original.Settings.Port
			current.Enabled = true
			return nil

		case "-setsecurewebproxystate":
			if args[1] != original.Service || args[2] != "off" {
				t.Fatalf("unexpected state command: %v", args)
			}

			current.Enabled = false
			return nil

		default:
			t.Fatalf("unexpected command: %v", args)
			return nil
		}
	}

	remove := func(snapshot HTTPSProxySnapshot) error {
		if snapshot != original {
			t.Fatal("unexpected backup snapshot")
		}

		if current != original.Settings {
			t.Fatal("backup removed before restoration")
		}

		removed = true
		return nil
	}

	err := stopProxySession(original, true, read, remove, run)
	if err != nil {
		t.Fatalf("stopProxySession() error = %v", err)
	}

	if current != original.Settings {
		t.Fatalf("settings = %+v, want %+v", current, original.Settings)
	}

	if !removed {
		t.Fatal("expected verified backup to be removed")
	}
}

func TestStopProxySessionSkipsUnchangedSettings(t *testing.T) {
	snapshot := HTTPSProxySnapshot{
		Service:  "Wi-Fi",
		Settings: managedHTTPSSettings(),
	}

	read := func(string) (HTTPSSettings, error) {
		t.Fatal("must not read settings for an unmanaged session")
		return HTTPSSettings{}, nil
	}

	remove := func(HTTPSProxySnapshot) error {
		t.Fatal("must not remove an unrelated backup")
		return nil
	}

	run := func(args ...string) error {
		t.Fatal("must not modify existing proxy settings")
		return nil
	}

	if err := stopProxySession(
		snapshot, false, read, remove, run,
	); err != nil {
		t.Fatalf("stopProxySession() error = %v", err)
	}
}

func TestStopProxySessionPreservesConflictingSettings(t *testing.T) {
	original := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Enabled: false,
			Server:  "proxy.example.com",
			Port:    8080,
		},
	}

	changed := HTTPSSettings{
		Enabled: true,
		Server:  "other.example.com",
		Port:    3128,
	}

	read := func(string) (HTTPSSettings, error) {
		return changed, nil
	}

	remove := func(HTTPSProxySnapshot) error {
		t.Fatal("conflicting settings must preserve the backup")
		return nil
	}

	run := func(args ...string) error {
		t.Fatalf("must not overwrite conflicting settings: %v", args)
		return nil
	}

	err := stopProxySession(original, true, read, remove, run)
	if err == nil {
		t.Fatal("expected conflicting settings error")
	}
}

func TestStopProxySessionPreservesCleanupError(t *testing.T) {
	original := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Enabled: false,
			Server:  "proxy.example.com",
			Port:    8080,
		},
	}

	cleanupErr := errors.New("permission denied")

	read := func(string) (HTTPSSettings, error) {
		return original.Settings, nil
	}

	run := func(args ...string) error {
		t.Fatalf("settings are already restored: %v", args)
		return nil
	}

	remove := func(HTTPSProxySnapshot) error {
		return cleanupErr
	}

	err := stopProxySession(original, true, read, remove, run)

	if !errors.Is(err, cleanupErr) {
		t.Fatalf("expected cleanup error, got %v", err)
	}
}

func TestStopProxySessionRestoresEmptySettings(t *testing.T) {
	original := HTTPSProxySnapshot{
		Service:  "Wi-Fi",
		Settings: HTTPSSettings{},
	}

	current := managedHTTPSSettings()
	removed := false
	var commands [][]string

	read := func(string) (HTTPSSettings, error) {
		return current, nil
	}

	run := func(args ...string) error {
		commands = append(
			commands,
			append([]string(nil), args...),
		)

		switch args[0] {
		case "-setsecurewebproxy":
			if args[1] != "Wi-Fi" ||
				args[2] != "" ||
				args[3] != "0" {
				t.Fatalf("unexpected restore command: %v", args)
			}

			current.Server = ""
			current.Port = 0
			current.Enabled = true

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

	remove := func(snapshot HTTPSProxySnapshot) error {
		if snapshot != original || current != original.Settings {
			t.Fatal("backup removed before verified restoration")
		}

		removed = true
		return nil
	}

	if err := stopProxySession(
		original, true, read, remove, run,
	); err != nil {
		t.Fatalf("stopProxySession(): %v", err)
	}

	if current != original.Settings {
		t.Fatalf("settings = %+v, want %+v", current, original.Settings)
	}

	if len(commands) != 2 {
		t.Fatalf("command count = %d, want 2", len(commands))
	}

	if !removed {
		t.Fatal("expected recovery backup cleanup")
	}
}

func TestStartProxySessionRollbackEmptySettings(t *testing.T) {
	original := HTTPSProxySnapshot{
		Service:  "Wi-Fi",
		Settings: HTTPSSettings{},
	}

	current := original.Settings
	activationErr := errors.New("activation failed")
	saved := false
	removed := false

	read := func(string) (HTTPSSettings, error) {
		return current, nil
	}

	save := func(snapshot HTTPSProxySnapshot) (string, error) {
		if snapshot != original {
			t.Fatal("unexpected recovery snapshot")
		}
		saved = true
		return "backup.json", nil
	}

	remove := func(snapshot HTTPSProxySnapshot) error {
		if snapshot != original || current != original.Settings {
			t.Fatal("backup removed before verified rollback")
		}
		removed = true
		return nil
	}

	run := func(args ...string) error {
		if !saved {
			t.Fatal("system modified before backup")
		}

		switch args[0] {
		case "-setsecurewebproxy":
			if args[2] == "127.0.0.1" && args[3] == "9877" {
				current = managedHTTPSSettings()
				return activationErr
			}

			if args[2] != "" || args[3] != "0" {
				t.Fatalf("unexpected restore command: %v", args)
			}

			current = HTTPSSettings{Enabled: true}
			return nil

		case "-setsecurewebproxystate":
			if args[2] != "off" {
				t.Fatalf("unexpected proxy state: %v", args)
			}
			current.Enabled = false
			return nil

		default:
			t.Fatalf("unexpected command: %v", args)
			return nil
		}
	}

	activated, err := startProxySessionWithRollback(
		original, read, save, remove, run,
	)

	if activated {
		t.Fatal("activation must fail")
	}

	if !errors.Is(err, activationErr) {
		t.Fatalf("expected activation error, got %v", err)
	}

	if current != original.Settings {
		t.Fatalf("settings = %+v, want %+v", current, original.Settings)
	}

	if !saved || !removed {
		t.Fatal("expected backup and verified rollback cleanup")
	}
}

func TestStopProxySessionPreservesConflictWithEmptySettings(t *testing.T) {
	original := HTTPSProxySnapshot{
		Service:  "Wi-Fi",
		Settings: HTTPSSettings{},
	}

	changed := HTTPSSettings{
		Enabled: true,
		Server:  "other.example.com",
		Port:    8080,
	}

	read := func(string) (HTTPSSettings, error) {
		return changed, nil
	}

	remove := func(HTTPSProxySnapshot) error {
		t.Fatal("conflicting settings must preserve the backup")
		return nil
	}

	run := func(args ...string) error {
		t.Fatalf("must not overwrite user settings: %v", args)
		return nil
	}

	err := stopProxySession(
		original, true, read, remove, run,
	)

	if err == nil {
		t.Fatal("expected conflicting settings error")
	}

	if changed.Server != "other.example.com" ||
		changed.Port != 8080 {
		t.Fatal("user settings must remain unchanged")
	}
}
