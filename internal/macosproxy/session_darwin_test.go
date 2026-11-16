package macosproxy

import (
	"errors"
	"testing"
)

func TestSessionStartAndStop(t *testing.T) {
	original := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Enabled: false,
			Server:  "proxy.example.com",
			Port:    8080,
		},
	}

	current := original.Settings
	saved := false
	removed := false
	checked := false

	deps := sessionDependencies{
		check: func() error {
			checked = true
			return nil
		},
		capture: func() (HTTPSProxySnapshot, error) {
			if !checked {
				t.Fatal("recovery must be checked first")
			}
			return original, nil
		},
		read: func(string) (HTTPSSettings, error) {
			return current, nil
		},
		save: func(snapshot HTTPSProxySnapshot) (string, error) {
			if snapshot != original {
				t.Fatal("unexpected snapshot")
			}
			saved = true
			return "backup.json", nil
		},
		remove: func(snapshot HTTPSProxySnapshot) error {
			if current != original.Settings {
				t.Fatal("backup removed before restoration")
			}
			removed = true
			return nil
		},
		run: func(args ...string) error {
			if !saved {
				t.Fatal("system modified before backup")
			}

			switch args[0] {
			case "-setsecurewebproxy":
				if args[2] == "127.0.0.1" {
					current = managedHTTPSSettings()
				} else {
					current = HTTPSSettings{
						Enabled: true,
						Server:  original.Settings.Server,
						Port:    original.Settings.Port,
					}
				}

			case "-setsecurewebproxystate":
				if args[2] != "off" {
					t.Fatalf("unexpected state: %v", args)
				}
				current.Enabled = false

			default:
				t.Fatalf("unexpected command: %v", args)
			}
			return nil
		},
	}

	session, err := startSession(deps)
	if err != nil {
		t.Fatalf("startSession(): %v", err)
	}

	if !session.activated {
		t.Fatal("expected proxy activation")
	}

	if err := session.Stop(); err != nil {
		t.Fatalf("Stop(): %v", err)
	}

	if !removed || current != original.Settings {
		t.Fatal("original settings were not fully restored")
	}

	// Repeated Stop must not modify the system again.
	if err := session.Stop(); err != nil {
		t.Fatalf("second Stop(): %v", err)
	}
}

func TestSessionRejectsPendingRecovery(t *testing.T) {
	expected := errors.New("previous backup exists")

	deps := sessionDependencies{
		check: func() error {
			return expected
		},
		capture: func() (HTTPSProxySnapshot, error) {
			t.Fatal("must not capture before recovery")
			return HTTPSProxySnapshot{}, nil
		},
	}

	session, err := startSession(deps)

	if session != nil {
		t.Fatal("session must not start")
	}

	if !errors.Is(err, expected) {
		t.Fatalf("expected recovery error, got %v", err)
	}
}

func TestSessionAlreadyManaged(t *testing.T) {
	original := HTTPSProxySnapshot{
		Service:  "Wi-Fi",
		Settings: managedHTTPSSettings(),
	}

	deps := sessionDependencies{
		check: func() error {
			return nil
		},
		capture: func() (HTTPSProxySnapshot, error) {
			return original, nil
		},
		read: func(string) (HTTPSSettings, error) {
			return original.Settings, nil
		},
		save: func(HTTPSProxySnapshot) (string, error) {
			t.Fatal("must not save an unnecessary backup")
			return "", nil
		},
		remove: func(HTTPSProxySnapshot) error {
			t.Fatal("must not remove a backup")
			return nil
		},
		run: func(args ...string) error {
			t.Fatalf("must not change existing settings: %v", args)
			return nil
		},
	}

	session, err := startSession(deps)
	if err != nil {
		t.Fatalf("startSession(): %v", err)
	}

	if session.activated {
		t.Fatal("expected an unchanged configuration")
	}

	if err := session.Stop(); err != nil {
		t.Fatalf("Stop(): %v", err)
	}
}
