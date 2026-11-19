package macosproxy

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestSetManagedHTTPSProxy(t *testing.T) {
	var received []string

	run := func(args ...string) error {
		received = append([]string(nil), args...)
		return nil
	}

	err := setManagedHTTPSProxy("Wi-Fi", run)
	if err != nil {
		t.Fatalf("setManagedHTTPSProxy() error = %v", err)
	}

	want := []string{
		"-setsecurewebproxy",
		"Wi-Fi",
		"127.0.0.1",
		"9877",
	}

	if !reflect.DeepEqual(received, want) {
		t.Errorf("arguments = %q, want %q", received, want)
	}
}

func TestSetManagedHTTPSProxySupportsServiceNamesWithSpaces(t *testing.T) {
	run := func(args ...string) error {
		if args[1] != "USB 10/100/1000 LAN" {
			t.Errorf("incorrect network service: %q", args[1])
		}
		return nil
	}

	if err := setManagedHTTPSProxy("USB 10/100/1000 LAN", run); err != nil {
		t.Fatal(err)
	}
}

func TestSetManagedHTTPSProxyRejectsInvalidService(t *testing.T) {
	tests := []string{
		"",
		"   ",
		"-setsecurewebproxystate",
	}

	for _, service := range tests {
		t.Run(service, func(t *testing.T) {
			called := false

			run := func(args ...string) error {
				called = true
				return nil
			}

			if err := setManagedHTTPSProxy(service, run); err == nil {
				t.Fatal("expected an error")
			}

			if called {
				t.Fatal("networksetup must not run for invalid services")
			}
		})
	}
}

func TestSetManagedHTTPSProxyPropagatesFailure(t *testing.T) {
	expected := errors.New("permission denied")

	run := func(args ...string) error {
		return expected
	}

	err := setManagedHTTPSProxy("Wi-Fi", run)

	if !errors.Is(err, expected) {
		t.Fatalf("expected wrapped permission error, got %v", err)
	}

	if !strings.Contains(err.Error(), "Wi-Fi") {
		t.Fatalf("error does not identify network service: %v", err)
	}
}

func TestRestoreHTTPSProxySettings(t *testing.T) {
	tests := []struct {
		name     string
		settings HTTPSSettings
		want     [][]string
	}{
		{
			name: "restore enabled proxy",
			settings: HTTPSSettings{
				Enabled: true,
				Server:  "proxy.example.com",
				Port:    8080,
			},
			want: [][]string{
				{
					"-setsecurewebproxy",
					"Wi-Fi",
					"proxy.example.com",
					"8080",
				},
			},
		},
		{
			name: "restore disabled proxy with saved address",
			settings: HTTPSSettings{
				Enabled: false,
				Server:  "127.0.0.1",
				Port:    9877,
			},
			want: [][]string{
				{
					"-setsecurewebproxy",
					"Wi-Fi",
					"127.0.0.1",
					"9877",
				},
				{
					"-setsecurewebproxystate",
					"Wi-Fi",
					"off",
				},
			},
		},
		{
			name: "restore disabled empty proxy",
			settings: HTTPSSettings{
				Enabled: false,
				Server:  "",
				Port:    0,
			},
			want: [][]string{
				{
					"-setsecurewebproxy",
					"Wi-Fi",
					"",
					"0",
				},
				{
					"-setsecurewebproxystate",
					"Wi-Fi",
					"off",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var commands [][]string

			run := func(args ...string) error {
				commands = append(
					commands,
					append([]string(nil), args...),
				)
				return nil
			}

			snapshot := HTTPSProxySnapshot{
				Service:  "Wi-Fi",
				Settings: tt.settings,
			}

			if err := restoreHTTPSProxySettings(snapshot, run); err != nil {
				t.Fatalf("restoreHTTPSProxySettings() error = %v", err)
			}

			if !reflect.DeepEqual(commands, tt.want) {
				t.Errorf("commands = %q, want %q", commands, tt.want)
			}
		})
	}
}

func TestRestoreHTTPSProxySettingsRejectsUnsupportedSettings(t *testing.T) {
	tests := []struct {
		name     string
		snapshot HTTPSProxySnapshot
	}{
		{
			name: "empty service",
			snapshot: HTTPSProxySnapshot{
				Settings: HTTPSSettings{
					Server: "127.0.0.1",
					Port:   9877,
				},
			},
		},
		{
			name: "authenticated proxy",
			snapshot: HTTPSProxySnapshot{
				Service: "Wi-Fi",
				Settings: HTTPSSettings{
					Server:        "proxy.example.com",
					Port:          8080,
					Authenticated: true,
				},
			},
		},
		{
			name: "invalid saved port",
			snapshot: HTTPSProxySnapshot{
				Service: "Wi-Fi",
				Settings: HTTPSSettings{
					Server: "proxy.example.com",
					Port:   70000,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false

			run := func(args ...string) error {
				called = true
				return nil
			}

			if err := restoreHTTPSProxySettings(tt.snapshot, run); err == nil {
				t.Fatal("expected restoration to be rejected")
			}

			if called {
				t.Fatal("networksetup was called for unsupported settings")
			}
		})
	}
}

func TestRestoreHTTPSProxySettingsStopsOnFailure(t *testing.T) {
	expected := errors.New("permission denied")
	calls := 0

	run := func(args ...string) error {
		calls++

		if calls == 2 {
			return expected
		}

		return nil
	}

	snapshot := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Server: "127.0.0.1",
			Port:   9877,
		},
	}

	err := restoreHTTPSProxySettings(snapshot, run)

	if !errors.Is(err, expected) {
		t.Fatalf("expected wrapped error, got %v", err)
	}

	if calls != 2 {
		t.Errorf("command calls = %d, want 2", calls)
	}
}
