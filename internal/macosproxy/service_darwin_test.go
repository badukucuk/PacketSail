package macosproxy

import (
	"strings"
	"testing"
)

const sampleRouteOutput = `   route to: default
destination: default
    gateway: 192.168.3.1
  interface: en0
     flags: <UP,GATEWAY,DONE>
`

const sampleServiceOutput = `An asterisk (*) denotes that a network service is disabled.
(1) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

(2) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(3) iPhone USB
(Hardware Port: iPhone USB, Device: en5)
`

func TestParseDefaultInterface(t *testing.T) {
	got, err := parseDefaultInterface(sampleRouteOutput)
	if err != nil {
		t.Fatalf("parseDefaultInterface() error = %v", err)
	}

	if got != "en0" {
		t.Errorf("interface = %q, want %q", got, "en0")
	}
}

func TestParseDefaultInterfaceRejectsMissingInterface(t *testing.T) {
	_, err := parseDefaultInterface("route to: default\n")

	if err == nil {
		t.Fatal("expected an error for missing interface")
	}
}

func TestFindNetworkService(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		device  string
		want    string
		wantErr bool
	}{
		{
			name:   "Wi-Fi",
			output: sampleServiceOutput,
			device: "en0",
			want:   "Wi-Fi",
		},
		{
			name:   "iPhone USB",
			output: sampleServiceOutput,
			device: "en5",
			want:   "iPhone USB",
		},
		{
			name:    "unknown interface",
			output:  sampleServiceOutput,
			device:  "utun0",
			wantErr: true,
		},
		{
			name:    "missing hardware information",
			output:  "(1) Wi-Fi\n",
			device:  "en0",
			wantErr: true,
		},
		{
			name: "multiple matching services",
			output: sampleServiceOutput +
				"(4) Another Wi-Fi\n" +
				"(Hardware Port: Wi-Fi, Device: en0)\n",
			device:  "en0",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := findNetworkService(tt.output, tt.device)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("findNetworkService() error = %v", err)
			}

			if got != tt.want {
				t.Errorf("service = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindNetworkServiceSkipsDisabledService(t *testing.T) {
	output := strings.Replace(
		sampleServiceOutput,
		"(2) Wi-Fi",
		"(2) *Wi-Fi",
		1,
	)

	_, err := findNetworkService(output, "en0")
	if err == nil {
		t.Fatal("expected an error for disabled network service")
	}
}

// Reads system information without changing network settings.
func TestDetectNetworkService(t *testing.T) {
	service, err := DetectNetworkService()
	if err != nil {
		t.Fatalf("DetectNetworkService() error = %v", err)
	}

	t.Logf("detected network service: %q", service)
}
