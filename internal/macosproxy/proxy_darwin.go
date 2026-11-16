package macosproxy

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// HTTPSSettings represents the HTTPS proxy configuration of a network service.
type HTTPSSettings struct {
	Enabled       bool
	Server        string
	Port          int
	Authenticated bool
}

// HTTPSProxySnapshot records the network service and its original HTTPS proxy settings so they can be restored together.
type HTTPSProxySnapshot struct {
	Service  string
	Settings HTTPSSettings
}

// validateRestorableSnapshot rejects configurations that cannot currently be restored without losing their original settings.
func validateRestorableSnapshot(snapshot HTTPSProxySnapshot) error {
	service := strings.TrimSpace(snapshot.Service)

	if service == "" {
		return fmt.Errorf("network service cannot be empty")
	}

	if strings.HasPrefix(service, "-") {
		return fmt.Errorf("network service cannot begin with '-'")
	}

	settings := snapshot.Settings

	// Authenticated proxies cannot be safely restored because PacketSail does not preserve proxy credentials.
	if settings.Authenticated {
		return fmt.Errorf(
			"authenticated HTTPS proxy settings cannot be safely restored",
		)
	}

	// A disabled proxy may have no configured server or port.
	if settings.Server == "" && settings.Port == 0 {
		if settings.Enabled {
			return fmt.Errorf(
				"enabled HTTPS proxy requires a server and port",
			)
		}

		return nil
	}

	// Any non-empty configuration requires both a server and a valid port.
	if strings.TrimSpace(settings.Server) == "" {
		return fmt.Errorf("HTTPS proxy server cannot be empty")
	}

	if settings.Port < 1 || settings.Port > 65535 {
		return fmt.Errorf(
			"HTTPS proxy port must be between 1 and 65535",
		)
	}

	return nil
}

// ReadHTTPSSettings reads a service's HTTPS proxy configuration without modifying any system settings.
func ReadHTTPSSettings(service string) (HTTPSSettings, error) {
	if strings.TrimSpace(service) == "" {
		return HTTPSSettings{}, fmt.Errorf("network service name cannot be empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(
		ctx,
		"/usr/sbin/networksetup",
		"-getsecurewebproxy",
		service,
	)

	output, err := cmd.Output()
	if err != nil {
		return HTTPSSettings{}, fmt.Errorf(
			"read HTTPS proxy settings for %q: %w",
			service,
			err,
		)
	}

	settings, err := parseHTTPSSettings(string(output))
	if err != nil {
		return HTTPSSettings{}, fmt.Errorf(
			"parse HTTPS proxy settings for %q: %w",
			service,
			err,
		)
	}

	return settings, nil
}

// CaptureHTTPSProxy reads the current network service and its HTTPS proxy settings without modifying the system configuration.
func CaptureHTTPSProxy() (HTTPSProxySnapshot, error) {
	service, err := DetectNetworkService()
	if err != nil {
		return HTTPSProxySnapshot{}, fmt.Errorf(
			"detect network service: %w",
			err,
		)
	}

	settings, err := ReadHTTPSSettings(service)
	if err != nil {
		return HTTPSProxySnapshot{}, fmt.Errorf(
			"read HTTPS proxy configuration: %w",
			err,
		)
	}

	snapshot := HTTPSProxySnapshot{
		Service:  service,
		Settings: settings,
	}

	if err := validateRestorableSnapshot(snapshot); err != nil {
		return HTTPSProxySnapshot{}, fmt.Errorf(
			"unsupported existing HTTPS proxy configuration: %w",
			err,
		)
	}

	return snapshot, nil
}

// parseHTTPSSettings validates the fields returned by networksetup.
func parseHTTPSSettings(output string) (HTTPSSettings, error) {
	fields := make(map[string]string)

	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}

		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return HTTPSSettings{}, fmt.Errorf(
				"invalid proxy settings line: %q",
				line,
			)
		}

		key = strings.TrimSpace(key)

		if _, exists := fields[key]; exists {
			return HTTPSSettings{}, fmt.Errorf("duplicate field %q", key)
		}

		fields[key] = strings.TrimSpace(value)
	}

	required := []string{
		"Enabled",
		"Server",
		"Port",
		"Authenticated Proxy Enabled",
	}

	for _, key := range required {
		if _, exists := fields[key]; !exists {
			return HTTPSSettings{}, fmt.Errorf("missing field %q", key)
		}
	}

	settings := HTTPSSettings{
		Server: fields["Server"],
	}

	switch fields["Enabled"] {
	case "Yes":
		settings.Enabled = true
	case "No":
		settings.Enabled = false
	default:
		return HTTPSSettings{}, fmt.Errorf("invalid Enabled value")
	}

	port, err := strconv.Atoi(fields["Port"])
	if err != nil || port < 0 || port > 65535 {
		return HTTPSSettings{}, fmt.Errorf("invalid proxy port %q", fields["Port"])
	}
	settings.Port = port

	switch fields["Authenticated Proxy Enabled"] {
	case "1":
		settings.Authenticated = true
	case "0":
		settings.Authenticated = false
	default:
		return HTTPSSettings{}, fmt.Errorf("invalid authentication value")
	}

	if settings.Enabled && (settings.Server == "" || settings.Port == 0) {
		return HTTPSSettings{}, fmt.Errorf(
			"enabled HTTPS proxy requires a server and port",
		)
	}

	return settings, nil
}
