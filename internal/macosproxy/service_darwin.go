package macosproxy

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var serviceLinePattern = regexp.MustCompile(`^\(\d+\)\s+(.+)$`)

// DetectNetworkService finds the network service associated with the current default IPv4 route.
func DetectNetworkService() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	routeOutput, err := exec.CommandContext(
		ctx,
		"/sbin/route",
		"-n",
		"get",
		"default",
	).Output()
	if err != nil {
		return "", fmt.Errorf("get default IPv4 route: %w", err)
	}

	networkInterface, err := parseDefaultInterface(string(routeOutput))
	if err != nil {
		return "", fmt.Errorf("parse default IPv4 route: %w", err)
	}

	serviceOutput, err := exec.CommandContext(
		ctx,
		"/usr/sbin/networksetup",
		"-listnetworkserviceorder",
	).Output()
	if err != nil {
		return "", fmt.Errorf("list network services: %w", err)
	}

	service, err := findNetworkService(
		string(serviceOutput),
		networkInterface,
	)
	if err != nil {
		return "", fmt.Errorf(
			"find network service for %q: %w",
			networkInterface,
			err,
		)
	}

	return service, nil
}

// parseDefaultInterface extracts the interface from the routing output.
func parseDefaultInterface(output string) (string, error) {
	var networkInterface string

	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)

		if len(fields) == 0 || fields[0] != "interface:" {
			continue
		}

		if len(fields) != 2 || networkInterface != "" {
			return "", fmt.Errorf("invalid default route interface")
		}

		networkInterface = fields[1]
	}

	if networkInterface == "" {
		return "", fmt.Errorf("default route interface not found")
	}

	return networkInterface, nil
}

// findNetworkService matches an interface to an enabled network service.
func findNetworkService(output, networkInterface string) (string, error) {
	lines := strings.Split(output, "\n")
	var matchedService string

	for index, line := range lines {
		matches := serviceLinePattern.FindStringSubmatch(strings.TrimSpace(line))
		if matches == nil {
			continue
		}

		service := matches[1]

		// Disabled services must not be selected for system changes.
		if strings.HasPrefix(service, "*") {
			continue
		}

		if index+1 >= len(lines) {
			return "", fmt.Errorf("missing hardware information for %q", service)
		}

		hardwareLine := strings.TrimSpace(lines[index+1])
		const deviceMarker = ", Device: "

		position := strings.LastIndex(hardwareLine, deviceMarker)
		if !strings.HasPrefix(hardwareLine, "(Hardware Port: ") ||
			position == -1 ||
			!strings.HasSuffix(hardwareLine, ")") {
			return "", fmt.Errorf("invalid hardware information for %q", service)
		}

		device := strings.TrimSuffix(
			hardwareLine[position+len(deviceMarker):],
			")",
		)

		if device != networkInterface {
			continue
		}

		if matchedService != "" {
			return "", fmt.Errorf(
				"multiple services use interface %q",
				networkInterface,
			)
		}

		matchedService = service
	}

	if matchedService == "" {
		return "", fmt.Errorf(
			"no enabled network service uses interface %q",
			networkInterface,
		)
	}

	return matchedService, nil
}
