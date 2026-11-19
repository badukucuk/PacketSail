package macosproxy

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type networkSetupRunner func(args ...string) error

// runNetworkSetup executes a macOS network configuration command.
// Arguments are passed directly without invoking a shell.
func runNetworkSetup(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	output, err := exec.CommandContext(
		ctx,
		"/usr/sbin/networksetup",
		args...,
	).CombinedOutput()

	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("networksetup timed out: %w", ctx.Err())
		}

		return fmt.Errorf(
			"networksetup failed: %w: %s",
			err,
			strings.TrimSpace(string(output)),
		)
	}

	return nil
}

// setManagedHTTPSProxy configures PacketSail's HTTPS proxy.
// The caller must save and validate the original configuration first.
func setManagedHTTPSProxy(
	service string,
	run networkSetupRunner,
) error {
	if strings.TrimSpace(service) == "" {
		return fmt.Errorf("network service name cannot be empty")
	}

	// The leading dash would make the service name ambiguous
	// with a networksetup command-line option.
	if strings.HasPrefix(service, "-") {
		return fmt.Errorf("invalid network service name: %q", service)
	}

	settings := managedHTTPSSettings()

	err := run(
		"-setsecurewebproxy",
		service,
		settings.Server,
		fmt.Sprint(settings.Port),
	)
	if err != nil {
		return fmt.Errorf(
			"configure PacketSail HTTPS proxy for %q: %w",
			service,
			err,
		)
	}

	return nil
}

// restoreHTTPSProxySettings restores a previously saved HTTPS proxy configuration.
// The caller must verify that restoration is safe.
func restoreHTTPSProxySettings(snapshot HTTPSProxySnapshot, run networkSetupRunner) error {
	if err := validateRestorableSnapshot(snapshot); err != nil {
		return fmt.Errorf("cannot restore HTTPS proxy: %w", err)
	}

	settings := snapshot.Settings
	service := snapshot.Service

	// Setting the server also enables the HTTPS proxy.
	// Restore the original server and port before restoring its state.
	if err := run(
		"-setsecurewebproxy",
		service,
		settings.Server,
		fmt.Sprint(settings.Port),
	); err != nil {
		return fmt.Errorf(
			"restore HTTPS proxy server for %q: %w",
			service,
			err,
		)
	}

	if !settings.Enabled {
		if err := run(
			"-setsecurewebproxystate",
			service,
			"off",
		); err != nil {
			return fmt.Errorf(
				"disable restored HTTPS proxy for %q: %w",
				service,
				err,
			)
		}
	}

	return nil
}
