package macosproxy

import "fmt"

// RecoveryState describes how the current HTTPS proxy settings compare with the saved configuration.
type RecoveryState string

const (
	RecoveryOriginal RecoveryState = "original"
	RecoveryManaged  RecoveryState = "managed"
	RecoveryConflict RecoveryState = "conflict"
)

// managedHTTPSSettings returns the configuration PacketSail intends to apply when its local HTTP CONNECT proxy is running.
func managedHTTPSSettings() HTTPSSettings {
	return HTTPSSettings{
		Enabled: true,
		Server:  "127.0.0.1",
		Port:    9877,
	}
}

// classifyHTTPSProxyState determines whether restoring the saved configuration would overwrite an unexpected user change.
func classifyHTTPSProxyState(
	original HTTPSSettings,
	current HTTPSSettings,
) RecoveryState {
	// If the original settings are already present, no restoration is needed, even if they happen to match PacketSail's settings.
	if current == original {
		return RecoveryOriginal
	}

	if current == managedHTTPSSettings() {
		return RecoveryManaged
	}

	return RecoveryConflict
}

// InspectHTTPSProxyRecovery checks a saved recovery backup against the live macOS configuration without changing system settings.
func InspectHTTPSProxyRecovery() (HTTPSProxySnapshot, RecoveryState, error) {
	snapshot, err := LoadHTTPSProxySnapshot()
	if err != nil {
		return HTTPSProxySnapshot{}, "", fmt.Errorf(
			"load HTTPS proxy recovery backup: %w",
			err,
		)
	}

	current, err := ReadHTTPSSettings(snapshot.Service)
	if err != nil {
		return HTTPSProxySnapshot{}, "", fmt.Errorf(
			"read current HTTPS proxy settings for %q: %w",
			snapshot.Service,
			err,
		)
	}

	state := classifyHTTPSProxyState(snapshot.Settings, current)

	return snapshot, state, nil
}

type httpsSettingsReader func(service string) (HTTPSSettings, error)

// restoreHTTPSProxyIfSafe restores the original settings only when the current configuration is still managed by PacketSail.
func restoreHTTPSProxyIfSafe(
	snapshot HTTPSProxySnapshot,
	read httpsSettingsReader,
	run networkSetupRunner,
) error {
	if err := validateRestorableSnapshot(snapshot); err != nil {
		return fmt.Errorf("invalid HTTPS proxy snapshot: %w", err)
	}

	current, err := read(snapshot.Service)
	if err != nil {
		return fmt.Errorf(
			"read current HTTPS proxy settings for %q: %w",
			snapshot.Service,
			err,
		)
	}

	switch classifyHTTPSProxyState(snapshot.Settings, current) {
	case RecoveryOriginal:
		// The original configuration is already present.
		return nil

	case RecoveryConflict:
		// Do not overwrite changes made outside PacketSail.
		return fmt.Errorf(
			"HTTPS proxy settings for %q have changed; automatic restoration refused",
			snapshot.Service,
		)

	case RecoveryManaged:
		if err := restoreHTTPSProxySettings(snapshot, run); err != nil {
			return fmt.Errorf("restore HTTPS proxy settings: %w", err)
		}

	default:
		return fmt.Errorf("unknown HTTPS proxy recovery state")
	}

	// A successful command does not necessarily mean the system applied the requested configuration.
	// Verify the final state.
	restored, err := read(snapshot.Service)
	if err != nil {
		return fmt.Errorf(
			"verify restored HTTPS proxy settings: %w",
			err,
		)
	}

	if restored != snapshot.Settings {
		return fmt.Errorf(
			"HTTPS proxy restoration verification failed for %q",
			snapshot.Service,
		)
	}

	return nil
}
