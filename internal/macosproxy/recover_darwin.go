package macosproxy

import (
	"fmt"
	"os"
	"path/filepath"
)

// Recover restores HTTPS proxy settings from a previous PacketSail session.
// The caller must hold the application-wide instance lock.
func Recover() error {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("find user configuration directory: %w", err)
	}

	return recoverFromDir(
		filepath.Join(configDir, "packetsail"),
		ReadHTTPSSettings,
		runNetworkSetup,
	)
}

// recoverFromDir allows recovery to be tested without changing the actual macOS system proxy configuration.
func recoverFromDir(
	dir string,
	read httpsSettingsReader,
	run networkSetupRunner,
) error {
	snapshot, err := loadSnapshotFromDir(dir)
	if err != nil {
		return fmt.Errorf("load HTTPS proxy recovery backup: %w", err)
	}

	// Restore only if the current configuration is either the original one or PacketSail's known managed configuration.
	if err := restoreHTTPSProxyIfSafe(snapshot, read, run); err != nil {
		return fmt.Errorf(
			"restore HTTPS proxy; recovery backup preserved: %w",
			err,
		)
	}

	// Confirm the original settings before deleting recovery data.
	current, err := read(snapshot.Service)
	if err != nil {
		return fmt.Errorf(
			"verify recovered HTTPS proxy; backup preserved: %w",
			err,
		)
	}

	if current != snapshot.Settings {
		return fmt.Errorf(
			"recovered HTTPS proxy settings differ from the backup; backup preserved",
		)
	}

	if err := removeSnapshotFromDir(dir, snapshot); err != nil {
		return fmt.Errorf("remove recovered HTTPS proxy backup: %w", err)
	}

	return nil
}
