package macosproxy

import (
	"errors"
	"fmt"
)

type snapshotSaver func(HTTPSProxySnapshot) (string, error)

// startProxySession prepares and activates PacketSail's HTTPS proxy.
// It returns true only when the initial settings required a change.
// On activation failure, the recovery backup remains available because networksetup may have partially modified the system configuration.
func startProxySession(
	snapshot HTTPSProxySnapshot,
	read httpsSettingsReader,
	save snapshotSaver,
	run networkSetupRunner,
) (bool, error) {
	if err := validateRestorableSnapshot(snapshot); err != nil {
		return false, fmt.Errorf(
			"invalid initial HTTPS proxy settings: %w",
			err,
		)
	}

	current, err := read(snapshot.Service)
	if err != nil {
		return false, fmt.Errorf(
			"check current HTTPS proxy settings: %w",
			err,
		)
	}

	// The configuration may have changed after the initial capture.
	if current != snapshot.Settings {
		return false, fmt.Errorf(
			"HTTPS proxy settings for %q changed before activation",
			snapshot.Service,
		)
	}

	// Preserve an existing PacketSail-compatible configuration.
	// The lifecycle manager must check for stale recovery backups before calling this function.
	if current == managedHTTPSSettings() {
		return false, nil
	}

	// Persist the original settings before attempting any modification.
	if _, err := save(snapshot); err != nil {
		return false, fmt.Errorf(
			"save HTTPS proxy recovery backup: %w",
			err,
		)
	}

	if err := setManagedHTTPSProxy(snapshot.Service, run); err != nil {
		return false, fmt.Errorf(
			"enable HTTPS proxy; recovery backup was preserved: %w",
			err,
		)
	}

	applied, err := read(snapshot.Service)
	if err != nil {
		return false, fmt.Errorf(
			"verify HTTPS proxy activation; recovery backup was preserved: %w",
			err,
		)
	}

	if applied != managedHTTPSSettings() {
		return false, fmt.Errorf(
			"HTTPS proxy activation verification failed for %q; recovery backup was preserved",
			snapshot.Service,
		)
	}

	return true, nil
}

type snapshotRemover func(HTTPSProxySnapshot) error

// startProxySessionWithRollback activates the HTTPS proxy and attempts safe recovery if activation fails after the backup was saved.
// The backup is removed only after the original settings are verified.
func startProxySessionWithRollback(
	snapshot HTTPSProxySnapshot,
	read httpsSettingsReader,
	save snapshotSaver,
	remove snapshotRemover,
	run networkSetupRunner,
) (bool, error) {
	backupSaved := false

	// Track whether a recovery backup was successfully persisted.
	trackedSave := func(value HTTPSProxySnapshot) (string, error) {
		path, err := save(value)
		if err != nil {
			return "", err
		}

		backupSaved = true
		return path, nil
	}

	activated, err := startProxySession(
		snapshot,
		read,
		trackedSave,
		run,
	)
	if err == nil {
		return activated, nil
	}

	// Validation and backup failures cannot require rollback because activation has not yet attempted to modify the system settings.
	if !backupSaved {
		return false, err
	}

	// Restore only if the current settings are either the original configuration or PacketSail's known managed configuration.
	if restoreErr := restoreHTTPSProxyIfSafe(
		snapshot,
		read,
		run,
	); restoreErr != nil {
		return false, errors.Join(
			err,
			fmt.Errorf(
				"automatic HTTPS proxy rollback failed; recovery backup preserved: %w",
				restoreErr,
			),
		)
	}

	// Verify the original configuration again before removing the backup.
	// A successful rollback result alone is not sufficient for cleanup.
	current, verifyErr := read(snapshot.Service)
	if verifyErr != nil {
		return false, errors.Join(
			err,
			fmt.Errorf("verify HTTPS proxy rollback; recovery backup preserved: %w", verifyErr),
		)
	}

	if current != snapshot.Settings {
		return false, errors.Join(
			err,
			fmt.Errorf("HTTPS proxy settings differ after rollback; recovery backup preserved"),
		)
	}

	// The original configuration is safe again. Only now may the persistent backup be removed.
	if removeErr := remove(snapshot); removeErr != nil {
		return false, errors.Join(
			err,
			fmt.Errorf(
				"HTTPS proxy restored but recovery backup cleanup failed: %w",
				removeErr,
			),
		)
	}

	// Startup still failed, even though rollback succeeded.
	return false, err
}

// stopProxySession restores the original HTTPS proxy configuration when PacketSail changed it during startup.
// The recovery backup is removed only after restoration is verified.
func stopProxySession(
	snapshot HTTPSProxySnapshot,
	activated bool,
	read httpsSettingsReader,
	remove snapshotRemover,
	run networkSetupRunner,
) error {
	// PacketSail must leave pre-existing proxy settings untouched.
	if !activated {
		return nil
	}

	if err := restoreHTTPSProxyIfSafe(snapshot, read, run); err != nil {
		return fmt.Errorf(
			"restore original HTTPS proxy settings; recovery backup preserved: %w",
			err,
		)
	}

	// Verify the original settings immediately before backup cleanup, including when restoration found them already unchanged.
	current, err := read(snapshot.Service)
	if err != nil {
		return fmt.Errorf(
			"verify restored HTTPS proxy settings; recovery backup preserved: %w",
			err,
		)
	}

	if current != snapshot.Settings {
		return fmt.Errorf(
			"HTTPS proxy settings changed before backup cleanup; recovery backup preserved",
		)
	}

	if err := remove(snapshot); err != nil {
		return fmt.Errorf(
			"remove verified HTTPS proxy recovery backup: %w",
			err,
		)
	}

	return nil
}
