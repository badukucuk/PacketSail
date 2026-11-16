package macosproxy

import (
	"fmt"
	"os"
	"path/filepath"
)

// Session represents one HTTPS proxy management session.
type Session struct {
	snapshot  HTTPSProxySnapshot
	activated bool
	stopped   bool

	read   httpsSettingsReader
	remove snapshotRemover
	run    networkSetupRunner
}

// sessionDependencies keeps system operations replaceable in tests.
type sessionDependencies struct {
	check   func() error
	capture func() (HTTPSProxySnapshot, error)
	read    httpsSettingsReader
	save    snapshotSaver
	remove  snapshotRemover
	run     networkSetupRunner
}

// Start prepares macOS HTTPS proxy management.
// The caller must hold PacketSail's application-wide instance lock and ensure the HTTP CONNECT listener is ready before calling Start.
func Start() (*Session, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf(
			"find user configuration directory: %w",
			err,
		)
	}

	dir := filepath.Join(configDir, "packetsail")

	deps := sessionDependencies{
		check: func() error {
			return checkPendingRecoveryInDir(dir)
		},
		capture: CaptureHTTPSProxy,
		read:    ReadHTTPSSettings,
		save: func(snapshot HTTPSProxySnapshot) (string, error) {
			return saveSnapshotToDir(dir, snapshot)
		},
		remove: func(snapshot HTTPSProxySnapshot) error {
			return removeSnapshotFromDir(dir, snapshot)
		},
		run: runNetworkSetup,
	}

	return startSession(deps)
}

// startSession coordinates activation without depending directly on macOS commands, making the complete flow testable.
func startSession(deps sessionDependencies) (*Session, error) {
	// Never overwrite an unresolved backup from an earlier run.
	if err := deps.check(); err != nil {
		return nil, fmt.Errorf(
			"check previous HTTPS proxy recovery: %w",
			err,
		)
	}

	snapshot, err := deps.capture()
	if err != nil {
		return nil, fmt.Errorf(
			"capture original HTTPS proxy settings: %w",
			err,
		)
	}

	activated, err := startProxySessionWithRollback(
		snapshot,
		deps.read,
		deps.save,
		deps.remove,
		deps.run,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"start HTTPS proxy session: %w",
			err,
		)
	}

	return &Session{
		snapshot:  snapshot,
		activated: activated,
		read:      deps.read,
		remove:    deps.remove,
		run:       deps.run,
	}, nil
}

// Stop restores the original settings when this session changed them.
// A failed Stop can be retried; a successful Stop is idempotent.
func (session *Session) Stop() error {
	if session == nil || session.stopped {
		return nil
	}

	if err := stopProxySession(
		session.snapshot,
		session.activated,
		session.read,
		session.remove,
		session.run,
	); err != nil {
		return fmt.Errorf("stop HTTPS proxy session: %w", err)
	}

	session.stopped = true
	return nil
}
