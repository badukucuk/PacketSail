package macosproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const backupFileName = "https-proxy-backup.json"

type backupRecord struct {
	Version  int            `json:"version"`
	Service  string         `json:"service"`
	Settings backupSettings `json:"settings"`
}

type backupSettings struct {
	Enabled       bool   `json:"enabled"`
	Server        string `json:"server"`
	Port          int    `json:"port"`
	Authenticated bool   `json:"authenticated"`
}

// SaveHTTPSProxySnapshot persists the original proxy configuration.
// An existing backup is never overwritten because it may be needed to recover from a previous unexpected termination.
func SaveHTTPSProxySnapshot(snapshot HTTPSProxySnapshot) (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find user configuration directory: %w", err)
	}

	return saveSnapshotToDir(
		filepath.Join(configDir, "packetsail"),
		snapshot,
	)
}

func saveSnapshotToDir(dir string, snapshot HTTPSProxySnapshot) (string, error) {
	if err := validateRestorableSnapshot(snapshot); err != nil {
		return "", fmt.Errorf("invalid HTTPS proxy backup: %w", err)
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create proxy backup directory: %w", err)
	}

	settings := snapshot.Settings

	record := backupRecord{
		Version: 1,
		Service: snapshot.Service,
		Settings: backupSettings{
			Enabled:       settings.Enabled,
			Server:        settings.Server,
			Port:          settings.Port,
			Authenticated: settings.Authenticated,
		},
	}

	// Write to a temporary file first so an incomplete JSON document never becomes the official recovery backup.
	file, err := os.CreateTemp(dir, ".https-proxy-backup-*")
	if err != nil {
		return "", fmt.Errorf("create temporary proxy backup: %w", err)
	}
	defer os.Remove(file.Name())

	if err := file.Chmod(0600); err != nil {
		file.Close()
		return "", fmt.Errorf("restrict proxy backup permissions: %w", err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(record); err != nil {
		file.Close()
		return "", fmt.Errorf("encode proxy backup: %w", err)
	}

	if err := file.Sync(); err != nil {
		file.Close()
		return "", fmt.Errorf("sync proxy backup: %w", err)
	}

	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close proxy backup: %w", err)
	}

	path := filepath.Join(dir, backupFileName)

	// A hard link publishes the completed file atomically and fails if a previous backup already exists.
	if err := os.Link(file.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf(
				"proxy recovery backup already exists at %q",
				path,
			)
		}

		return "", fmt.Errorf("publish proxy backup: %w", err)
	}

	return path, nil
}

// LoadHTTPSProxySnapshot reads the saved recovery backup without modifying the current macOS proxy configuration.
func LoadHTTPSProxySnapshot() (HTTPSProxySnapshot, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return HTTPSProxySnapshot{}, fmt.Errorf(
			"find user configuration directory: %w",
			err,
		)
	}

	return loadSnapshotFromDir(filepath.Join(configDir, "packetsail"))
}

func loadSnapshotFromDir(dir string) (HTTPSProxySnapshot, error) {
	path := filepath.Join(dir, backupFileName)

	data, err := readBackupFile(path)
	if err != nil {
		return HTTPSProxySnapshot{}, err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var record backupRecord

	if err := decoder.Decode(&record); err != nil {
		return HTTPSProxySnapshot{}, fmt.Errorf(
			"decode proxy recovery backup: %w",
			err,
		)
	}

	// The backup must contain exactly one JSON document.
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return HTTPSProxySnapshot{}, fmt.Errorf(
			"proxy recovery backup contains additional data",
		)
	}

	if record.Version != 1 {
		return HTTPSProxySnapshot{}, fmt.Errorf(
			"unsupported proxy backup version: %d",
			record.Version,
		)
	}

	settings := HTTPSSettings{
		Enabled:       record.Settings.Enabled,
		Server:        record.Settings.Server,
		Port:          record.Settings.Port,
		Authenticated: record.Settings.Authenticated,
	}

	snapshot := HTTPSProxySnapshot{
		Service:  record.Service,
		Settings: settings,
	}

	if err := validateRestorableSnapshot(snapshot); err != nil {
		return HTTPSProxySnapshot{}, fmt.Errorf(
			"invalid saved HTTPS proxy configuration: %w",
			err,
		)
	}

	return snapshot, nil
}

// removeSnapshotFromDir removes a recovery backup only when its contents match the snapshot expected by the caller.
// The caller must first verify that restoration has completed.
func removeSnapshotFromDir(dir string, expected HTTPSProxySnapshot) error {
	if err := validateRestorableSnapshot(expected); err != nil {
		return fmt.Errorf("invalid expected HTTPS proxy snapshot: %w", err)
	}

	saved, err := loadSnapshotFromDir(dir)
	if err != nil {
		return fmt.Errorf("load proxy backup before removal: %w", err)
	}

	// Do not remove a backup belonging to a different configuration.
	if saved != expected {
		return fmt.Errorf(
			"proxy recovery backup does not match the expected snapshot",
		)
	}

	path := filepath.Join(dir, backupFileName)

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove proxy recovery backup: %w", err)
	}

	return nil
}

// CheckPendingRecovery reports whether a previous proxy backup must be handled before starting another managed session.
func CheckPendingRecovery() error {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("find user configuration directory: %w", err)
	}

	return checkPendingRecoveryInDir(
		filepath.Join(configDir, "packetsail"),
	)
}

// checkPendingRecoveryInDir is separated so tests never inspect or modify the user's actual recovery files.
func checkPendingRecoveryInDir(dir string) error {
	path := filepath.Join(dir, backupFileName)

	_, err := os.Lstat(path)

	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("inspect proxy recovery backup: %w", err)
	}

	// Even a damaged backup must not be silently overwritten.
	return fmt.Errorf(
		"a previous HTTPS proxy recovery backup exists at %q; recovery is required before starting a new session",
		path,
	)
}

// readBackupFile opens the recovery backup without following symbolic links and validates the opened file before reading it.
func readBackupFile(path string) ([]byte, error) {
	fd, err := syscall.Open(
		path,
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open recovery backup: %w", err)
	}

	file := os.NewFile(uintptr(fd), path)
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect recovery backup: %w", err)
	}

	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, fmt.Errorf(
			"recovery backup must be a regular file with permissions 0600",
		)
	}

	const maxBackupSize = 64 * 1024

	// A backup contains only a small JSON record.
	// Reject unexpected large files before attempting to decode their contents.
	if info.Size() > maxBackupSize {
		return nil, fmt.Errorf("recovery backup exceeds maximum size")
	}

	data, err := io.ReadAll(io.LimitReader(file, maxBackupSize+1))
	if err != nil {
		return nil, fmt.Errorf("read recovery backup: %w", err)
	}

	if len(data) > maxBackupSize {
		return nil, fmt.Errorf("recovery backup exceeds maximum size")
	}

	return data, nil
}
