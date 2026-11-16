package instance

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const lockFileName = "packetsail.lock"

// Lock holds the exclusive lock for a running PacketSail instance.
type Lock struct {
	file *os.File
}

// Acquire prevents another PacketSail instance from starting under the same macOS user account.
func Acquire() (*Lock, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("find user configuration directory: %w", err)
	}

	return acquireInDir(filepath.Join(configDir, "packetsail"))
}

// acquireInDir allows the locking behavior to be tested without creating files in the user's actual configuration directory.
func acquireInDir(dir string) (*Lock, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create PacketSail state directory: %w", err)
	}

	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("inspect PacketSail state directory: %w", err)
	}

	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, fmt.Errorf(
			"PacketSail state directory must have permissions 0700",
		)
	}

	path := filepath.Join(dir, lockFileName)

	// Avoid following symlinks and prevent child processes from inheriting the lock file descriptor.
	fd, err := syscall.Open(
		path,
		syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
		0600,
	)
	if err != nil {
		return nil, fmt.Errorf("open PacketSail lock file: %w", err)
	}

	file := os.NewFile(uintptr(fd), path)

	fileInfo, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("inspect PacketSail lock file: %w", err)
	}

	if !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm() != 0600 {
		file.Close()
		return nil, fmt.Errorf(
			"PacketSail lock file must have permissions 0600",
		)
	}

	// LOCK_NB returns immediately if another instance holds the lock.
	if err := syscall.Flock(
		int(file.Fd()),
		syscall.LOCK_EX|syscall.LOCK_NB,
	); err != nil {
		file.Close()

		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf(
				"another PacketSail instance is already running: %w",
				err,
			)
		}

		return nil, fmt.Errorf("acquire PacketSail lock: %w", err)
	}

	return &Lock{file: file}, nil
}

// Close releases the lock by closing its file descriptor.
// The lock file remains on disk so future instances use the same file.
func (lock *Lock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}

	err := lock.file.Close()
	lock.file = nil

	if err != nil {
		return fmt.Errorf("release PacketSail lock: %w", err)
	}

	return nil
}
