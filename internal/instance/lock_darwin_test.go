package instance

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAcquireInDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "packetsail")

	first, err := acquireInDir(dir)
	if err != nil {
		t.Fatalf("acquire first lock: %v", err)
	}
	defer first.Close()

	// A second instance must not acquire the same lock.
	second, err := acquireInDir(dir)
	if err == nil {
		second.Close()
		t.Fatal("expected second lock acquisition to fail")
	}

	if !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatalf("expected lock contention error, got %v", err)
	}

	// Releasing the first lock allows another instance to start.
	if err := first.Close(); err != nil {
		t.Fatalf("release first lock: %v", err)
	}

	third, err := acquireInDir(dir)
	if err != nil {
		t.Fatalf("acquire lock after release: %v", err)
	}
	defer third.Close()

	// The lock file stays in place.
	path := filepath.Join(dir, lockFileName)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("lock file should remain: %v", err)
	}
}

func TestAcquireInDirRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	path := filepath.Join(dir, lockFileName)

	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	lock, err := acquireInDir(dir)
	if err == nil {
		lock.Close()
		t.Fatal("expected symlink to be rejected")
	}
}

func TestAcquireInDirRejectsUnsafePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, lockFileName)

	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}

	lock, err := acquireInDir(dir)
	if err == nil {
		lock.Close()
		t.Fatal("expected unsafe permissions to be rejected")
	}
}

func TestAcquireInDirRejectsUnsafeDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "packetsail")

	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}

	lock, err := acquireInDir(dir)
	if err == nil {
		lock.Close()
		t.Fatal("expected unsafe directory to be rejected")
	}
}

func TestLockCloseIsIdempotent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "packetsail")

	lock, err := acquireInDir(dir)
	if err != nil {
		t.Fatalf("acquire lock: %v", err)
	}

	if err := lock.Close(); err != nil {
		t.Fatalf("first Close() failed: %v", err)
	}

	if err := lock.Close(); err != nil {
		t.Fatalf("second Close() failed: %v", err)
	}
}
