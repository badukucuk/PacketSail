package macosproxy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSaveHTTPSProxySnapshot(t *testing.T) {
	snapshot := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Server: "127.0.0.1",
			Port:   9877,
		},
	}

	dir := filepath.Join(t.TempDir(), "packetsail")

	path, err := saveSnapshotToDir(dir, snapshot)
	if err != nil {
		t.Fatalf("saveSnapshotToDir() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved backup: %v", err)
	}

	var got backupRecord

	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("decode saved backup: %v", err)
	}

	want := backupRecord{
		Version: 1,
		Service: "Wi-Fi",
		Settings: backupSettings{
			Server: "127.0.0.1",
			Port:   9877,
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("saved backup = %+v, want %+v", got, want)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat backup: %v", err)
	}

	if info.Mode().Perm() != 0600 {
		t.Errorf("backup permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestSaveHTTPSProxySnapshotDoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()

	original := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Server: "original.example.com",
			Port:   8080,
		},
	}

	path, err := saveSnapshotToDir(dir, original)
	if err != nil {
		t.Fatalf("save original backup: %v", err)
	}

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	replacement := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Server: "replacement.example.com",
			Port:   9090,
		},
	}

	if _, err := saveSnapshotToDir(dir, replacement); err == nil {
		t.Fatal("expected error when backup already exists")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if string(after) != string(before) {
		t.Fatal("existing proxy backup was modified")
	}
}

func TestSaveHTTPSProxySnapshotRejectsAuthenticatedProxy(t *testing.T) {
	snapshot := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Enabled:       true,
			Server:        "proxy.example.com",
			Port:          8080,
			Authenticated: true,
		},
	}

	_, err := saveSnapshotToDir(t.TempDir(), snapshot)
	if err == nil {
		t.Fatal("expected authenticated proxy to be rejected")
	}
}

func TestSaveHTTPSProxySnapshotRejectsMissingService(t *testing.T) {
	snapshot := HTTPSProxySnapshot{}

	_, err := saveSnapshotToDir(t.TempDir(), snapshot)
	if err == nil {
		t.Fatal("expected missing network service to be rejected")
	}
}

func TestLoadHTTPSProxySnapshot(t *testing.T) {
	dir := t.TempDir()

	want := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Enabled: false,
			Server:  "127.0.0.1",
			Port:    9877,
		},
	}

	if _, err := saveSnapshotToDir(dir, want); err != nil {
		t.Fatalf("saveSnapshotToDir() error = %v", err)
	}

	got, err := loadSnapshotFromDir(dir)
	if err != nil {
		t.Fatalf("loadSnapshotFromDir() error = %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("loaded snapshot = %+v, want %+v", got, want)
	}
}

func TestLoadHTTPSProxySnapshotRejectsInvalidData(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{
			name: "invalid JSON",
			data: "{invalid",
		},
		{
			name: "unsupported version",
			data: `{"version":2,"service":"Wi-Fi","settings":{}}`,
		},
		{
			name: "missing service",
			data: `{"version":1,"settings":{}}`,
		},
		{
			name: "invalid port",
			data: `{"version":1,"service":"Wi-Fi","settings":{"enabled":true,"server":"proxy.example.com","port":70000}}`,
		},
		{
			name: "authenticated proxy",
			data: `{"version":1,"service":"Wi-Fi","settings":{"authenticated":true}}`,
		},
		{
			name: "unknown field",
			data: `{"version":1,"service":"Wi-Fi","unexpected":true,"settings":{}}`,
		},
		{
			name: "additional JSON document",
			data: `{"version":1,"service":"Wi-Fi","settings":{}} {}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, backupFileName)

			if err := os.WriteFile(path, []byte(tt.data), 0600); err != nil {
				t.Fatal(err)
			}

			_, err := loadSnapshotFromDir(dir)
			if err == nil {
				t.Fatal("expected invalid backup to be rejected")
			}
		})
	}
}

func TestLoadHTTPSProxySnapshotRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	link := filepath.Join(dir, backupFileName)

	if err := os.WriteFile(target, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	_, err := loadSnapshotFromDir(dir)
	if err == nil {
		t.Fatal("expected symbolic link to be rejected")
	}
}

func TestLoadHTTPSProxySnapshotRejectsUnsafePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, backupFileName)

	// Recovery backups must not be accessible by other users.
	if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := loadSnapshotFromDir(dir)
	if err == nil {
		t.Fatal("expected unsafe backup permissions to be rejected")
	}

	if !strings.Contains(err.Error(), "permissions 0600") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadHTTPSProxySnapshotRejectsMissingFile(t *testing.T) {
	_, err := loadSnapshotFromDir(t.TempDir())

	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected file-not-found error, got %v", err)
	}
}

func TestRemoveSnapshotFromDir(t *testing.T) {
	dir := t.TempDir()

	snapshot := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Server: "127.0.0.1",
			Port:   9877,
		},
	}

	path, err := saveSnapshotToDir(dir, snapshot)
	if err != nil {
		t.Fatalf("saveSnapshotToDir() error = %v", err)
	}

	if err := removeSnapshotFromDir(dir, snapshot); err != nil {
		t.Fatalf("removeSnapshotFromDir() error = %v", err)
	}

	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup should be removed, got %v", err)
	}
}

func TestRemoveSnapshotFromDirRejectsDifferentSnapshot(t *testing.T) {
	dir := t.TempDir()

	original := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Server: "original.example.com",
			Port:   8080,
		},
	}

	path, err := saveSnapshotToDir(dir, original)
	if err != nil {
		t.Fatal(err)
	}

	different := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Server: "different.example.com",
			Port:   9090,
		},
	}

	if err := removeSnapshotFromDir(dir, different); err == nil {
		t.Fatal("expected mismatched snapshot to be rejected")
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("original backup must remain: %v", err)
	}
}

func TestRemoveSnapshotFromDirRejectsInvalidBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, backupFileName)

	if err := os.WriteFile(path, []byte("invalid JSON"), 0600); err != nil {
		t.Fatal(err)
	}

	expected := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Server: "127.0.0.1",
			Port:   9877,
		},
	}

	if err := removeSnapshotFromDir(dir, expected); err == nil {
		t.Fatal("expected invalid backup to be rejected")
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("invalid backup must not be deleted: %v", err)
	}
}

func TestRemoveSnapshotFromDirRejectsMissingBackup(t *testing.T) {
	expected := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Server: "127.0.0.1",
			Port:   9877,
		},
	}

	err := removeSnapshotFromDir(t.TempDir(), expected)

	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected missing backup error, got %v", err)
	}
}

func TestCheckPendingRecoveryNoBackup(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "packetsail")

	if err := checkPendingRecoveryInDir(dir); err != nil {
		t.Fatalf("unexpected recovery error: %v", err)
	}
}

func TestCheckPendingRecoveryExistingBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, backupFileName)

	if err := os.WriteFile(path, []byte("existing backup"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := checkPendingRecoveryInDir(dir); err == nil {
		t.Fatal("expected pending recovery to prevent startup")
	}

	// Startup checks must never remove the existing backup.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("recovery backup must remain: %v", err)
	}
}

func TestCheckPendingRecoveryRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	path := filepath.Join(dir, backupFileName)

	if err := os.WriteFile(target, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	if err := checkPendingRecoveryInDir(dir); err == nil {
		t.Fatal("expected symlink to block startup")
	}
}

func TestBackupEmptyHTTPSProxySettings(t *testing.T) {
	dir := t.TempDir()

	original := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Enabled:       false,
			Server:        "",
			Port:          0,
			Authenticated: false,
		},
	}

	if _, err := saveSnapshotToDir(dir, original); err != nil {
		t.Fatalf("save empty HTTPS proxy settings: %v", err)
	}

	restored, err := loadSnapshotFromDir(dir)
	if err != nil {
		t.Fatalf("load empty HTTPS proxy settings: %v", err)
	}

	if restored != original {
		t.Fatalf(
			"restored snapshot = %+v, want %+v",
			restored,
			original,
		)
	}
}

func TestReadBackupFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()

	target := filepath.Join(dir, "target.json")
	path := filepath.Join(dir, backupFileName)

	if err := os.WriteFile(target, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	if _, err := readBackupFile(path); err == nil {
		t.Fatal("expected symbolic link to be rejected")
	}
}

func TestReadBackupFileRejectsUnsafePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, backupFileName)

	if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := readBackupFile(path); err == nil {
		t.Fatal("expected unsafe permissions to be rejected")
	}
}

func TestReadBackupFileRejectsLargeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, backupFileName)

	data := make([]byte, 64*1024+1)

	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := readBackupFile(path); err == nil {
		t.Fatal("expected oversized backup to be rejected")
	}
}
