package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWindowsSourceCompatibilityNestedLicense(t *testing.T) {
	base := t.TempDir()
	name := "frp_0.62.0_windows_amd64/LICENSE"
	writeFixture(t, filepath.Join(base, filepath.FromSlash(name)), []byte("license fixture"))
	file, err := openSourceCompatibility(base, name, &os.PathError{Op: "openat", Path: name, Err: syscall.Errno(87)})
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	content, err := io.ReadAll(file)
	if err != nil || string(content) != "license fixture" {
		t.Fatalf("content=%q error=%v", content, err)
	}
}

func TestWindowsSourceCompatibilityDoesNotBypassOtherErrors(t *testing.T) {
	for _, original := range []error{os.ErrPermission, os.ErrNotExist, errors.New("path escapes root")} {
		file, err := openSourceCompatibility(t.TempDir(), "LICENSE", original)
		if file != nil || err != original {
			t.Fatal("unexpected fallback for non-parameter error")
		}
	}
}

func TestWindowsVerifiedSourceRejectsEscape(t *testing.T) {
	base := t.TempDir()
	for _, name := range []string{`..\LICENSE`, `C:\LICENSE`, `\\server\share\LICENSE`} {
		if file, err := openVerifiedSource(base, name); err == nil {
			file.Close()
			t.Fatalf("accepted %q", name)
		}
	}
	outside := filepath.Join(t.TempDir(), "LICENSE")
	writeFixture(t, outside, []byte("outside"))
	if err := os.Symlink(outside, filepath.Join(base, "link")); err != nil {
		t.Skipf("Windows symlink creation unavailable: %v", err)
	}
	if file, err := openVerifiedSource(base, "link"); err == nil {
		file.Close()
		t.Fatal("accepted outside symlink")
	}
}
