package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPickFolderWindowsCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell to simulate PowerShell output")
	}
	for _, test := range []struct {
		name   string
		script string
		path   string
		error  string
	}{
		{"unicode path", "printf 'C:\\\\测试目录\\\\资料'", `C:\测试目录\资料`, ""},
		{"cancel", "exit 0", "", "未选择文件夹"},
		{"failure", "echo 'PowerShell blocked' >&2; exit 1", "", "PowerShell blocked"},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.WriteFile(filepath.Join(directory, "powershell.exe"), []byte("#!/bin/sh\n"+test.script+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", directory)
			path, err := pickFolderWindows()
			if path != test.path {
				t.Fatalf("path = %q, want %q", path, test.path)
			}
			if test.error == "" && err != nil {
				t.Fatal(err)
			}
			if test.error != "" && (err == nil || !strings.Contains(err.Error(), test.error)) {
				t.Fatalf("error = %v, want %q", err, test.error)
			}
		})
	}
}
