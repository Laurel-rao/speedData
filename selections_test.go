package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMixedSelectionsUpload(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(fmt.Sprint(compressed), func(t *testing.T) {
			folder := filepath.Join(t.TempDir(), "资料")
			nested := filepath.Join(folder, "子目录", "清单.txt")
			writeFixture(t, nested, []byte("nested payload"))
			writeFixture(t, filepath.Join(folder, "空.txt"), nil)
			writeFixture(t, filepath.Join(folder, cacheDirectory, "ignored.txt"), []byte("cache"))
			first := filepath.Join(t.TempDir(), "单个;文件.txt")
			second := filepath.Join(t.TempDir(), "单个;文件.txt")
			writeFixture(t, first, []byte("first payload"))
			writeFixture(t, second, []byte("second payload"))
			writeFixture(t, filepath.Join(filepath.Dir(first), "不得发送.txt"), []byte("private sibling"))
			expected := map[string][]byte{
				"资料/子目录/清单.txt": []byte("nested payload"),
				"资料/空.txt":      nil,
				"单个;文件.txt":     []byte("first payload"),
				"单个;文件 (1).txt": []byte("second payload"),
			}
			receiver := &App{receiver: &Receiver{dest: t.TempDir(), password: "receive", token: "token", policy: "rename"}}
			server := httptest.NewServer(newAppMux(receiver))
			defer server.Close()
			defer receiver.Close()
			sending := &App{port: 3}
			handler := newAppMux(sending)
			defer sending.Close()
			response := requestFixture(t, handler, http.MethodPost, "/api/push", sending.adminKey, map[string]interface{}{
				"remote_url": server.URL, "remote_password": "receive", "compress": compressed,
				"paths": []string{first, nested, folder, first, folder, second},
			})
			if response.Code != 200 {
				t.Fatal(response.Body.String())
			}
			state := sending.preparationState()
			if state.Stage != "ready" || state.TotalFiles != len(expected) {
				t.Fatalf("duplicates not removed or selections missing: %+v", state)
			}
			awaitCondition(t, func() bool { return receiver.receiveState("")["all_done"] == true })
			for name, body := range expected {
				actual, err := os.ReadFile(filepath.Join(receiver.receiver.dest, filepath.FromSlash(name)))
				if err != nil || !bytes.Equal(actual, body) {
					t.Fatalf("wrong received file %s: %v", name, err)
				}
			}
			for _, name := range []string{"不得发送.txt", "清单.txt", "资料/" + cacheDirectory + "/ignored.txt"} {
				if _, err := os.Stat(filepath.Join(receiver.receiver.dest, filepath.FromSlash(name))); !os.IsNotExist(err) {
					t.Fatalf("unexpected file transmitted: %s", name)
				}
			}
			additional := filepath.Join(t.TempDir(), "追加.bin")
			writeFixture(t, additional, []byte("append"))
			response = requestFixture(t, handler, http.MethodPost, "/api/push", sending.adminKey, map[string]interface{}{
				"remote_url": server.URL, "remote_password": "receive", "compress": compressed, "paths": []string{additional},
			})
			if response.Code != 200 {
				t.Fatal(response.Body.String())
			}
			awaitCondition(t, func() bool {
				body, err := os.ReadFile(filepath.Join(receiver.receiver.dest, "追加.bin"))
				return err == nil && string(body) == "append"
			})
		})
	}
}

func TestSingleFileSelectionDoesNotExposeSiblings(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "chosen.txt")
	writeFixture(t, path, []byte("chosen"))
	writeFixture(t, filepath.Join(directory, "secret.txt"), []byte("secret"))
	sender := NewSender("fixture")
	name, err := sender.addRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	listed, err := sender.walk()
	if err != nil || len(listed) != 1 || listed[0].Path != name {
		t.Fatalf("single file listing incorrect: %v, %v", listed, err)
	}
	for _, request := range []string{"secret.txt", name + "/secret.txt", name + "/../secret.txt", filepath.Base(directory) + "/secret.txt"} {
		if file, err := sender.open(request); err == nil {
			file.Close()
			t.Fatalf("sibling accessible through %q", request)
		}
	}
	file, err := sender.open(name)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(file)
	file.Close()
	if err != nil || string(body) != "chosen" {
		t.Fatal("chosen file unreadable", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(path, "new-child.txt"), []byte("not selected"))
	if _, err := sender.selectedFiles([]string{path}, nil); err == nil {
		t.Fatal("selected file was silently expanded into a directory")
	}
}

func TestSelectedFileSymlinkReplacementRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated privileges")
	}
	root := t.TempDir()
	path := filepath.Join(root, "chosen.txt")
	other := filepath.Join(root, "secret.txt")
	writeFixture(t, path, []byte("chosen"))
	writeFixture(t, other, []byte("secret"))
	sender := NewSender("fixture")
	name, err := sender.addRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, path); err != nil {
		t.Fatal(err)
	}
	if file, err := sender.open(name); err == nil {
		file.Close()
		t.Fatal("replacement symlink was followed")
	}
	if _, err := sender.addRoot(path); err == nil {
		t.Fatal("symlink accepted as a selected regular file")
	}
}

func TestSingleEmptyFileArchive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "空文件.txt")
	writeFixture(t, path, nil)
	sender := NewSender("fixture")
	if _, err := sender.addRoot(path); err != nil {
		t.Fatal(err)
	}
	archivePath, count, total, err := sender.buildArchive([]string{path})
	if err != nil || count != 1 || total != 0 {
		t.Fatalf("empty file archive incorrect: %d %d %v", count, total, err)
	}
	archive, err := zip.OpenReader(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	if len(archive.File) != 1 || archive.File[0].Name != "空文件.txt" {
		t.Fatal("single file should not get a parent directory prefix")
	}
}

func TestNativeFilePickerCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX scripts instead of showing native dialogs")
	}
	for _, scenario := range []struct {
		name, script string
		wantError    bool
	}{
		{"selected", "printf '/tmp/中文;文件.txt'", false},
		{"empty", "exit 0", true},
		{"canceled", "exit 1", true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			directory := t.TempDir()
			tool := "osascript"
			if runtime.GOOS == "linux" {
				tool = "zenity"
			}
			if err := os.WriteFile(filepath.Join(directory, tool), []byte("#!/bin/sh\n"+scenario.script+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", directory)
			path, err := pickFile()
			if scenario.wantError != (err != nil) || (!scenario.wantError && path != "/tmp/中文;文件.txt") {
				t.Fatalf("picker result: %q, %v", path, err)
			}
		})
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "powershell.exe"), []byte("#!/bin/sh\nprintf '%s' \"$5\" > \"$PICKER_SCRIPT\"\nprintf 'C:\\\\中文文件.txt'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	t.Setenv("PICKER_SCRIPT", filepath.Join(directory, "captured.txt"))
	path, err := pickWindows("OpenFileDialog", "Title", "FileName", "文件")
	if err != nil || path != `C:\中文文件.txt` {
		t.Fatal(path, err)
	}
	script, err := os.ReadFile(filepath.Join(directory, "captured.txt"))
	if err != nil || !strings.Contains(string(script), "OpenFileDialog") || !strings.Contains(string(script), "$folder.FileName") {
		t.Fatal("wrong Windows file picker script", err)
	}
}

func TestFilePickerRequiresAdmin(t *testing.T) {
	app := &App{}
	response := requestFixture(t, newAppMux(app), http.MethodPost, "/api/pick-file", "wrong", nil)
	if response.Code != http.StatusUnauthorized {
		t.Fatal("file picker endpoint allowed unauthorized access")
	}
}

func TestEmptySelectionDoesNotShareWorkingDirectory(t *testing.T) {
	sender := NewSender("fixture")
	for _, path := range []string{"", "   "} {
		if _, err := sender.addRoot(path); err == nil {
			t.Fatal("empty path was registered")
		}
		if _, err := sender.selectedFiles([]string{path}, nil); err == nil {
			t.Fatal("empty path was scanned")
		}
	}
}
