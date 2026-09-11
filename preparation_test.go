package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestArchivePreparationProgress(t *testing.T) {
	body := make([]byte, 8<<20)
	if _, err := rand.Read(body); err != nil {
		t.Fatal(err)
	}
	sender, root, _ := localUploadSource(t, map[string][]byte{"大文件.bin": body, "子目录/空文件.txt": nil})
	app := &App{}
	progress, started := app.startPreparation("http://127.0.0.1:8600", true)
	if !started {
		t.Fatal("preparation not started")
	}
	result := make(chan error, 1)
	go func() {
		_, _, _, err := sender.buildArchiveProgress([]string{root}, progress)
		result <- err
	}()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	sawPartialFile := false
	var previous int64
	for {
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
			state := progress.snapshot()
			if !sawPartialFile {
				t.Fatal("large file had no intermediate byte progress")
			}
			if state.TotalFiles != 2 || state.DoneFiles != 2 || state.TotalBytes != int64(len(body)) || state.DoneBytes != state.TotalBytes {
				t.Fatalf("wrong final counts: %+v", state)
			}
			if state.Stage != "verifying" || state.ZipBytes <= 0 || state.VerifyBytes != state.ZipBytes {
				t.Fatalf("missing archive verification progress: %+v", state)
			}
			progress.finish("")
			if state = progress.snapshot(); state.Active || state.Stage != "ready" || state.Elapsed <= 0 {
				t.Fatalf("wrong finished state: %+v", state)
			}
			return
		case <-ticker.C:
			state := app.preparationState()
			if state.DoneBytes < previous {
				t.Fatal("compression progress moved backwards")
			}
			previous = state.DoneBytes
			if state.Stage == "compressing" && state.DoneBytes > 0 && state.DoneBytes < state.TotalBytes {
				sawPartialFile = true
			}
		}
	}
}

func TestPreparationAPIAndFailureRecovery(t *testing.T) {
	app := &App{}
	handler := newAppMux(app)
	defer app.Close()
	if response := requestFixture(t, handler, http.MethodGet, "/api/prepare-state", "wrong", nil); response.Code != 401 {
		t.Fatal("preparation state leaked without admin authorization")
	}
	response := requestFixture(t, handler, http.MethodGet, "/api/prepare-state", app.adminKey, nil)
	var state preparationState
	if err := json.Unmarshal(response.Body.Bytes(), &state); err != nil || state.Stage != "idle" {
		t.Fatal("missing initial idle state", err)
	}
	progress, _ := app.startPreparation("http://127.0.0.1:1", true)
	input := map[string]interface{}{"remote_url": "http://127.0.0.1:1", "remote_password": "fixture", "folders": []string{t.TempDir()}, "compress": true}
	response = requestFixture(t, handler, http.MethodPost, "/api/push", app.adminKey, input)
	if response.Code != 409 || app.preparationState().ID != progress.snapshot().ID {
		t.Fatal("duplicate request replaced active preparation")
	}
	progress.finish("fixture failure")
	previousID := progress.snapshot().ID
	response = requestFixture(t, handler, http.MethodPost, "/api/push", app.adminKey, input)
	state = app.preparationState()
	if response.Code != 400 || state.Stage != "error" || state.Active || state.ID == previousID || !strings.Contains(state.Error, "没有可发送") {
		t.Fatalf("empty directory did not report recoverable failure: %+v, %s", state, response.Body.String())
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "empty.txt"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	sender := NewSender("fixture")
	if _, err := sender.addRoot(root); err != nil {
		t.Fatal(err)
	}
	progress, started := app.startPreparation("http://127.0.0.1:1", true)
	if !started {
		t.Fatal("failed preparation prevented retry")
	}
	if _, _, _, err := sender.buildArchiveProgress([]string{root}, progress); err != nil {
		t.Fatal(err)
	}
	state = progress.snapshot()
	if state.DoneFiles != 1 || state.TotalFiles != 1 || state.DoneBytes != 0 || state.TotalBytes != 0 {
		t.Fatalf("zero-byte file progress incorrect: %+v", state)
	}
}

type failingProgressOutput struct{}

func (failingProgressOutput) Write(data []byte) (int, error) {
	return 2, errors.New("write failed")
}

func TestProgressWriterCountsOnlyWrittenBytes(t *testing.T) {
	var observed int64
	writer := &progressWriter{writer: failingProgressOutput{}, advance: func(count int64) { observed += count }}
	count, err := writer.Write(bytes.Repeat([]byte("x"), 8))
	if count != 2 || observed != 2 || err == nil {
		t.Fatal("failed write reported unread or unwritten bytes")
	}
}
