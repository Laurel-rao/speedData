package main

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func uploadRequest(test *testing.T, handler http.Handler, endpoint, token string, input interface{}) *httptest.ResponseRecorder {
	test.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		test.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-FT-Token", token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func uploadChunkRequest(handler http.Handler, token string, status uploadStatus, index int, body []byte, mode string) *httptest.ResponseRecorder {
	query := url.Values{"id": {status.ID}, "path": {status.Path}, "index": {strconv.Itoa(index)}, "generation": {strconv.FormatUint(status.Generation, 10)}}
	request := httptest.NewRequest(http.MethodPost, "/api/upload/chunk?"+query.Encode(), bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-FT-Token", token)
	request.Header.Set("X-Enc", mode)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func decodeUploadStatus(test *testing.T, response *httptest.ResponseRecorder) uploadStatus {
	test.Helper()
	if response.Code != 200 {
		test.Fatalf("HTTP %d: %s", response.Code, response.Body.String())
	}
	var status uploadStatus
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		test.Fatal(err)
	}
	return status
}

func localUploadSource(test *testing.T, contents map[string][]byte) (*Sender, string, string) {
	test.Helper()
	root := test.TempDir()
	for name, body := range contents {
		writeFixture(test, filepath.Join(root, name), body)
	}
	sender := NewSender("local-source")
	name, err := sender.addRoot(root)
	if err != nil {
		test.Fatal(err)
	}
	return sender, root, name
}

func TestUploadWithoutSenderListener(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(fmt.Sprint(compressed), func(test *testing.T) {
			body := bytes.Repeat([]byte("upload fixture bytes"), chunkSize/10)
			sender, root, name := localUploadSource(test, map[string][]byte{"nested/payload.bin": body, "empty.txt": nil})
			receiver := &App{receiver: &Receiver{dest: test.TempDir(), password: "receive", token: "token", policy: "rename"}}
			server := httptest.NewServer(newAppMux(receiver))
			defer receiver.Close()
			defer server.Close()
			sending := &App{sender: sender, port: 1}
			defer sending.Close()
			response := requestFixture(test, newAppMux(sending), http.MethodPost, "/api/push", sending.adminKey, map[string]interface{}{"remote_url": server.URL, "remote_password": "receive", "folders": []string{root}, "compress": compressed})
			if response.Code != 200 || !strings.Contains(response.Body.String(), `"ok":true`) {
				test.Fatal(response.Body.String())
			}
			preparation := sending.preparationState()
			if preparation.Active || preparation.Stage != "ready" || preparation.Compressed != compressed || preparation.TotalFiles != 2 || preparation.TotalBytes != int64(len(body)) {
				test.Fatalf("preparation not completed before upload response: %+v", preparation)
			}
			awaitCondition(test, func() bool { return receiver.receiveState("")["all_done"] == true })
			content, err := os.ReadFile(filepath.Join(receiver.receiver.dest, name, "nested", "payload.bin"))
			if err != nil || !bytes.Equal(content, body) {
				test.Fatal("uploaded content mismatch", err)
			}
			info, err := os.Stat(filepath.Join(receiver.receiver.dest, name, "empty.txt"))
			if err != nil || info.Size() != 0 {
				test.Fatal("empty file missing", err)
			}
			for _, puller := range receiver.pullerList() {
				if !puller.passive || !strings.HasPrefix(puller.baseURL, "upload:") {
					test.Fatal("receiver requires outbound connection")
				}
			}
			if sending.sendState()["all_done"] != true {
				test.Fatal("sender did not observe receiver completion")
			}
		})
	}
}

func TestUploadAuthorizationValidationAndControls(t *testing.T) {
	sender, _, name := localUploadSource(t, map[string][]byte{"file.txt": []byte("correct bytes")})
	rel := name + "/file.txt"
	manifest, err := sender.manifest(rel)
	if err != nil {
		t.Fatal(err)
	}
	app := &App{receiver: &Receiver{dest: t.TempDir(), password: "receive", token: "token", policy: "rename"}}
	handler := newAppMux(app)
	defer app.Close()
	input := uploadStart{Source: sha256hex([]byte("sender offline")), Manifest: manifest}
	for _, endpoint := range []string{"start", "status", "fail"} {
		if response := uploadRequest(t, handler, "/api/upload/"+endpoint, "wrong", input); response.Code != 401 {
			t.Fatal("upload authorization bypass")
		}
	}
	invalid := input
	invalid.Manifest.Path = "../escape"
	if response := uploadRequest(t, handler, "/api/upload/start", "token", invalid); response.Code != 400 {
		t.Fatal("unsafe manifest accepted")
	}
	status := decodeUploadStatus(t, uploadRequest(t, handler, "/api/upload/start", "token", input))
	if response := uploadChunkRequest(handler, "wrong", status, 0, []byte("correct bytes"), "r"); response.Code != 401 {
		t.Fatal("unauthorized chunk accepted")
	}
	if response := uploadChunkRequest(handler, "token", status, 0, []byte("wrong bytes!!"), "r"); response.Code != 400 {
		t.Fatal("corrupt chunk accepted")
	}
	if response := uploadChunkRequest(handler, "token", status, -1, []byte("correct bytes"), "r"); response.Code != 400 {
		t.Fatal("negative index accepted")
	}
	var buffer bytes.Buffer
	writer := zlib.NewWriter(&buffer)
	writer.Write(bytes.Repeat([]byte("x"), chunkSize+1))
	writer.Close()
	if response := uploadChunkRequest(handler, "token", status, 0, buffer.Bytes(), "z"); response.Code != 413 {
		t.Fatal("oversized compressed chunk accepted")
	}
	puller := app.getPuller()
	puller.pause(rel)
	if response := uploadChunkRequest(handler, "token", status, 0, []byte("correct bytes"), "r"); response.Code != 409 {
		t.Fatal("paused upload accepted")
	}
	puller.resume(rel)
	if response := uploadChunkRequest(handler, "token", status, 0, []byte("correct bytes"), "r"); response.Code != 409 {
		t.Fatal("old generation accepted")
	}
	status, _ = puller.uploadStatus(rel)
	if response := uploadChunkRequest(handler, "token", status, 0, []byte("correct bytes"), "r"); response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	awaitStatus(t, puller, rel, "done")
	duplicate := decodeUploadStatus(t, uploadRequest(t, handler, "/api/upload/start", "token", input))
	if duplicate.Status != "done" {
		t.Fatal("lost response causes duplicate upload")
	}
	if _, err := os.Stat(filepath.Join(app.receiver.dest, name, "file (1).txt")); !os.IsNotExist(err) {
		t.Fatal("duplicate renamed file")
	}
	if response := requestFixture(t, handler, http.MethodPost, "/api/push-request", "", map[string]string{"sender_url": "http://127.0.0.1:1"}); response.Code != 410 {
		t.Fatal("legacy callback still enabled")
	}
}

func TestUploadReceiverRestartResumesVerifiedChunks(t *testing.T) {
	body := bytes.Repeat([]byte("z"), chunkSize+5)
	sender, _, name := localUploadSource(t, map[string][]byte{"file.bin": body})
	rel := name + "/file.bin"
	manifest, err := sender.manifest(rel)
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	input := uploadStart{Source: sha256hex([]byte("restart source")), Manifest: manifest}
	first := &App{receiver: &Receiver{dest: dest, password: "receive", token: "token", policy: "rename"}}
	handler := newAppMux(first)
	status := decodeUploadStatus(t, uploadRequest(t, handler, "/api/upload/start", "token", input))
	if response := uploadChunkRequest(handler, "token", status, 0, body[:chunkSize], "r"); response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	first.Close()
	second := &App{receiver: &Receiver{dest: dest, password: "receive", token: "new-token", policy: "rename"}}
	defer second.Close()
	handler = newAppMux(second)
	status = decodeUploadStatus(t, uploadRequest(t, handler, "/api/upload/start", "new-token", input))
	if len(status.Missing) != 1 || status.Missing[0] != 1 {
		t.Fatalf("resume lost verified chunks: %v", status.Missing)
	}
	if response := uploadChunkRequest(handler, "new-token", status, 1, body[chunkSize:], "r"); response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	awaitStatus(t, second.getPuller(), rel, "done")
	content, err := os.ReadFile(filepath.Join(dest, rel))
	if err != nil || !bytes.Equal(content, body) {
		t.Fatal("resumed content mismatch", err)
	}
}

func TestUploadCancellationDoesNotCommit(t *testing.T) {
	sender, _, name := localUploadSource(t, map[string][]byte{"file.txt": []byte("cancel fixture")})
	rel := name + "/file.txt"
	manifest, _ := sender.manifest(rel)
	app := &App{receiver: &Receiver{dest: t.TempDir(), password: "receive", token: "token", policy: "rename"}}
	defer app.Close()
	handler := newAppMux(app)
	status := decodeUploadStatus(t, uploadRequest(t, handler, "/api/upload/start", "token", uploadStart{Source: sha256hex([]byte("cancel source")), Manifest: manifest}))
	app.getPuller().cancelJob(rel)
	if response := uploadChunkRequest(handler, "token", status, 0, []byte("cancel fixture"), "r"); response.Code != 409 {
		t.Fatal("canceled upload accepted")
	}
	if _, err := os.Stat(filepath.Join(app.receiver.dest, rel)); !os.IsNotExist(err) {
		t.Fatal("canceled file committed")
	}
}

func TestUploadSkipReportsCompleted(t *testing.T) {
	sender, _, name := localUploadSource(t, map[string][]byte{"file.txt": []byte("new")})
	dest := t.TempDir()
	rel := name + "/file.txt"
	writeFixture(t, filepath.Join(dest, rel), []byte("original"))
	receiver := &App{receiver: &Receiver{dest: dest, password: "receive", token: "token", policy: "skip"}}
	server := httptest.NewServer(newAppMux(receiver))
	defer receiver.Close()
	defer server.Close()
	sending := &App{sender: sender}
	defer sending.Close()
	if _, err := sending.beginUpload(server.URL, "receive", sender, []string{rel}, false, 1, 3); err != nil {
		t.Fatal(err)
	}
	if sending.sendState()["all_done"] != true {
		t.Fatal("skipped batch never completes")
	}
	content, _ := os.ReadFile(filepath.Join(dest, rel))
	if string(content) != "original" {
		t.Fatal("skip overwrote existing file")
	}
}

func TestUploadRefreshesReceiverAuthorization(t *testing.T) {
	sender, _, name := localUploadSource(t, map[string][]byte{"file.txt": []byte("token refresh")})
	rel := name + "/file.txt"
	manifest, _ := sender.manifest(rel)
	receiver := &App{receiver: &Receiver{dest: t.TempDir(), password: "receive", token: "old-token", policy: "rename"}}
	server := httptest.NewServer(newAppMux(receiver))
	defer receiver.Close()
	defer server.Close()
	sending := &App{sender: sender}
	defer sending.Close()
	host, _ := os.Hostname()
	executable, _ := os.Executable()
	source := sha256hex([]byte(host + "\n" + executable + "\n0"))
	puller, _, err := receiver.acquirePuller("upload:"+source, "", receiver.receiver.dest, "rename")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := puller.addRecords([]string{rel}, "rename", false, 1, 13, manifest); err != nil {
		t.Fatal(err)
	}
	puller.pause(rel)
	if _, err := sending.beginUpload(server.URL, "receive", sender, []string{rel}, false, 1, 13); err != nil {
		t.Fatal(err)
	}
	receiver.mu.Lock()
	receiver.receiver = &Receiver{dest: receiver.receiver.dest, password: "receive", token: "replacement-token", policy: "rename"}
	receiver.mu.Unlock()
	uploader := sending.uploaders[server.URL]
	awaitCondition(t, func() bool {
		uploader.mu.Lock()
		defer uploader.mu.Unlock()
		return uploader.token == "replacement-token"
	})
	puller.resume(rel)
	awaitStatus(t, puller, rel, "done")
	if sending.sendState()["all_done"] != true {
		t.Fatal("progress credential not refreshed")
	}
}

func TestUploadRejectsLegacyReceiver(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/auth" {
			t.Error("unexpected legacy transfer request", request.URL.Path)
		}
		writeJSON(response, 200, map[string]interface{}{"ok": true, "token": "legacy-token", "proto": 1, "ver": "1.0.0"})
	}))
	defer server.Close()
	sender, _, name := localUploadSource(t, map[string][]byte{"file.txt": []byte("upgrade")})
	app := &App{sender: sender}
	defer app.Close()
	if _, err := app.beginUpload(server.URL, "password", sender, []string{name + "/file.txt"}, false, 1, 7); err == nil || !strings.Contains(err.Error(), "版本不兼容") {
		t.Fatal("legacy receiver was not rejected", err)
	}
}

func TestPassiveReceiverDoesNotScheduleDownloads(t *testing.T) {
	manifest := Manifest{Path: "file.txt", Size: 1, ChunkSize: chunkSize, NChunks: 1, SHA256: sha256hex([]byte("x")), ChunkHashes: []string{sha256hex([]byte("x"))}}
	puller := NewPuller("upload:"+sha256hex([]byte("no callback")), "", t.TempDir(), "rename")
	defer puller.Close()
	if _, err := puller.addRecords([]string{manifest.Path}, "rename", false, 1, 1, manifest); err != nil {
		t.Fatal(err)
	}
	puller.start()
	for index := 0; index < 10; index++ {
		if puller.pick() != nil {
			t.Fatal("passive receiver scheduled outbound download")
		}
	}
	time.Sleep(100 * time.Millisecond)
	puller.mu.Lock()
	defer puller.mu.Unlock()
	job := puller.jobs[manifest.Path]
	if job.status != "pending" || job.errors != 0 || len(job.inflight) != 0 {
		t.Fatal("receiver attempted to pull data", job.status, job.lastError)
	}
}
