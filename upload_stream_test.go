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
	"sync"
	"testing"
)

func streamingInput(body []byte) uploadStart {
	return uploadStart{Source: sha256hex([]byte("streaming fixture")), Manifest: Manifest{Path: "stream/file.bin", Size: int64(len(body)), MTime: 1700000000, ChunkSize: chunkSize, NChunks: (len(body) + chunkSize - 1) / chunkSize}}
}

func streamingChunk(handler http.Handler, status uploadStatus, index int, body []byte, digest, mode string) *httptest.ResponseRecorder {
	query := url.Values{"id": {status.ID}, "path": {status.Path}, "index": {strconv.Itoa(index)}, "generation": {strconv.FormatUint(status.Generation, 10)}, "chunk_sha256": {digest}}
	request := httptest.NewRequest(http.MethodPost, "/api/upload/chunk?"+query.Encode(), bytes.NewReader(body))
	request.Header.Set("X-FT-Token", "token")
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Enc", mode)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func streamingFinish(test *testing.T, handler http.Handler, status uploadStatus, digest string) *httptest.ResponseRecorder {
	test.Helper()
	return uploadRequest(test, handler, "/api/upload/finish", "token", uploadFinish{ID: status.ID, Path: status.Path, Generation: status.Generation, SHA256: digest})
}

func streamingApp(test *testing.T, dest string) (*App, http.Handler) {
	test.Helper()
	app := &App{receiver: &Receiver{dest: dest, password: "receive", token: "token", policy: "rename"}}
	test.Cleanup(app.Close)
	return app, newAppMux(app)
}

func TestStreamingUploadRoundTrip(t *testing.T) {
	for _, mode := range []string{"r", "z"} {
		t.Run(mode, func(test *testing.T) {
			body := bytes.Repeat([]byte("s"), chunkSize+17)
			input := streamingInput(body)
			app, handler := streamingApp(test, test.TempDir())
			status := decodeUploadStatus(test, uploadRequest(test, handler, "/api/upload/open", "token", input))
			if status.DoneChunks != 0 || status.MissingChunks != 2 {
				test.Fatalf("unexpected open: %+v", status)
			}
			if response := streamingFinish(test, handler, status, sha256hex(body)); response.Code != 409 {
				test.Fatalf("premature finish: %d %s", response.Code, response.Body.String())
			}
			for _, index := range []int{1, 1, 0} {
				chunk := body[index*chunkSize : min(len(body), (index+1)*chunkSize)]
				wire := chunk
				if mode == "z" {
					var compressed bytes.Buffer
					writer := zlib.NewWriter(&compressed)
					writer.Write(chunk)
					writer.Close()
					wire = compressed.Bytes()
				}
				if response := streamingChunk(handler, status, index, wire, strings.ToUpper(sha256hex(chunk)), mode); response.Code != 200 {
					test.Fatal(response.Code, response.Body.String())
				}
			}
			status, _ = app.getPuller().uploadStatus(input.Manifest.Path)
			if status.Phase != "waiting_for_finish" || status.DoneChunks != 2 || status.BytesDone != int64(len(body)) {
				test.Fatalf("unexpected streamed state: %+v", status)
			}
			if _, err := os.Stat(filepath.Join(app.receiver.dest, status.Path)); !os.IsNotExist(err) {
				test.Fatal("unverified file was committed", err)
			}
			decodeUploadStatus(test, streamingFinish(test, handler, status, sha256hex(body)))
			awaitStatus(test, app.getPuller(), status.Path, "done")
			decodeUploadStatus(test, streamingFinish(test, handler, status, sha256hex(body)))
			reopened := decodeUploadStatus(test, uploadRequest(test, handler, "/api/upload/open", "token", input))
			if reopened.Status != "done" {
				test.Fatalf("lost completion response not idempotent: %+v", reopened)
			}
			actual, err := os.ReadFile(filepath.Join(app.receiver.dest, status.Path))
			if err != nil || !bytes.Equal(actual, body) {
				test.Fatal("content differs", err)
			}
		})
	}
}

func TestStreamingUploadRejectsInvalidChunks(t *testing.T) {
	body := []byte("valid chunk")
	input := streamingInput(body)
	app, handler := streamingApp(t, t.TempDir())
	status := decodeUploadStatus(t, uploadRequest(t, handler, "/api/upload/open", "token", input))
	for _, fixture := range []struct {
		name   string
		index  int
		body   []byte
		digest string
	}{
		{"missing hash", 0, body, ""},
		{"malformed hash", 0, body, "not-sha256"},
		{"wrong hash", 0, body, sha256hex([]byte("wrong"))},
		{"negative index", -1, body, sha256hex(body)},
		{"large index", 1, body, sha256hex(body)},
		{"wrong length", 0, body[:2], sha256hex(body[:2])},
	} {
		t.Run(fixture.name, func(test *testing.T) {
			if response := streamingChunk(handler, status, fixture.index, fixture.body, fixture.digest, "r"); response.Code != 400 {
				test.Fatal(response.Code, response.Body.String())
			}
		})
	}
	current, _ := app.getPuller().uploadStatus(status.Path)
	if current.BytesDone != 0 || current.DoneChunks != 0 {
		t.Fatal("invalid chunk changed progress", current)
	}
	if response := streamingChunk(handler, status, 0, body, sha256hex(body), "r"); response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	changed := bytes.Repeat([]byte("x"), len(body))
	if response := streamingChunk(handler, status, 0, changed, sha256hex(changed), "r"); response.Code != 400 {
		t.Fatal("conflicting duplicate accepted", response.Code)
	}
	if response := streamingFinish(t, handler, status, "invalid"); response.Code != 400 {
		t.Fatal("invalid final hash accepted")
	}
}

func TestStreamingUploadRestartRevalidatesChunks(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(fmt.Sprint(corrupt), func(test *testing.T) {
			body := bytes.Repeat([]byte("p"), chunkSize+23)
			input := streamingInput(body)
			dest := test.TempDir()
			first, handler := streamingApp(test, dest)
			status := decodeUploadStatus(test, uploadRequest(test, handler, "/api/upload/open", "token", input))
			if response := streamingChunk(handler, status, 0, body[:chunkSize], sha256hex(body[:chunkSize]), "r"); response.Code != 200 {
				test.Fatal(response.Body.String())
			}
			partName := first.getPuller().jobs[status.Path].partName
			first.Close()
			if corrupt {
				file, err := os.OpenFile(filepath.Join(dest, partName), os.O_WRONLY, 0600)
				if err != nil {
					test.Fatal(err)
				}
				_, err = file.WriteAt([]byte("damage"), 0)
				file.Close()
				if err != nil {
					test.Fatal(err)
				}
			}
			second, handler := streamingApp(test, dest)
			status = decodeUploadStatus(test, uploadRequest(test, handler, "/api/upload/open", "token", input))
			expected := 1
			if corrupt {
				expected = 2
			}
			if len(status.Missing) != expected {
				test.Fatalf("incorrect recovery: %+v", status)
			}
			for _, index := range status.Missing {
				chunk := body[index*chunkSize : min(len(body), (index+1)*chunkSize)]
				if response := streamingChunk(handler, status, index, chunk, sha256hex(chunk), "r"); response.Code != 200 {
					test.Fatal(response.Body.String())
				}
			}
			second.Close()
			third, handler := streamingApp(test, dest)
			status = decodeUploadStatus(test, uploadRequest(test, handler, "/api/upload/open", "token", input))
			if status.Phase != "waiting_for_finish" || status.MissingChunks != 0 {
				test.Fatalf("lost finished chunks: %+v", status)
			}
			decodeUploadStatus(test, streamingFinish(test, handler, status, sha256hex(body)))
			awaitStatus(test, third.getPuller(), status.Path, "done")
		})
	}
}

func TestStreamingUploadFinalHashFailureAndRecovery(t *testing.T) {
	body := []byte("right content")
	input := streamingInput(body)
	dest := t.TempDir()
	first, handler := streamingApp(t, dest)
	status := decodeUploadStatus(t, uploadRequest(t, handler, "/api/upload/open", "token", input))
	if response := streamingChunk(handler, status, 0, body, sha256hex(body), "r"); response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	decodeUploadStatus(t, streamingFinish(t, handler, status, sha256hex([]byte("wrong full hash"))))
	awaitStatus(t, first.getPuller(), status.Path, "error")
	if _, err := os.Stat(filepath.Join(dest, status.Path)); !os.IsNotExist(err) {
		t.Fatal("invalid full file committed", err)
	}
	first.Close()
	second, handler := streamingApp(t, dest)
	status = decodeUploadStatus(t, uploadRequest(t, handler, "/api/upload/open", "token", input))
	if status.DoneChunks != 0 || status.MissingChunks != 1 {
		t.Fatalf("invalid file restored as verified: %+v", status)
	}
	if response := streamingChunk(handler, status, 0, body, sha256hex(body), "r"); response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	decodeUploadStatus(t, streamingFinish(t, handler, status, sha256hex(body)))
	awaitStatus(t, second.getPuller(), status.Path, "done")
}

func TestStreamingUploadRestoresSealedTask(t *testing.T) {
	body := []byte("persisted final hash")
	input := streamingInput(body)
	dest := t.TempDir()
	first := NewPuller("upload:"+input.Source, "", dest, "rename")
	t.Cleanup(first.Close)
	if _, err := first.addRecordsMode([]string{input.Manifest.Path}, "rename", false, 0, 0, true, input.Manifest); err != nil {
		t.Fatal(err)
	}
	status, _ := first.uploadStatus(input.Manifest.Path)
	if code, err := first.acceptChunk(status.Path, 0, status.Generation, body, sha256hex(body)); code != 200 {
		t.Fatal(err)
	}
	if code, err := first.finishUpload(uploadFinish{Path: status.Path, Generation: status.Generation, SHA256: sha256hex(body)}); code != 200 {
		t.Fatal(err)
	}
	first.Close()
	second, handler := streamingApp(t, dest)
	decodeUploadStatus(t, uploadRequest(t, handler, "/api/upload/open", "token", input))
	awaitStatus(t, second.getPuller(), status.Path, "done")
}

func TestStreamingUploadEmptyAndOptionalFullHash(t *testing.T) {
	for _, fixture := range []struct {
		name     string
		body     []byte
		expected bool
	}{
		{"empty deferred", nil, false}, {"empty expected", nil, true}, {"expected", []byte("expected hash"), true},
	} {
		t.Run(fixture.name, func(test *testing.T) {
			input := streamingInput(fixture.body)
			if fixture.expected {
				input.Manifest.SHA256 = strings.ToUpper(sha256hex(fixture.body))
			}
			app, handler := streamingApp(test, test.TempDir())
			status := decodeUploadStatus(test, uploadRequest(test, handler, "/api/upload/open", "token", input))
			if len(fixture.body) > 0 {
				if response := streamingChunk(handler, status, 0, fixture.body, sha256hex(fixture.body), "r"); response.Code != 200 {
					test.Fatal(response.Body.String())
				}
			}
			if !fixture.expected {
				decodeUploadStatus(test, streamingFinish(test, handler, status, sha256hex(nil)))
			}
			awaitStatus(test, app.getPuller(), status.Path, "done")
		})
	}
}

func TestStreamingUploadValidationAndLegacyIsolation(t *testing.T) {
	input := streamingInput([]byte("body"))
	app, handler := streamingApp(t, t.TempDir())
	if response := uploadRequest(t, handler, "/api/upload/open", "bad-token", input); response.Code != 401 {
		t.Fatal("missing authentication")
	}
	if response := uploadRequest(t, handler, "/api/upload/start", "token", input); response.Code != 400 {
		t.Fatal("legacy start accepts incomplete manifest")
	}
	for _, mutate := range []func(*uploadStart){
		func(input *uploadStart) { input.Source = "bad" },
		func(input *uploadStart) { input.Manifest.Path = "../escape" },
		func(input *uploadStart) { input.Manifest.Path = cacheDirectory + "/escape" },
		func(input *uploadStart) { input.Manifest.Size = -1 },
		func(input *uploadStart) { input.Manifest.Size = int64(chunkSize)*maxChunks + 1 },
		func(input *uploadStart) { input.Manifest.ChunkSize = 1 },
		func(input *uploadStart) { input.Manifest.NChunks++ },
		func(input *uploadStart) { input.Manifest.SHA256 = "bad" },
		func(input *uploadStart) { input.Extract = true; input.Files = -1 },
	} {
		invalid := input
		mutate(&invalid)
		if response := uploadRequest(t, handler, "/api/upload/open", "token", invalid); response.Code != 400 {
			t.Fatal(response.Code, response.Body.String())
		}
	}
	status := decodeUploadStatus(t, uploadRequest(t, handler, "/api/upload/open", "token", input))
	legacy := input
	legacy.Manifest.SHA256 = sha256hex([]byte("body"))
	legacy.Manifest.ChunkHashes = []string{legacy.Manifest.SHA256}
	if response := uploadRequest(t, handler, "/api/upload/start", "token", legacy); response.Code != 400 {
		t.Fatal("legacy request merged into streaming task")
	}
	app.getPuller().pause(status.Path)
	if response := streamingFinish(t, handler, status, legacy.Manifest.SHA256); response.Code != 409 {
		t.Fatal("paused finish accepted")
	}
	app.getPuller().resume(status.Path)
	if response := streamingChunk(handler, status, 0, []byte("body"), legacy.Manifest.SHA256, "r"); response.Code != 409 {
		t.Fatal("stale generation accepted")
	}
	status, _ = app.getPuller().uploadStatus(status.Path)
	app.getPuller().cancelJob(status.Path)
	if response := streamingChunk(handler, status, 0, []byte("body"), legacy.Manifest.SHA256, "r"); response.Code != 409 {
		t.Fatal("canceled chunk accepted")
	}
}

func TestStreamingUploadConcurrentOpenAndChunks(t *testing.T) {
	body := bytes.Repeat([]byte("c"), chunkSize+3)
	input := streamingInput(body)
	app, handler := streamingApp(t, t.TempDir())
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for index := 0; index < 8; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			request := httptest.NewRequest(http.MethodPost, "/api/upload/open", bytes.NewReader(encoded))
			request.Header.Set("X-FT-Token", "token")
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != 200 {
				t.Error(response.Code, response.Body.String())
			}
		}()
	}
	workers.Wait()
	if t.Failed() {
		t.FailNow()
	}
	status, _ := app.getPuller().uploadStatus(input.Manifest.Path)
	for index := 0; index < 8; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			index %= 2
			chunk := body[index*chunkSize : min(len(body), (index+1)*chunkSize)]
			if response := streamingChunk(handler, status, index, chunk, sha256hex(chunk), "r"); response.Code != 200 {
				t.Error(response.Code, response.Body.String())
			}
		}(index)
	}
	workers.Wait()
	if t.Failed() {
		t.FailNow()
	}
	decodeUploadStatus(t, streamingFinish(t, handler, status, sha256hex(body)))
	awaitStatus(t, app.getPuller(), status.Path, "done")
}

func TestStreamingUploadReusesLegacyManifest(t *testing.T) {
	body := []byte("legacy manifest")
	input := streamingInput(body)
	input.Manifest.SHA256 = sha256hex(body)
	input.Manifest.ChunkHashes = []string{sha256hex(body)}
	app, handler := streamingApp(t, t.TempDir())
	legacy := decodeUploadStatus(t, uploadRequest(t, handler, "/api/upload/start", "token", input))
	input.Manifest.SHA256 = ""
	input.Manifest.ChunkHashes = nil
	status := decodeUploadStatus(t, uploadRequest(t, handler, "/api/upload/open", "token", input))
	if status.ID != legacy.ID || status.Generation != legacy.Generation {
		t.Fatal("legacy task was replaced", status)
	}
	changed := bytes.Repeat([]byte("x"), len(body))
	if response := streamingChunk(handler, status, 0, changed, sha256hex(changed), "r"); response.Code != 400 {
		t.Fatal("legacy manifest hashes no longer enforced", response.Code)
	}
	if response := streamingChunk(handler, status, 0, body, sha256hex(body), "r"); response.Code != 200 {
		t.Fatal(response.Code, response.Body.String())
	}
	decodeUploadStatus(t, streamingFinish(t, handler, status, sha256hex(body)))
	awaitStatus(t, app.getPuller(), status.Path, "done")
}

func TestStreamingUploadCanceledReopenRejectsOldGeneration(t *testing.T) {
	body := []byte("cancel and reopen")
	input := streamingInput(body)
	app, handler := streamingApp(t, t.TempDir())
	old := decodeUploadStatus(t, uploadRequest(t, handler, "/api/upload/open", "token", input))
	app.getPuller().cancelJob(old.Path)
	current := decodeUploadStatus(t, uploadRequest(t, handler, "/api/upload/open", "token", input))
	if current.Generation <= old.Generation {
		t.Fatal("generation reused after cancellation", current)
	}
	if response := streamingChunk(handler, old, 0, body, sha256hex(body), "r"); response.Code != 409 {
		t.Fatal("old generation accepted", response.Code)
	}
	if response := streamingChunk(handler, current, 0, body, sha256hex(body), "r"); response.Code != 200 {
		t.Fatal(response.Code, response.Body.String())
	}
}

func TestStreamingUploadOpenPersistenceFailure(t *testing.T) {
	input := streamingInput([]byte("must persist"))
	app, handler := streamingApp(t, t.TempDir())
	puller, _, err := app.acquirePuller("upload:"+input.Source, "", app.receiver.dest, "rename")
	if err != nil {
		t.Fatal(err)
	}
	if err := puller.root.Mkdir(cacheDirectory+"/"+puller.id+".jobs.json", 0700); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		response := uploadRequest(t, handler, "/api/upload/open", "token", input)
		if response.Code < 400 {
			t.Fatal("unpersisted task acknowledged", response.Code, response.Body.String())
		}
	}
}

func TestStreamingUploadAccessLayer(t *testing.T) {
	_, handler := streamingApp(t, t.TempDir())
	for _, endpoint := range []string{"/api/upload/open", "/api/upload/finish"} {
		if response := uploadRequest(t, handler, endpoint, "wrong", map[string]string{}); response.Code != 401 || strings.Contains(response.Body.String(), "admin_required") {
			t.Fatal("endpoint does not use receiver authentication", response.Code, response.Body.String())
		}
		request := httptest.NewRequest(http.MethodGet, endpoint, nil)
		request.Header.Set("X-FT-Token", "token")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusMethodNotAllowed {
			t.Fatal("write endpoint accepts GET", endpoint, response.Code)
		}
	}
}

func TestStreamingUploadCompletedTaskAcceptsNewVersion(t *testing.T) {
	app, handler := streamingApp(t, t.TempDir())
	for version, body := range [][]byte{[]byte("first version"), []byte("second version")} {
		input := streamingInput(body)
		input.Manifest.MTime += int64(version)
		status := decodeUploadStatus(t, uploadRequest(t, handler, "/api/upload/open", "token", input))
		if status.Status == "done" {
			t.Fatal("new version incorrectly treated as completed", version)
		}
		if response := streamingChunk(handler, status, 0, body, sha256hex(body), "r"); response.Code != 200 {
			t.Fatal(response.Code, response.Body.String())
		}
		decodeUploadStatus(t, streamingFinish(t, handler, status, sha256hex(body)))
		awaitStatus(t, app.getPuller(), status.Path, "done")
	}
	content, err := os.ReadFile(filepath.Join(app.receiver.dest, "stream/file (1).bin"))
	if err != nil || string(content) != "second version" {
		t.Fatal("renamed new version missing", err)
	}
}
