package main

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeFixture(test *testing.T, path string, content []byte) {
	test.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		test.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0644); err != nil {
		test.Fatal(err)
	}
}

func zipFixture(test *testing.T, files map[string][]byte) []byte {
	test.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, content := range files {
		entry, err := writer.Create(name)
		if err != nil {
			test.Fatal(err)
		}
		if _, err := entry.Write(content); err != nil {
			test.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		test.Fatal(err)
	}
	return buffer.Bytes()
}

func sourceFixture(test *testing.T, files map[string][]byte) (*Sender, *httptest.Server, string) {
	test.Helper()
	dir := test.TempDir()
	for name, content := range files {
		writeFixture(test, filepath.Join(dir, name), content)
	}
	sender := NewSender("fixture-password")
	name, err := sender.addRoot(dir)
	if err != nil {
		test.Fatal(err)
	}
	app := &App{sender: sender}
	server := httptest.NewServer(newAppMux(app))
	test.Cleanup(func() { server.Close(); app.Close() })
	return sender, server, name
}

func pullerFixture(test *testing.T, sender *Sender, server *httptest.Server, dest, policy string) *Puller {
	test.Helper()
	puller := NewPuller(server.URL, sender.token, dest, policy)
	if puller.initErr != nil {
		test.Fatal(puller.initErr)
	}
	test.Cleanup(puller.Close)
	return puller
}

func awaitCondition(test *testing.T, predicate func() bool) {
	test.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	test.Fatal("condition did not become true before timeout")
}

func awaitStatus(test *testing.T, puller *Puller, path, wanted string) {
	test.Helper()
	awaitCondition(test, func() bool {
		puller.mu.Lock()
		defer puller.mu.Unlock()
		job := puller.jobs[path]
		if job == nil {
			return false
		}
		if job.status == "error" && wanted != "error" {
			test.Fatalf("unexpected error for %s: %s", path, job.lastError)
		}
		return job.status == wanted
	})
}

func requestFixture(test *testing.T, handler http.Handler, method, path, key string, payload interface{}) *httptest.ResponseRecorder {
	test.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		test.Fatal(err)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.RemoteAddr = "192.0.2.40:43123"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-FT-Admin", key)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestManagementAuthorization(t *testing.T) {
	app := &App{}
	handler := newAppMux(app)
	for _, route := range []string{"start-serve", "receive-config", "add-folder", "remove-folder", "push", "connect", "download", "pause", "resume", "cancel", "clean-cache", "pick-folder", "open-folder", "monitor", "state", "log", "info", "remote", "send-state"} {
		t.Run(route, func(t *testing.T) {
			response := requestFixture(t, handler, "POST", "/api/"+route, "", map[string]string{"password": "attacker", "folder": t.TempDir()})
			if response.Code != 401 {
				t.Fatalf("unauthorized status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	request := httptest.NewRequest("POST", "/api/start-serve", strings.NewReader(`{}`))
	request.Header.Set("X-FT-Admin", app.adminKey)
	request.Header.Set("Origin", "https://other.invalid")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 403 {
		t.Fatal("cross-origin administration accepted")
	}
	response = requestFixture(t, handler, "GET", "/api/session", app.adminKey, nil)
	if !strings.Contains(response.Body.String(), `"authorized":true`) {
		t.Fatal(response.Body.String())
	}
	response = requestFixture(t, handler, "GET", "/api/clean-cache", app.adminKey, nil)
	if response.Code != 405 {
		t.Fatal("mutation accepted through GET")
	}
}

func TestDefaultAdminPassword(t *testing.T) {
	for index := 0; index < 2; index++ {
		app := &App{}
		handler := newAppMux(app)
		if app.adminKey != "Admin@981" {
			t.Fatal("unexpected default management password")
		}
		for _, password := range []string{"", "admin@981", "incorrect", "Admin@981"} {
			response := requestFixture(t, handler, "GET", "/api/info", password, nil)
			want := http.StatusUnauthorized
			if password == "Admin@981" {
				want = http.StatusOK
			}
			if response.Code != want {
				t.Fatalf("authorization status=%d want=%d", response.Code, want)
			}
		}
	}
	custom := &App{adminKey: "explicit-test-password"}
	newAppMux(custom)
	if custom.adminKey != "explicit-test-password" {
		t.Fatal("explicit management password overwritten")
	}
}

func TestInvalidManagementJSONHasNoSideEffects(t *testing.T) {
	app := &App{}
	handler := newAppMux(app)
	for _, body := range []string{`{"password":"test","folders":["/tmp"]`, `{"password":"test"} {}`, `{"password":123}`} {
		request := httptest.NewRequest("POST", "/api/receive-config", strings.NewReader(body))
		request.Header.Set("X-FT-Admin", app.adminKey)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || app.receiver != nil {
			t.Fatalf("invalid JSON accepted: status=%d receiver=%v", response.Code, app.receiver)
		}
	}
}

func TestLoopbackCallbackAddress(t *testing.T) {
	for _, remote := range []string{"http://127.0.0.1:8600", "http://localhost:8600", "http://[::1]:8600"} {
		if got, err := callbackURL(remote, 8601); err != nil || got != "http://127.0.0.1:8601" {
			t.Fatalf("callback for %s: %s (%v)", remote, got, err)
		}
	}
}

func TestCallbackUsesReceiverRoute(t *testing.T) {
	for _, fixture := range []struct{ remote, target, local, expected string }{
		{"http://192.168.40.228:8600", "192.168.40.228:8600", "192.168.40.52", "http://192.168.40.52:8601"},
		{"https://receiver.example", "receiver.example:443", "192.168.100.52", "http://192.168.100.52:8601"},
		{"http://[fd00::228]:8600", "[fd00::228]:8600", "fd00::52", "http://[fd00::52]:8601"},
	} {
		got, err := callbackURLWithRoute(fixture.remote, 8601, func(address string) (net.IP, error) {
			if address != fixture.target {
				t.Fatalf("selected route to %q instead of %q", address, fixture.target)
			}
			return net.ParseIP(fixture.local), nil
		})
		if err != nil || got != fixture.expected {
			t.Fatalf("callback=%q expected=%q error=%v", got, fixture.expected, err)
		}
	}
}

func TestCallbackRouteFailureDoesNotAdvertiseDefaultIP(t *testing.T) {
	for _, routeErr := range []error{nil, errors.New("no route")} {
		got, err := callbackURLWithRoute("http://192.168.40.228:8600", 8601, func(address string) (net.IP, error) {
			return nil, routeErr
		})
		if err == nil || got != "" {
			t.Fatalf("advertised address despite route failure: %q %v", got, err)
		}
	}
}

func TestArchiveNestedWindowsDistribution(t *testing.T) {
	base := t.TempDir()
	name := "frp_0.62.0_windows_amd64/LICENSE"
	writeFixture(t, filepath.Join(base, filepath.FromSlash(name)), []byte("license fixture"))
	sender := NewSender("fixture")
	virtual, err := sender.addRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	archivePath, count, size, err := sender.buildArchive([]string{base})
	if err != nil || count != 1 || size != 15 {
		t.Fatalf("count=%d size=%d err=%v", count, size, err)
	}
	archive, err := zip.OpenReader(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	if len(archive.File) != 1 || archive.File[0].Name != virtual+"/"+name {
		t.Fatal("incorrect nested archive path")
	}
}

func TestElapsedClockStopsAndResumes(t *testing.T) {
	base := time.Unix(1700000000, 0)
	job := &FileJob{status: "pending"}
	puller := &Puller{jobs: map[string]*FileJob{"file": job}}
	puller.updateClock(base)
	job.status = "extracting"
	puller.updateClock(base.Add(3 * time.Second))
	if got := puller.elapsedSeconds(base.Add(5 * time.Second)); got != 5 {
		t.Fatalf("extraction not counted: %d", got)
	}
	job.status = "done"
	puller.updateClock(base.Add(6 * time.Second))
	if got := puller.elapsedSeconds(base.Add(time.Hour)); got != 6 {
		t.Fatalf("completed timer kept running: %d", got)
	}
	puller.jobs["second"] = &FileJob{status: "pending"}
	puller.updateClock(base.Add(time.Hour))
	if got := puller.elapsedSeconds(base.Add(time.Hour + 4*time.Second)); got != 10 {
		t.Fatalf("appending counted idle time or reset timer: %d", got)
	}
	for _, status := range []string{"paused", "canceled", "error"} {
		puller.jobs["second"].status = status
		puller.updateClock(base.Add(time.Hour + 4*time.Second))
		if got := puller.elapsedSeconds(base.Add(2 * time.Hour)); got != 10 {
			t.Fatalf("%s timer kept running: %d", status, got)
		}
	}
}

func TestCompletedTransferElapsedIsFrozen(t *testing.T) {
	sender, server, name := sourceFixture(t, map[string][]byte{"file.txt": []byte("timer fixture")})
	puller := pullerFixture(t, sender, server, t.TempDir(), "rename")
	rel := name + "/file.txt"
	if _, err := puller.addPaths([]string{rel}, "rename"); err != nil {
		t.Fatal(err)
	}
	puller.mu.Lock()
	puller.runningSince = time.Now().Add(-5 * time.Second)
	puller.mu.Unlock()
	puller.start()
	awaitStatus(t, puller, rel, "done")
	state := puller.state()
	puller.mu.Lock()
	defer puller.mu.Unlock()
	if !puller.runningSince.IsZero() || state["elapsed"] != puller.elapsedSeconds(time.Now().Add(time.Hour)) {
		t.Fatal("completion did not freeze the API clock")
	}
	if state["elapsed"].(int64) < 5 {
		t.Fatal("elapsed duration lost")
	}
}

func TestConcurrentDestinationCommits(t *testing.T) {
	root, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var workers sync.WaitGroup
	results := make(chan string, 16)
	for index := 0; index < 16; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			part := fmt.Sprintf("%s/source-%d", cacheDirectory, index)
			if err := root.WriteFile(part, []byte(fmt.Sprint(index)), 0600); err != nil {
				t.Error(err)
				return
			}
			target, _, err := commitFile(root, part, "same.txt", "rename")
			if err != nil {
				t.Error(err)
				return
			}
			results <- target
		}(index)
	}
	workers.Wait()
	close(results)
	seen := map[string]bool{}
	for target := range results {
		if seen[target] {
			t.Fatalf("target overwritten: %s", target)
		}
		seen[target] = true
	}
	if len(seen) != 16 {
		t.Fatalf("committed %d files", len(seen))
	}
}

func TestUnauthenticatedDirectoryExposureBlocked(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, filepath.Join(root, "private.txt"), []byte("private"))
	app := &App{}
	handler := newAppMux(app)
	response := requestFixture(t, handler, "POST", "/api/start-serve", "", map[string]interface{}{"folders": []string{root}, "password": "attacker"})
	if response.Code != 401 || app.sender != nil {
		t.Fatal("remote caller enabled sharing")
	}
	response = requestFixture(t, handler, "POST", "/api/start-serve", app.adminKey, map[string]interface{}{"folders": []string{root}, "password": "authorized"})
	if response.Code != 200 || app.sender == nil {
		t.Fatal(response.Body.String())
	}
	response = requestFixture(t, handler, "POST", "/api/receive-config", app.sender.token, map[string]string{"password": "attacker"})
	if response.Code != 401 {
		t.Fatal("transfer token grants administration")
	}
}

func TestDefaultDestination(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "chosen")
	app := &App{defaultDest: dest}
	handler := newAppMux(app)
	response := requestFixture(t, handler, "POST", "/api/receive-config", app.adminKey, map[string]string{"password": "receive", "policy": "rename"})
	if response.Code != 200 || app.receiver == nil || app.receiver.dest != dest {
		t.Fatalf("destination ignored: %s", response.Body.String())
	}
	response = requestFixture(t, handler, "GET", "/api/info", app.adminKey, nil)
	if !strings.Contains(response.Body.String(), dest) {
		t.Fatal("default not exposed to authorized UI")
	}
}

func TestRegularConflictPolicies(t *testing.T) {
	sender, server, name := sourceFixture(t, map[string][]byte{"file.txt": []byte("NEW")})
	for _, policy := range []string{"rename", "skip", "overwrite"} {
		t.Run(policy, func(t *testing.T) {
			dest := t.TempDir()
			rel := name + "/file.txt"
			target := filepath.Join(dest, rel)
			writeFixture(t, target, []byte("OLD"))
			puller := pullerFixture(t, sender, server, dest, policy)
			added, err := puller.addPaths([]string{rel}, policy)
			if err != nil {
				t.Fatal(err)
			}
			if policy == "skip" {
				if added != 0 {
					t.Fatal("skip queued existing file")
				}
			} else {
				puller.start()
				awaitStatus(t, puller, rel, "done")
			}
			content, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			want := "OLD"
			if policy == "overwrite" {
				want = "NEW"
			}
			if string(content) != want {
				t.Fatalf("expected %s got %s", want, content)
			}
			if policy == "rename" {
				renamed, err := os.ReadFile(filepath.Join(dest, name, "file (1).txt"))
				if err != nil || string(renamed) != "NEW" {
					t.Fatalf("renamed content=%s error=%v", renamed, err)
				}
			}
		})
	}
}

func TestArchiveConflictPolicies(t *testing.T) {
	archive := zipFixture(t, map[string][]byte{"docs/file.txt": []byte("NEW-CONTENT")})
	sender, server, name := sourceFixture(t, map[string][]byte{"incoming.zip": archive})
	for _, policy := range []string{"rename", "skip", "overwrite"} {
		t.Run(policy, func(t *testing.T) {
			dest := t.TempDir()
			target := filepath.Join(dest, "docs", "file.txt")
			writeFixture(t, target, []byte("ORIGINAL"))
			puller := pullerFixture(t, sender, server, dest, policy)
			rel := name + "/incoming.zip"
			if ok, err := puller.addArchive(rel, 1, 11, policy); !ok || err != nil {
				t.Fatalf("archive=%v error=%v", ok, err)
			}
			puller.start()
			awaitStatus(t, puller, rel, "done")
			content, _ := os.ReadFile(target)
			wanted := "ORIGINAL"
			if policy == "overwrite" {
				wanted = "NEW-CONTENT"
			}
			if string(content) != wanted {
				t.Fatalf("policy %s corrupted original: %s", policy, content)
			}
			if policy == "rename" {
				renamed, err := os.ReadFile(filepath.Join(dest, "docs", "file (1).txt"))
				if err != nil || string(renamed) != "NEW-CONTENT" {
					t.Fatalf("renamed=%s error=%v", renamed, err)
				}
			}
		})
	}
}

func TestEmptyFileAndPayloadCacheSuffix(t *testing.T) {
	sender, server, name := sourceFixture(t, map[string][]byte{"empty.txt": nil, "asset.part": []byte("real-payload"), "asset.part.json": []byte("also-payload")})
	dest := t.TempDir()
	puller := pullerFixture(t, sender, server, dest, "rename")
	paths := []string{name + "/empty.txt", name + "/asset.part", name + "/asset.part.json"}
	if count, err := puller.addPaths(paths, ""); count != 3 || err != nil {
		t.Fatalf("added=%d error=%v", count, err)
	}
	puller.start()
	for _, path := range paths {
		awaitStatus(t, puller, path, "done")
	}
	puller.cleanCache()
	puller.cleanStale()
	for _, path := range paths {
		if _, err := os.Stat(filepath.Join(dest, path)); err != nil {
			t.Fatalf("payload missing %s: %v", path, err)
		}
	}
	if info, err := os.Stat(filepath.Join(dest, paths[0])); err != nil || info.Size() != 0 {
		t.Fatal("empty file not committed")
	}
}

func TestCleanCachePreservesUnownedFiles(t *testing.T) {
	dest := t.TempDir()
	writeFixture(t, filepath.Join(dest, "project", "asset.part"), []byte("user"))
	writeFixture(t, filepath.Join(dest, "asset.part.json"), []byte("user"))
	puller := NewPuller("http://127.0.0.1:1", "token", dest, "rename")
	defer puller.Close()
	if puller.initErr != nil {
		t.Fatal(puller.initErr)
	}
	if removed := puller.cleanCache(); removed != 0 {
		t.Fatalf("removed %d unowned files", removed)
	}
	unknown := filepath.Join(t.TempDir(), cacheDirectory)
	writeFixture(t, filepath.Join(unknown, "user.txt"), []byte("user"))
	other := NewPuller("http://127.0.0.1:1", "token", filepath.Dir(unknown), "rename")
	defer other.Close()
	if other.initErr == nil {
		t.Fatal("adopted an existing unowned cache directory")
	}
}

func TestSenderSymlinkBoundary(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	writeFixture(t, filepath.Join(outside, "secret.txt"), []byte("outside"))
	if err := os.Symlink(outside, filepath.Join(dir, "linked")); err != nil {
		t.Skip(err)
	}
	sender := NewSender("pw")
	name, err := sender.addRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sender.manifest(name + "/linked/secret.txt"); err == nil {
		t.Fatal("read escaped root")
	}
}

func TestReceiverSymlinkBoundary(t *testing.T) {
	archive := zipFixture(t, map[string][]byte{"linked/secret.txt": []byte("replace")})
	sender, server, name := sourceFixture(t, map[string][]byte{"incoming.zip": archive})
	dest, outside := t.TempDir(), t.TempDir()
	writeFixture(t, filepath.Join(outside, "secret.txt"), []byte("ORIGINAL"))
	if err := os.Symlink(outside, filepath.Join(dest, "linked")); err != nil {
		t.Skip(err)
	}
	puller := pullerFixture(t, sender, server, dest, "overwrite")
	rel := name + "/incoming.zip"
	if ok, err := puller.addArchive(rel, 1, 7, ""); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	puller.start()
	awaitStatus(t, puller, rel, "error")
	content, _ := os.ReadFile(filepath.Join(outside, "secret.txt"))
	if string(content) != "ORIGINAL" {
		t.Fatal("extraction escaped root")
	}
	if puller.state()["all_done"] == true {
		t.Fatal("failed extraction reported success")
	}
}

func TestArchiveTraversalRejected(t *testing.T) {
	for _, path := range []string{"../escape.txt", "/absolute.txt", cacheDirectory + "/owner", "docs/file.txt:stream"} {
		t.Run(path, func(t *testing.T) {
			archive := zipFixture(t, map[string][]byte{path: []byte("malicious")})
			sender, server, name := sourceFixture(t, map[string][]byte{"bad.zip": archive})
			puller := pullerFixture(t, sender, server, t.TempDir(), "overwrite")
			rel := name + "/bad.zip"
			if ok, err := puller.addArchive(rel, 1, 9, ""); !ok || err != nil {
				t.Fatalf("%v %v", ok, err)
			}
			puller.start()
			awaitStatus(t, puller, rel, "error")
		})
	}
}

func TestMalformedManifestRejected(t *testing.T) {
	valid := Manifest{Path: "file.bin", Size: 1, ChunkSize: chunkSize, NChunks: 1, SHA256: sha256hex([]byte("x")), ChunkHashes: []string{sha256hex([]byte("x"))}}
	for _, fault := range []string{"empty-hashes", "negative-size", "zero-chunk", "too-many", "wrong-count", "bad-hash", "different-path"} {
		t.Run(fault, func(t *testing.T) {
			manifest := valid
			switch fault {
			case "empty-hashes":
				manifest.ChunkHashes = nil
			case "negative-size":
				manifest.Size = -1
			case "zero-chunk":
				manifest.ChunkSize = 0
			case "too-many":
				manifest.NChunks = maxChunks + 1
			case "wrong-count":
				manifest.Size = chunkSize + 1
			case "bad-hash":
				manifest.SHA256 = "x"
			case "different-path":
				manifest.Path = "different.bin"
			}
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) { writeJSON(response, 200, manifest) }))
			defer server.Close()
			puller := NewPuller(server.URL, "token", t.TempDir(), "rename")
			defer puller.Close()
			if added, err := puller.addPaths([]string{"file.bin"}, ""); added != 0 || err == nil {
				t.Fatalf("malformed admitted: %d %v", added, err)
			}
			if len(puller.jobs) != 0 {
				t.Fatal("invalid job stored")
			}
		})
	}
}

func TestOversizedChunkRejected(t *testing.T) {
	var compressed bytes.Buffer
	writer := zlib.NewWriter(&compressed)
	writer.Write(bytes.Repeat([]byte("a"), chunkSize+1))
	writer.Close()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("X-Enc", "z")
		response.Write(compressed.Bytes())
	}))
	defer server.Close()
	puller := NewPuller(server.URL, "token", t.TempDir(), "rename")
	defer puller.Close()
	if _, err := puller.getChunk(context.Background(), "file.bin", 0); err == nil {
		t.Fatal("oversized inflated chunk accepted")
	}
}

func TestCancelInflightChunk(t *testing.T) {
	content := []byte("last chunk")
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/manifest" {
			writeJSON(response, 200, Manifest{Path: "one.txt", Size: int64(len(content)), ChunkSize: chunkSize, NChunks: 1, SHA256: sha256hex(content), ChunkHashes: []string{sha256hex(content)}})
			return
		}
		entered <- struct{}{}
		select {
		case <-release:
			response.Write(content)
		case <-request.Context().Done():
		}
	}))
	defer server.Close()
	dest := t.TempDir()
	puller := NewPuller(server.URL, "token", dest, "overwrite")
	defer puller.Close()
	if added, err := puller.addPaths([]string{"one.txt"}, ""); added != 1 || err != nil {
		t.Fatal(added, err)
	}
	puller.start()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not start")
	}
	puller.cancelJob("one.txt")
	close(release)
	awaitCondition(t, func() bool {
		puller.mu.Lock()
		defer puller.mu.Unlock()
		return len(puller.jobs["one.txt"].inflight) == 0
	})
	awaitStatus(t, puller, "one.txt", "canceled")
	if _, err := os.Stat(filepath.Join(dest, "one.txt")); !os.IsNotExist(err) {
		t.Fatal("canceled file was committed")
	}
}

func TestCancelBeforeFinalCommit(t *testing.T) {
	sender, server, name := sourceFixture(t, map[string][]byte{"empty": nil})
	puller := pullerFixture(t, sender, server, t.TempDir(), "overwrite")
	rel := name + "/empty"
	if _, err := puller.addPaths([]string{rel}, ""); err != nil {
		t.Fatal(err)
	}
	job := puller.jobs[rel]
	job.ioMu.Lock()
	finished := make(chan struct{})
	go func() { puller.finalizeReady(); close(finished) }()
	awaitStatus(t, puller, rel, "finalizing")
	puller.cancelJob(rel)
	job.ioMu.Unlock()
	<-finished
	awaitStatus(t, puller, rel, "canceled")
	if _, err := os.Stat(job.final); !os.IsNotExist(err) {
		t.Fatal("commit happened after cancellation")
	}
}

func TestRetryFailedCommit(t *testing.T) {
	sender, server, name := sourceFixture(t, map[string][]byte{"file.txt": []byte("correct")})
	dest := t.TempDir()
	rel := name + "/file.txt"
	if err := os.MkdirAll(filepath.Join(dest, rel), 0755); err != nil {
		t.Fatal(err)
	}
	puller := pullerFixture(t, sender, server, dest, "overwrite")
	if _, err := puller.addPaths([]string{rel}, ""); err != nil {
		t.Fatal(err)
	}
	puller.start()
	awaitStatus(t, puller, rel, "error")
	if err := os.Remove(filepath.Join(dest, rel)); err != nil {
		t.Fatal(err)
	}
	puller.resume(rel)
	awaitStatus(t, puller, rel, "done")
	content, _ := os.ReadFile(filepath.Join(dest, rel))
	if string(content) != "correct" {
		t.Fatal("retry did not commit correct bytes")
	}
}

func TestRetryFailedWholeHash(t *testing.T) {
	sender, server, name := sourceFixture(t, map[string][]byte{"file.txt": []byte("correct")})
	puller := pullerFixture(t, sender, server, t.TempDir(), "overwrite")
	rel := name + "/file.txt"
	if _, err := puller.addPaths([]string{rel}, ""); err != nil {
		t.Fatal(err)
	}
	job := puller.jobs[rel]
	writeFixture(t, job.part, []byte("invalid"))
	job.done[0] = true
	job.bytesDone = 7
	job.status = "verifying"
	puller.finalizeReady()
	awaitStatus(t, puller, rel, "error")
	puller.resume(rel)
	puller.start()
	awaitStatus(t, puller, rel, "done")
	content, _ := os.ReadFile(job.final)
	if string(content) != "correct" {
		t.Fatal("hash retry retained invalid chunks")
	}
}

func TestArchiveRestoreAndCachedArchive(t *testing.T) {
	archive := zipFixture(t, map[string][]byte{"docs/restored.txt": []byte("restored")})
	sender, server, name := sourceFixture(t, map[string][]byte{"incoming.zip": archive})
	rel := name + "/incoming.zip"
	for _, mode := range []string{"restart", "existing-zip"} {
		t.Run(mode, func(t *testing.T) {
			dest := t.TempDir()
			if mode == "restart" {
				first := NewPuller(server.URL, sender.token, dest, "rename")
				if ok, err := first.addArchive(rel, 1, 8, ""); !ok || err != nil {
					t.Fatal(ok, err)
				}
				job := first.jobs[rel]
				writeFixture(t, job.part, archive)
				job.done[0] = true
				job.bytesDone = int64(len(archive))
				if err := first.saveMeta(job); err != nil {
					t.Fatal(err)
				}
				first.saveJobs()
				first.Close()
			} else {
				writeFixture(t, filepath.Join(dest, rel), archive)
			}
			puller := pullerFixture(t, sender, server, dest, "rename")
			if mode == "restart" {
				if count := puller.restoreJobs(); count != 1 {
					t.Fatalf("restored %d", count)
				}
				if !puller.jobs[rel].extract {
					t.Fatal("archive semantics lost")
				}
			} else {
				if ok, err := puller.addArchive(rel, 1, 8, ""); !ok || err != nil {
					t.Fatal(ok, err)
				}
			}
			puller.start()
			awaitStatus(t, puller, rel, "done")
			content, _ := os.ReadFile(filepath.Join(dest, "docs", "restored.txt"))
			if string(content) != "restored" {
				t.Fatal("archive not extracted")
			}
		})
	}
}

func TestCorruptResumeMetadataRechecksChunks(t *testing.T) {
	sender, server, name := sourceFixture(t, map[string][]byte{"file.txt": []byte("correct")})
	dest := t.TempDir()
	rel := name + "/file.txt"
	first := NewPuller(server.URL, sender.token, dest, "rename")
	if _, err := first.addPaths([]string{rel}, ""); err != nil {
		t.Fatal(err)
	}
	job := first.jobs[rel]
	writeFixture(t, job.part, []byte("invalid"))
	job.done[0] = true
	job.bytesDone = 7
	if err := first.saveMeta(job); err != nil {
		t.Fatal(err)
	}
	first.saveJobs()
	first.Close()
	puller := pullerFixture(t, sender, server, dest, "rename")
	if puller.restoreJobs() != 1 {
		t.Fatal("restore failed")
	}
	if len(puller.jobs[rel].done) != 0 {
		t.Fatal("corrupt cached block trusted")
	}
	puller.start()
	awaitStatus(t, puller, rel, "done")
}

func TestConsecutivePushesRetainTasks(t *testing.T) {
	sender, _, name := sourceFixture(t, map[string][]byte{"first.txt": []byte("first"), "next.txt": []byte("next")})
	app := &App{receiver: &Receiver{dest: t.TempDir(), password: "receive", token: "receive-token", policy: "rename"}}
	handler := newAppMux(app)
	server := httptest.NewServer(handler)
	defer server.Close()
	defer app.Close()
	sending := &App{sender: sender}
	defer sending.Close()
	var original *Puller
	for _, file := range []string{"first.txt", "next.txt"} {
		if _, err := sending.beginUpload(server.URL, "receive", sender, []string{name + "/" + file}, false, 1, 0); err != nil {
			t.Fatal(err)
		}
		if original == nil {
			original = app.getPuller()
		} else if original != app.getPuller() {
			t.Fatal("active puller replaced")
		}
	}
	awaitStatus(t, original, name+"/first.txt", "done")
	awaitStatus(t, original, name+"/next.txt", "done")
	if app.receiveState("")["total"] != 2 {
		t.Fatal("previous jobs disappeared")
	}
}

func TestMultipleSendersAndGlobalControls(t *testing.T) {
	app := &App{receiver: &Receiver{dest: t.TempDir(), password: "receive", token: "token", policy: "rename"}}
	handler := newAppMux(app)
	defer app.Close()
	for index := 0; index < 2; index++ {
		sender, server, name := sourceFixture(t, map[string][]byte{"file.txt": []byte(fmt.Sprint(index))})
		puller, _, err := app.acquirePuller(server.URL, sender.token, app.receiver.dest, "rename")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := puller.addPaths([]string{name + "/file.txt"}, ""); err != nil {
			t.Fatal(err)
		}
	}
	response := requestFixture(t, handler, "POST", "/api/pause", app.adminKey, map[string]string{"path": ""})
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	state := app.receiveState("")
	files := state["files"].([]map[string]interface{})
	if len(files) != 2 || files[0]["id"] == files[1]["id"] {
		t.Fatal("sender task identities overlap")
	}
	for _, file := range files {
		if file["status"] != "paused" {
			t.Fatal("global pause missed a sender")
		}
	}
	requestFixture(t, handler, "POST", "/api/resume", app.adminKey, map[string]string{"path": files[0]["id"].(string)})
	state = app.receiveState("")
	files = state["files"].([]map[string]interface{})
	if files[0]["status"] != "pending" || files[1]["status"] != "paused" {
		t.Fatal("per-task control crossed sender boundary")
	}
}

func TestSenderStatsConcurrentSnapshot(t *testing.T) {
	sender := NewSender("fixture")
	var group sync.WaitGroup
	group.Add(1)
	go func() {
		defer group.Done()
		for index := 0; index < 5000; index++ {
			sender.stats.add(fmt.Sprintf("file-%d", index%5), 1, 1, 10000)
		}
	}()
	for index := 0; index < 5000; index++ {
		if _, err := json.Marshal(sender.stats.snapshot()); err != nil {
			t.Fatal(err)
		}
	}
	group.Wait()
}

func TestParallelTransferAndSnapshot(t *testing.T) {
	content := bytes.Repeat([]byte("aBcDeFgH"), (chunkSize*5+128)/8)
	sender, server, name := sourceFixture(t, map[string][]byte{"large.bin": content})
	puller := pullerFixture(t, sender, server, t.TempDir(), "overwrite")
	rel := name + "/large.bin"
	if _, err := puller.addPaths([]string{rel}, ""); err != nil {
		t.Fatal(err)
	}
	puller.start()
	awaitCondition(t, func() bool {
		state := puller.state()
		if _, err := json.Marshal(state); err != nil {
			t.Fatal(err)
		}
		if state["errors"].(int) > 0 {
			t.Fatalf("transfer failed: %v", state)
		}
		return state["all_done"] == true
	})
	actual, err := os.ReadFile(filepath.Join(puller.dest, rel))
	if err != nil || !bytes.Equal(actual, content) {
		t.Fatal("parallel transfer integrity failure", err)
	}
}

func TestArchiveSnapshotConcurrent(t *testing.T) {
	files := map[string][]byte{}
	for index := 0; index < 80; index++ {
		files[fmt.Sprintf("docs/%d.txt", index)] = bytes.Repeat([]byte("test"), 100)
	}
	archive := zipFixture(t, files)
	sender, server, name := sourceFixture(t, map[string][]byte{"archive.zip": archive})
	puller := pullerFixture(t, sender, server, t.TempDir(), "rename")
	rel := name + "/archive.zip"
	if ok, err := puller.addArchive(rel, len(files), 32000, ""); !ok || err != nil {
		t.Fatal(ok, err)
	}
	puller.start()
	awaitCondition(t, func() bool {
		state := puller.state()
		json.Marshal(state)
		if state["errors"].(int) > 0 {
			t.Fatal(state)
		}
		return state["all_done"] == true
	})
}

func TestUnreadableArchiveSourceFails(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	root := t.TempDir()
	if err := os.Symlink(filepath.Join(root, "missing"), filepath.Join(root, "unreadable.txt")); err != nil {
		t.Skip(err)
	}
	sender := NewSender("fixture")
	if _, err := sender.addRoot(root); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := sender.buildArchive([]string{root}); err == nil {
		t.Fatal("unreadable source silently archived")
	}
}

func TestStableArchiveIdentity(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	root := t.TempDir()
	writeFixture(t, filepath.Join(root, "file.txt"), []byte("stable"))
	sender := NewSender("fixture")
	sender.addRoot(root)
	first, _, _, err := sender.buildArchive([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	second, _, _, err := sender.buildArchive([]string{root})
	if err != nil || first != second {
		t.Fatal("identical re-push cannot resume archive", err)
	}
}

func TestMonitorDisconnectIsExplicit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) { http.Error(response, "offline", 503) }))
	defer server.Close()
	app := &App{monitor: &Monitor{baseURL: server.URL, token: "test", client: server.Client()}}
	handler := newAppMux(app)
	response := requestFixture(t, handler, "POST", "/api/monitor-state", app.adminKey, nil)
	var result map[string]interface{}
	json.Unmarshal(response.Body.Bytes(), &result)
	if result["connected"] != false || result["error"] == nil {
		t.Fatal("failure represented as connected", result)
	}
}

func TestSendProgressUsesReceiverBytes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("source") != "http://sender.invalid" {
			t.Error("sender filter missing")
		}
		writeJSON(response, 200, map[string]interface{}{"role": "receiver", "state": map[string]interface{}{"connected": true, "all_done": true, "total_bytes": 1222, "done_bytes": 1222, "total": 1, "done": 1, "active": 0, "files": []map[string]interface{}{{"id": "id", "path": "archive.zip", "status": "done", "size": 1222, "bytes_done": 1222}}, "archives": []archiveMeta{{Status: "done", TotalFiles: 1, TotalBytes: 1048576, DoneFiles: 1}}}})
	}))
	defer server.Close()
	app := &App{outgoing: map[string]*Monitor{server.URL: {baseURL: server.URL, source: "http://sender.invalid", token: "fixture", client: server.Client()}}}
	state := app.sendState()
	if state["all_done"] != true || state["active"] != 0 || state["total_bytes"] != state["done_bytes"] || state["total_bytes"] != int64(1222) {
		t.Fatalf("wrong compressed progress: %v", state)
	}
}

func TestMalformedRemoteURLDoesNotPanic(t *testing.T) {
	for _, address := range []string{"http://%", "http://", "ftp://example.invalid", "http://user:password@example.invalid", "http://example.invalid/path"} {
		if _, err := authRemote(address, "test"); err == nil {
			t.Fatalf("invalid URL accepted: %s", address)
		}
	}
}
