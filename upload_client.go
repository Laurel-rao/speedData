package main

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"
)

type uploadHTTPError struct {
	code    int
	message string
}

func (err *uploadHTTPError) Error() string { return fmt.Sprintf("HTTP %d: %s", err.code, err.message) }

type uploadTask struct {
	input      uploadStart
	id         string
	busy       bool
	done       bool
	retryAt    time.Time
	failures   int
	generation uint64
	streaming  bool
	finalSHA   string
}

type Uploader struct {
	mu         sync.Mutex
	queueMu    sync.Mutex
	tasks      []*uploadTask
	remote     string
	token      string
	password   string
	sourceID   string
	sender     *Sender
	app        *App
	client     *http.Client
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	chunkSlots chan struct{}
}

func (uploader *Uploader) Close() {
	uploader.cancel()
	uploader.wg.Wait()
	uploader.client.CloseIdleConnections()
}

func (app *App) beginUpload(remote, password string, sender *Sender, paths []string, extract bool, files int, totalBytes int64) (int, error) {
	info, err := authRemote(remote, password)
	if err != nil {
		return 0, err
	}
	host, err := os.Hostname()
	if err != nil {
		return 0, err
	}
	executable, err := os.Executable()
	if err != nil {
		return 0, err
	}
	sourceID := sha256hex([]byte(host + "\n" + executable + "\n" + strconv.Itoa(app.port)))
	app.mu.Lock()
	if app.uploaders == nil {
		app.uploaders = map[string]*Uploader{}
	}
	uploader := app.uploaders[remote]
	if uploader == nil {
		ctx, cancel := context.WithCancel(context.Background())
		uploader = &Uploader{remote: remote, sourceID: sourceID, sender: sender, app: app, client: &http.Client{Timeout: httpTimeout}, ctx: ctx, cancel: cancel, chunkSlots: make(chan struct{}, workerCount)}
		app.uploaders[remote] = uploader
		for index := 0; index < workerCount; index++ {
			uploader.wg.Add(1)
			go func() { defer uploader.wg.Done(); uploader.worker() }()
		}
	}
	app.mu.Unlock()
	uploader.setCredentials(info.Token, password)
	uploader.queueMu.Lock()
	defer uploader.queueMu.Unlock()
	added := 0
	for _, path := range paths {
		var status uploadStatus
		input, streaming, err := uploader.openStreaming(sender, sourceID, path, extract, files, totalBytes, &status)
		if err != nil {
			return added, fmt.Errorf("创建上传 %s 失败：%w", path, err)
		}
		if !streaming {
			manifest, manifestErr := sender.manifest(path)
			if manifestErr != nil {
				return added, manifestErr
			}
			input = uploadStart{Source: sourceID, Manifest: manifest, Extract: extract, Files: files, Bytes: totalBytes}
			if err := uploader.jsonRequest("/api/upload/start", input, &status); err != nil {
				return added, fmt.Errorf("创建上传 %s 失败：%w", path, err)
			}
		}
		if status.Status == "skipped" || status.Status == "done" {
			continue
		}
		uploader.mu.Lock()
		found := false
		for _, task := range uploader.tasks {
			if task.input.Manifest.Path == path && task.input.Manifest.SHA256 == input.Manifest.SHA256 && !task.done {
				found = true
				break
			}
		}
		if !found {
			uploader.tasks = append(uploader.tasks, &uploadTask{input: input, id: status.ID, generation: status.Generation, streaming: streaming})
		}
		uploader.mu.Unlock()
		added++
	}
	return added, nil
}

func (uploader *Uploader) openStreaming(sender *Sender, source, path string, extract bool, files int, totalBytes int64, status *uploadStatus) (uploadStart, bool, error) {
	file, err := sender.open(path)
	if err != nil {
		return uploadStart{}, false, err
	}
	info, err := file.Stat()
	file.Close()
	if err != nil {
		return uploadStart{}, false, err
	}
	manifest := Manifest{Path: path, Size: info.Size(), MTime: info.ModTime().Unix(), ChunkSize: chunkSize, NChunks: int((info.Size() + chunkSize - 1) / chunkSize)}
	input := uploadStart{Source: source, Manifest: manifest, Extract: extract, Files: files, Bytes: totalBytes}
	if err := uploader.jsonRequest("/api/upload/open", input, status); err != nil {
		var httpErr *uploadHTTPError
		if errors.As(err, &httpErr) && (httpErr.code == http.StatusNotFound || httpErr.code == http.StatusMethodNotAllowed || (httpErr.code == http.StatusUnauthorized && httpErr.message == "请先输入本机管理密码")) {
			return input, false, nil
		}
		return uploadStart{}, false, err
	}
	return input, true, nil
}

func (uploader *Uploader) setCredentials(token, password string) {
	uploader.mu.Lock()
	uploader.token = token
	uploader.password = password
	uploader.mu.Unlock()
	uploader.app.mu.Lock()
	if uploader.app.outgoing == nil {
		uploader.app.outgoing = map[string]*Monitor{}
	}
	uploader.app.outgoing[uploader.remote] = &Monitor{baseURL: uploader.remote, token: token, source: "upload:" + uploader.sourceID, client: &http.Client{Timeout: 5 * time.Second}}
	uploader.app.mu.Unlock()
}

func (uploader *Uploader) request(endpoint string, body []byte, mode string, out interface{}) error {
	request, err := http.NewRequestWithContext(uploader.ctx, http.MethodPost, uploader.remote+endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if mode != "" {
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set("X-Enc", mode)
	}
	uploader.mu.Lock()
	token := uploader.token
	uploader.mu.Unlock()
	request.Header.Set("X-FT-Token", token)
	response, err := uploader.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		var failure struct {
			Error string `json:"error"`
		}
		json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&failure)
		return &uploadHTTPError{code: response.StatusCode, message: failure.Error}
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(response.Body, maxJSONBytes)).Decode(out)
	}
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	return err
}

func (uploader *Uploader) jsonRequest(endpoint string, input, out interface{}) error {
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	return uploader.request(endpoint, body, "", out)
}

func (uploader *Uploader) worker() {
	for uploader.ctx.Err() == nil {
		uploader.mu.Lock()
		var selected *uploadTask
		for _, task := range uploader.tasks {
			if !task.busy && !task.done && !time.Now().Before(task.retryAt) {
				task.busy = true
				selected = task
				break
			}
		}
		uploader.mu.Unlock()
		if selected == nil {
			select {
			case <-uploader.ctx.Done():
				return
			case <-time.After(80 * time.Millisecond):
			}
			continue
		}
		done, delay := uploader.step(selected)
		uploader.mu.Lock()
		selected.busy = false
		selected.done = done
		selected.retryAt = time.Now().Add(delay)
		uploader.mu.Unlock()
	}
}

func (uploader *Uploader) step(task *uploadTask) (bool, time.Duration) {
	if task.streaming {
		return uploader.stepStreaming(task)
	}
	query := uploadQuery{ID: task.id, Path: task.input.Manifest.Path}
	var status uploadStatus
	err := uploader.jsonRequest("/api/upload/status", query, &status)
	if err != nil {
		var remoteError *uploadHTTPError
		if errors.As(err, &remoteError) {
			if remoteError.code == 401 {
				uploader.mu.Lock()
				password := uploader.password
				uploader.mu.Unlock()
				if info, authErr := authRemote(uploader.remote, password); authErr == nil {
					uploader.setCredentials(info.Token, password)
				}
			} else if remoteError.code == 404 {
				if startErr := uploader.jsonRequest("/api/upload/start", task.input, &status); startErr == nil {
					task.id = status.ID
					return status.Status == "done" || status.Status == "skipped", time.Second
				}
			}
		}
		return false, time.Second
	}
	if status.Status == "done" || status.Status == "skipped" {
		return true, 0
	}
	if status.Status != "pending" && status.Status != "active" {
		return false, time.Second
	}
	if task.generation != status.Generation {
		task.generation = status.Generation
		task.failures = 0
	}
	if len(status.Missing) == 0 {
		return false, 200 * time.Millisecond
	}
	var workers sync.WaitGroup
	failures := make(chan error, workerCount)
	for _, index := range status.Missing[:min(workerCount, len(status.Missing))] {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			select {
			case uploader.chunkSlots <- struct{}{}:
			case <-uploader.ctx.Done():
				failures <- uploader.ctx.Err()
				return
			}
			defer func() { <-uploader.chunkSlots }()
			body, mode, _, _, err := uploader.sender.chunk(task.input.Manifest.Path, index)
			if err == nil {
				values := url.Values{"id": {task.id}, "path": {task.input.Manifest.Path}, "index": {strconv.Itoa(index)}, "generation": {strconv.FormatUint(status.Generation, 10)}}
				err = uploader.request("/api/upload/chunk?"+values.Encode(), body, mode, nil)
			}
			if err != nil {
				failures <- err
			}
		}(index)
	}
	workers.Wait()
	close(failures)
	var failure error
	for err := range failures {
		failure = err
	}
	if failure != nil {
		var remoteError *uploadHTTPError
		if errors.As(failure, &remoteError) && (remoteError.code == 409 || remoteError.code == 401 || remoteError.code == 404) {
			return false, time.Second
		}
		task.failures++
		if task.failures >= maxRetries {
			query.Generation = status.Generation
			query.Error = failure.Error()
			uploader.jsonRequest("/api/upload/fail", query, nil)
		}
		return false, time.Second
	}
	task.failures = 0
	return false, 10 * time.Millisecond
}

func (uploader *Uploader) stepStreaming(task *uploadTask) (bool, time.Duration) {
	query := uploadQuery{ID: task.id, Path: task.input.Manifest.Path}
	var status uploadStatus
	if err := uploader.jsonRequest("/api/upload/status", query, &status); err != nil {
		return uploader.retryUploadStatus(task, err)
	}
	if status.Status == "done" || status.Status == "skipped" {
		return true, 0
	}
	if status.Status != "pending" && status.Status != "active" && status.Phase != "waiting_for_finish" {
		return false, time.Second
	}
	if task.generation != status.Generation {
		task.generation = status.Generation
		task.failures = 0
	}
	if len(status.Missing) > 0 {
		failures := make(chan error, len(status.Missing[:min(workerCount, len(status.Missing))]))
		var workers sync.WaitGroup
		for _, index := range status.Missing[:min(workerCount, len(status.Missing))] {
			workers.Add(1)
			go func(index int) {
				defer workers.Done()
				select {
				case uploader.chunkSlots <- struct{}{}:
				case <-uploader.ctx.Done():
					failures <- uploader.ctx.Err()
					return
				}
				defer func() { <-uploader.chunkSlots }()
				body, mode, digest, err := uploader.streamChunk(task.input.Manifest.Path, index)
				if err == nil {
					values := url.Values{"id": {task.id}, "path": {task.input.Manifest.Path}, "index": {strconv.Itoa(index)}, "generation": {strconv.FormatUint(status.Generation, 10)}, "chunk_sha256": {digest}}
					err = uploader.request("/api/upload/chunk?"+values.Encode(), body, mode, nil)
				}
				if err != nil {
					failures <- err
				}
			}(index)
		}
		workers.Wait()
		close(failures)
		for err := range failures {
			task.failures++
			if task.failures >= maxRetries {
				query.Generation, query.Error = status.Generation, err.Error()
				_ = uploader.jsonRequest("/api/upload/fail", query, nil)
			}
			return false, time.Second
		}
		task.failures = 0
		return false, 10 * time.Millisecond
	}
	if task.finalSHA == "" {
		digest, err := uploader.sender.fileDigest(task.input.Manifest.Path)
		if err != nil {
			return false, time.Second
		}
		task.finalSHA = digest
	}
	finish := uploadFinish{ID: task.id, Path: task.input.Manifest.Path, Generation: status.Generation, SHA256: task.finalSHA}
	if err := uploader.jsonRequest("/api/upload/finish", finish, &status); err != nil {
		return false, time.Second
	}
	return status.Status == "done", 200 * time.Millisecond
}

func (uploader *Uploader) retryUploadStatus(task *uploadTask, err error) (bool, time.Duration) {
	var remoteError *uploadHTTPError
	if errors.As(err, &remoteError) && remoteError.code == http.StatusUnauthorized {
		uploader.mu.Lock()
		password := uploader.password
		uploader.mu.Unlock()
		if info, authErr := authRemote(uploader.remote, password); authErr == nil {
			uploader.setCredentials(info.Token, password)
		}
	}
	if errors.As(err, &remoteError) && remoteError.code == http.StatusNotFound {
		var status uploadStatus
		if startErr := uploader.jsonRequest("/api/upload/open", task.input, &status); startErr == nil {
			task.id, task.generation = status.ID, status.Generation
			return status.Status == "done" || status.Status == "skipped", time.Second
		}
	}
	return false, time.Second
}

func (uploader *Uploader) streamChunk(path string, index int) ([]byte, string, string, error) {
	file, err := uploader.sender.open(path)
	if err != nil {
		return nil, "", "", err
	}
	defer file.Close()
	if _, err := file.Seek(int64(index)*chunkSize, io.SeekStart); err != nil {
		return nil, "", "", err
	}
	raw := make([]byte, chunkSize)
	count, err := io.ReadFull(file, raw)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, "", "", err
	}
	raw = raw[:count]
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	if len(raw) == 0 {
		return raw, "r", digest, nil
	}
	var compressed bytes.Buffer
	writer, err := zlib.NewWriterLevel(&compressed, 6)
	if err != nil {
		return nil, "", "", err
	}
	if _, err = writer.Write(raw); err != nil {
		writer.Close()
		return nil, "", "", err
	}
	if err = writer.Close(); err != nil {
		return nil, "", "", err
	}
	if compressed.Len() < len(raw) {
		return compressed.Bytes(), "z", digest, nil
	}
	return raw, "r", digest, nil
}

func (sender *Sender) fileDigest(path string) (string, error) {
	file, err := sender.open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}
