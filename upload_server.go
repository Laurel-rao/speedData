package main

import (
	"bytes"
	"compress/zlib"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

type uploadStart struct {
	Source   string   `json:"source"`
	Manifest Manifest `json:"manifest"`
	Extract  bool     `json:"extract"`
	Files    int      `json:"files"`
	Bytes    int64    `json:"bytes"`
}

type uploadQuery struct {
	ID         string `json:"id"`
	Path       string `json:"path"`
	Generation uint64 `json:"generation"`
	Error      string `json:"error,omitempty"`
}

type uploadStatus struct {
	ID            string `json:"id"`
	Path          string `json:"path"`
	Status        string `json:"status"`
	Generation    uint64 `json:"generation"`
	Missing       []int  `json:"missing"`
	Chunks        int    `json:"chunks"`
	DoneChunks    int    `json:"done_chunks"`
	BytesDone     int64  `json:"bytes_done"`
	BytesTotal    int64  `json:"bytes_total"`
	MissingChunks int    `json:"missing_chunks"`
	Phase         string `json:"phase"`
	Error         string `json:"error,omitempty"`
}

func (app *App) uploadReceiver(response http.ResponseWriter, request *http.Request) *Receiver {
	app.mu.Lock()
	receiver := app.receiver
	app.mu.Unlock()
	if receiver == nil || receiver.token == "" || subtle.ConstantTimeCompare([]byte(request.Header.Get("X-FT-Token")), []byte(receiver.token)) != 1 {
		writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "接收授权失效，请重新连接接收服务器"})
		return nil
	}
	return receiver
}

func (app *App) uploadPuller(id, dest string) *Puller {
	for _, puller := range app.pullerList() {
		if puller.passive && puller.id == id && puller.dest == dest {
			return puller
		}
	}
	return nil
}

func (puller *Puller) uploadStatus(path string) (uploadStatus, bool) {
	puller.mu.Lock()
	defer puller.mu.Unlock()
	job := puller.jobs[path]
	if job == nil {
		return uploadStatus{}, false
	}
	status := uploadStatus{ID: puller.id, Path: path, Status: job.status, Generation: job.generation, Error: job.lastError, Missing: []int{}, Chunks: job.nChunks, BytesDone: job.bytesDone, BytesTotal: job.size}
	status.DoneChunks = len(job.done)
	switch job.status {
	case "pending":
		status.Phase = "waiting_for_chunks"
	case "active":
		status.Phase = "uploading_chunks"
	case "verifying":
		status.Phase = "verifying_file"
	case "finalizing":
		status.Phase = "finalizing_file"
	case "done":
		status.Phase = "completed"
	case "error":
		status.Phase = "failed"
	default:
		status.Phase = job.status
	}
	if job.streaming && job.sha256 == "" && len(job.done) == job.nChunks && (job.status == "pending" || job.status == "active") {
		status.Phase = "waiting_for_finish"
	}
	if job.status == "pending" || job.status == "active" {
		for job.uploadCursor < job.nChunks && job.done[job.uploadCursor] {
			job.uploadCursor++
		}
		for index := job.uploadCursor; index < job.nChunks && len(status.Missing) < 64; index++ {
			if !job.done[index] {
				status.Missing = append(status.Missing, index)
			}
		}
		status.MissingChunks = job.nChunks - status.DoneChunks
	}
	return status, true
}

func (app *App) uploadRoutes(mux *http.ServeMux) {
	app.streamingUploadRoutes(mux)
	mux.HandleFunc("/api/upload/start", func(response http.ResponseWriter, request *http.Request) {
		receiver := app.uploadReceiver(response, request)
		if receiver == nil {
			return
		}
		var input uploadStart
		if !decodeRequest(response, request, &input) {
			return
		}
		source, err := hex.DecodeString(input.Source)
		if err != nil || len(source) != 32 || input.Files < 0 || input.Bytes < 0 {
			writeJSON(response, 400, map[string]string{"error": "上传标识或压缩包参数无效"})
			return
		}
		if err := validateManifest(input.Manifest, input.Manifest.Path); err != nil {
			writeJSON(response, 400, map[string]string{"error": err.Error()})
			return
		}
		puller, _, err := app.acquirePuller("upload:"+input.Source, "", receiver.dest, receiver.policy)
		if err != nil {
			writeJSON(response, 400, map[string]string{"error": err.Error()})
			return
		}
		puller.restoreOnce.Do(func() {
			puller.restoreJobs()
			puller.cleanStale()
		})
		puller.mu.Lock()
		previous := puller.jobs[input.Manifest.Path]
		alreadyDone := previous != nil && !previous.streaming && previous.status == "done" && previous.sha256 == input.Manifest.SHA256 && previous.extract == input.Extract
		puller.mu.Unlock()
		if !alreadyDone {
			_, err = puller.addRecords([]string{input.Manifest.Path}, receiver.policy, input.Extract, input.Files, input.Bytes, input.Manifest)
			if err != nil {
				writeJSON(response, 400, map[string]string{"error": err.Error()})
				return
			}
		}
		status, exists := puller.uploadStatus(input.Manifest.Path)
		if !exists {
			status = uploadStatus{ID: puller.id, Path: input.Manifest.Path, Status: "skipped", Missing: []int{}}
		}
		puller.start()
		writeJSON(response, 200, status)
	})
	mux.HandleFunc("/api/upload/status", func(response http.ResponseWriter, request *http.Request) {
		receiver := app.uploadReceiver(response, request)
		if receiver == nil {
			return
		}
		var query uploadQuery
		if !decodeRequest(response, request, &query) {
			return
		}
		puller := app.uploadPuller(query.ID, receiver.dest)
		if puller != nil {
			if status, ok := puller.uploadStatus(query.Path); ok {
				writeJSON(response, 200, status)
				return
			}
		}
		writeJSON(response, 404, map[string]string{"error": "上传任务不存在，请重新提交清单"})
	})
	mux.HandleFunc("/api/upload/chunk", func(response http.ResponseWriter, request *http.Request) {
		receiver := app.uploadReceiver(response, request)
		if receiver == nil {
			return
		}
		query := request.URL.Query()
		puller := app.uploadPuller(query.Get("id"), receiver.dest)
		if puller == nil {
			writeJSON(response, 404, map[string]string{"error": "上传任务不存在"})
			return
		}
		index, err := strconv.Atoi(query.Get("index"))
		generation, generationErr := strconv.ParseUint(query.Get("generation"), 10, 64)
		if err != nil || generationErr != nil {
			writeJSON(response, 400, map[string]string{"error": "分块参数无效"})
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, chunkSize+1))
		if err != nil || len(body) > chunkSize {
			writeJSON(response, 413, map[string]string{"error": "分块过大或读取失败"})
			return
		}
		mode := request.Header.Get("X-Enc")
		if mode == "z" {
			reader, err := zlib.NewReader(bytes.NewReader(body))
			if err != nil {
				writeJSON(response, 400, map[string]string{"error": "压缩块无效"})
				return
			}
			body, err = io.ReadAll(io.LimitReader(reader, chunkSize+1))
			reader.Close()
			if err != nil || len(body) > chunkSize {
				writeJSON(response, 413, map[string]string{"error": "解压分块超限或损坏"})
				return
			}
		} else if mode != "r" {
			writeJSON(response, 400, map[string]string{"error": "未知分块编码"})
			return
		}
		code, err := puller.acceptChunk(query.Get("path"), index, generation, body, query.Get("chunk_sha256"))
		if err != nil {
			writeJSON(response, code, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(response, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/api/upload/fail", func(response http.ResponseWriter, request *http.Request) {
		receiver := app.uploadReceiver(response, request)
		if receiver == nil {
			return
		}
		var query uploadQuery
		if !decodeRequest(response, request, &query) {
			return
		}
		puller := app.uploadPuller(query.ID, receiver.dest)
		if puller == nil {
			writeJSON(response, 404, map[string]string{"error": "上传任务不存在"})
			return
		}
		puller.mu.Lock()
		job := puller.jobs[query.Path]
		puller.mu.Unlock()
		if job != nil {
			puller.fail(job, query.Generation, fmt.Errorf("发送端上传失败：%.1000s", query.Error), false)
		}
		writeJSON(response, 200, map[string]bool{"ok": true})
	})
}

func (puller *Puller) acceptChunk(path string, index int, generation uint64, body []byte, suppliedHashes ...string) (int, error) {
	puller.mu.Lock()
	job := puller.jobs[path]
	puller.mu.Unlock()
	if job == nil {
		return 404, errors.New("上传文件不存在")
	}
	job.ioMu.Lock()
	defer job.ioMu.Unlock()
	puller.mu.Lock()
	if puller.jobs[path] != job || job.generation != generation || job.ctx.Err() != nil || (job.status != "pending" && job.status != "active") {
		puller.mu.Unlock()
		return 409, errors.New("任务状态已改变，请刷新进度")
	}
	digest := sha256hex(body)
	supplied := ""
	if len(suppliedHashes) > 0 {
		supplied = suppliedHashes[0]
	}
	if index < 0 || index >= job.nChunks || int64(len(body)) != min(int64(job.chunkSize), job.size-int64(index)*int64(job.chunkSize)) || (job.streaming && supplied == "") || (supplied != "" && !sameUploadDigest(supplied, digest)) || (!job.streaming && digest != job.chunkHashes[index]) || (job.streaming && job.done[index] && digest != job.chunkHashes[index]) {
		puller.mu.Unlock()
		return 400, errors.New("分块索引、长度或哈希无效")
	}
	if job.done[index] {
		puller.mu.Unlock()
		return 200, nil
	}
	job.status = "active"
	puller.mu.Unlock()
	err := job.writeChunk(index, body)
	puller.mu.Lock()
	stale := puller.jobs[path] != job || job.generation != generation || job.ctx.Err() != nil
	if err == nil && !stale {
		if job.streaming {
			job.chunkHashes[index] = digest
		}
		job.done[index] = true
		job.bytesDone += int64(len(body))
		if len(job.done) == job.nChunks && job.sha256 != "" {
			job.status = "verifying"
		}
	}
	puller.mu.Unlock()
	if stale {
		return 409, errors.New("任务已暂停、取消或重新开始")
	}
	if err == nil {
		err = puller.saveMeta(job)
	}
	if err != nil {
		puller.fail(job, generation, err, false)
		return 500, err
	}
	return 200, nil
}
