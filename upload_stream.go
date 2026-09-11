package main

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
)

type uploadFinish struct {
	ID         string `json:"id"`
	Path       string `json:"path"`
	Generation uint64 `json:"generation"`
	SHA256     string `json:"sha256"`
}

func sameUploadDigest(first, second string) bool {
	decoded, err := hex.DecodeString(first)
	return err == nil && len(decoded) == 32 && strings.EqualFold(first, second)
}

func validateStreamingManifest(man Manifest, rel string) error {
	path, err := incomingPath(man.Path)
	if err != nil || path != rel || man.Path != rel {
		return errors.New("文件清单路径不匹配")
	}
	if man.Size < 0 || man.ChunkSize != chunkSize || man.NChunks < 0 || man.NChunks > maxChunks || man.Size > int64(chunkSize)*maxChunks {
		return errors.New("非法文件大小或分块参数（单文件上限 1 TiB）")
	}
	count := int((man.Size + chunkSize - 1) / chunkSize)
	if man.NChunks != count || (len(man.ChunkHashes) != 0 && len(man.ChunkHashes) != count) {
		return errors.New("文件清单分块数量不一致")
	}
	for _, digest := range append([]string{man.SHA256}, man.ChunkHashes...) {
		if digest != "" && !sameUploadDigest(digest, digest) {
			return errors.New("文件清单哈希无效")
		}
	}
	if man.Size == 0 && man.SHA256 != "" && !sameUploadDigest(man.SHA256, sha256hex(nil)) {
		return errors.New("空文件哈希无效")
	}
	return nil
}

func (app *App) streamingUploadRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/upload/open", func(response http.ResponseWriter, request *http.Request) {
		receiver := app.uploadReceiver(response, request)
		if receiver == nil {
			return
		}
		var input uploadStart
		if !decodeRequest(response, request, &input) {
			return
		}
		if !sameUploadDigest(input.Source, input.Source) || input.Files < 0 || input.Bytes < 0 {
			writeJSON(response, 400, map[string]string{"error": "上传标识或压缩包参数无效"})
			return
		}
		input.Manifest.SHA256 = strings.ToLower(input.Manifest.SHA256)
		if err := validateStreamingManifest(input.Manifest, input.Manifest.Path); err != nil {
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
		_, err = puller.addRecordsMode([]string{input.Manifest.Path}, receiver.policy, input.Extract, input.Files, input.Bytes, true, input.Manifest)
		if err != nil {
			writeJSON(response, 400, map[string]string{"error": err.Error()})
			return
		}
		status, exists := puller.uploadStatus(input.Manifest.Path)
		if !exists {
			writeJSON(response, 500, map[string]string{"error": "上传任务创建失败"})
			return
		}
		puller.start()
		writeJSON(response, 200, status)
	})
	mux.HandleFunc("/api/upload/finish", func(response http.ResponseWriter, request *http.Request) {
		receiver := app.uploadReceiver(response, request)
		if receiver == nil {
			return
		}
		var input uploadFinish
		if !decodeRequest(response, request, &input) {
			return
		}
		if !sameUploadDigest(input.SHA256, input.SHA256) {
			writeJSON(response, 400, map[string]string{"error": "整文件 SHA256 无效"})
			return
		}
		puller := app.uploadPuller(input.ID, receiver.dest)
		if puller == nil {
			writeJSON(response, 404, map[string]string{"error": "上传任务不存在，请重新打开任务"})
			return
		}
		code, err := puller.finishUpload(input)
		if err != nil {
			writeJSON(response, code, map[string]string{"error": err.Error()})
			return
		}
		status, _ := puller.uploadStatus(input.Path)
		writeJSON(response, 200, status)
	})
}

func (puller *Puller) finishUpload(input uploadFinish) (int, error) {
	puller.mu.Lock()
	job := puller.jobs[input.Path]
	puller.mu.Unlock()
	if job == nil {
		return 404, errors.New("上传文件不存在")
	}
	job.ioMu.Lock()
	defer job.ioMu.Unlock()
	puller.mu.Lock()
	if puller.jobs[input.Path] != job || job.generation != input.Generation || job.ctx.Err() != nil || (job.status != "pending" && job.status != "active" && job.status != "verifying" && job.status != "finalizing" && job.status != "extracting" && job.status != "done") {
		puller.mu.Unlock()
		return 409, errors.New("任务状态已改变，请刷新进度")
	}
	if len(job.done) != job.nChunks || (job.sha256 != "" && !sameUploadDigest(input.SHA256, job.sha256)) {
		puller.mu.Unlock()
		return 409, errors.New("分块尚未全部上传或整文件 SHA256 冲突")
	}
	if job.status == "done" || job.status == "verifying" || job.status == "finalizing" || job.status == "extracting" {
		puller.mu.Unlock()
		return 200, nil
	}
	job.sha256 = strings.ToLower(input.SHA256)
	puller.mu.Unlock()
	if err := puller.saveMeta(job); err != nil {
		puller.fail(job, input.Generation, err, false)
		return 500, err
	}
	if err := puller.saveJobs(); err != nil {
		puller.fail(job, input.Generation, err, false)
		return 500, err
	}
	puller.mu.Lock()
	defer puller.mu.Unlock()
	if job.generation != input.Generation || job.ctx.Err() != nil {
		return 409, errors.New("任务已暂停、取消或重新开始")
	}
	job.status = "verifying"
	return 200, nil
}
