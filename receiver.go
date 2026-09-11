package main

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxChunks = 262144
const maxJSONBytes = 32 << 20

type FileJob struct {
	path         string
	size         int64
	mtime        int64
	chunkSize    int
	nChunks      int
	sha256       string
	chunkHashes  []string
	streaming    bool
	final        string
	finalRel     string
	part         string
	meta         string
	partName     string
	metaName     string
	done         map[int]bool
	inflight     map[int]bool
	uploadCursor int
	status       string
	bytesDone    int64
	errors       int
	retries      int
	retryAfter   time.Time
	lastError    string
	startedAt    time.Time
	extract      bool
	policy       string
	archive      *archiveMeta
	extracted    map[string]bool
	root         *os.Root
	ioMu         sync.Mutex
	generation   uint64
	ctx          context.Context
	cancel       context.CancelFunc
}

type archiveMeta struct {
	Status     string   `json:"status"`
	TotalFiles int      `json:"total_files"`
	TotalBytes int64    `json:"total_bytes"`
	DoneFiles  int      `json:"done_files"`
	Current    []string `json:"current"`
	Error      string   `json:"error"`
}

type speedSample struct {
	t     time.Time
	bytes int64
}

type Puller struct {
	baseURL         string
	token           string
	dest            string
	policy          string
	id              string
	startedAt       time.Time
	elapsedDuration time.Duration
	runningSince    time.Time
	mu              sync.Mutex
	queueMu         sync.Mutex
	persistMu       sync.Mutex
	restoring       bool
	jobs            map[string]*FileJob
	passive         bool
	client          *http.Client
	speed           float64
	samples         []speedSample
	root            *os.Root
	initErr         error
	ctx             context.Context
	cancel          context.CancelFunc
	startOnce       sync.Once
	restoreOnce     sync.Once
	closeOnce       sync.Once
	wg              sync.WaitGroup
}

type jobRecord struct {
	Path      string    `json:"path"`
	Policy    string    `json:"policy"`
	Extract   bool      `json:"extract"`
	Files     int       `json:"files"`
	Bytes     int64     `json:"bytes"`
	Manifest  *Manifest `json:"manifest,omitempty"`
	Streaming bool      `json:"streaming,omitempty"`
}

type chunkWork struct {
	job        *FileJob
	index      int
	generation uint64
	ctx        context.Context
}

func validPolicy(policy string) bool {
	return policy == "" || policy == "rename" || policy == "skip" || policy == "overwrite"
}

func validateManifest(man Manifest, rel string) error {
	path, err := incomingPath(man.Path)
	if err != nil || path != rel || man.Path != rel {
		return errors.New("文件清单路径不匹配")
	}
	if man.Size < 0 || man.ChunkSize != chunkSize || man.NChunks < 0 || man.NChunks > maxChunks || man.Size > int64(chunkSize)*maxChunks {
		return errors.New("非法文件大小或分块参数（单文件上限 1 TiB）")
	}
	count := int((man.Size + chunkSize - 1) / chunkSize)
	if count != man.NChunks || len(man.ChunkHashes) != count {
		return errors.New("文件清单分块数量不一致")
	}
	for _, digest := range append([]string{man.SHA256}, man.ChunkHashes...) {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != 32 {
			return errors.New("文件清单哈希无效")
		}
	}
	if man.Size == 0 && man.SHA256 != sha256hex(nil) {
		return errors.New("空文件哈希无效")
	}
	return nil
}

func NewPuller(baseURL, token, dest, policy string) *Puller {
	if policy == "" {
		policy = "rename"
	}
	abs, err := filepath.Abs(dest)
	if err != nil {
		abs = dest
	}
	ctx, cancel := context.WithCancel(context.Background())
	puller := &Puller{baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"), token: token, dest: abs, policy: policy, startedAt: time.Now(), jobs: map[string]*FileJob{}, client: &http.Client{Timeout: httpTimeout}, ctx: ctx, cancel: cancel}
	puller.id = sha256hex([]byte(puller.baseURL + "\n" + abs))[:24]
	puller.passive = strings.HasPrefix(puller.baseURL, "upload:")
	puller.root, puller.initErr = openStore(abs)
	return puller
}

func (p *Puller) Close() {
	p.closeOnce.Do(func() {
		p.cancel()
		p.wg.Wait()
		p.client.CloseIdleConnections()
		if p.root != nil {
			p.root.Close()
		}
	})
}

func (p *Puller) getJSON(endpoint string, query url.Values, out interface{}) error {
	p.mu.Lock()
	query.Set("token", p.token)
	p.mu.Unlock()
	request, err := http.NewRequestWithContext(p.ctx, "GET", p.baseURL+endpoint+"?"+query.Encode(), nil)
	if err != nil {
		return err
	}
	response, err := p.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", response.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(response.Body, maxJSONBytes)).Decode(out)
}

func (p *Puller) getChunk(ctx context.Context, path string, index int) ([]byte, error) {
	p.mu.Lock()
	token := p.token
	p.mu.Unlock()
	query := url.Values{"token": {token}, "path": {path}, "idx": {strconv.Itoa(index)}}
	request, err := http.NewRequestWithContext(ctx, "GET", p.baseURL+"/api/chunk?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	response, err := p.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, chunkSize+1))
	if err != nil || len(body) > chunkSize {
		return nil, errors.New("分块响应超过大小限制或读取失败")
	}
	if response.Header.Get("X-Enc") == "z" {
		reader, err := zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		body, err = io.ReadAll(io.LimitReader(reader, chunkSize+1))
		if err != nil || len(body) > chunkSize {
			return nil, errors.New("解压后的分块超过大小限制或损坏")
		}
	}
	return body, nil
}

func (p *Puller) remoteTree() ([]FileInfo, error) {
	var out struct {
		Files []FileInfo `json:"files"`
	}
	err := p.getJSON("/api/tree", url.Values{}, &out)
	return out.Files, err
}

func (j *FileJob) loadMeta() bool {
	data, err := j.root.ReadFile(j.metaName)
	if err != nil {
		return false
	}
	var meta struct {
		Size        int64           `json:"size"`
		SHA256      string          `json:"sha256"`
		Done        []int           `json:"done"`
		Extracted   map[string]bool `json:"extracted"`
		Streaming   bool            `json:"streaming"`
		ChunkHashes map[int]string  `json:"chunk_hashes"`
	}
	if json.Unmarshal(data, &meta) != nil || meta.Size != j.size || meta.Streaming != j.streaming || (!j.streaming && meta.SHA256 != j.sha256) {
		return false
	}
	file, err := j.root.Open(j.partName)
	if err != nil {
		return false
	}
	defer file.Close()
	buffer := make([]byte, j.chunkSize)
	for _, index := range meta.Done {
		if index < 0 || index >= j.nChunks || j.done[index] {
			continue
		}
		length := min(int64(j.chunkSize), j.size-int64(index)*int64(j.chunkSize))
		read, err := file.ReadAt(buffer[:int(length)], int64(index)*int64(j.chunkSize))
		expected := j.chunkHashes[index]
		if j.streaming {
			expected = meta.ChunkHashes[index]
		}
		if err == nil && int64(read) == length && sha256hex(buffer[:read]) == expected {
			j.chunkHashes[index] = expected
			j.done[index] = true
			j.bytesDone += length
		}
	}
	if len(j.done) == j.nChunks && meta.Extracted != nil {
		j.extracted = meta.Extracted
	}
	return true
}

func (p *Puller) saveMeta(j *FileJob) error {
	p.mu.Lock()
	done := make([]int, 0, len(j.done))
	hashes := make(map[int]string)
	for index := range j.done {
		done = append(done, index)
		if j.streaming {
			hashes[index] = j.chunkHashes[index]
		}
	}
	extracted := make(map[string]bool, len(j.extracted))
	for path, complete := range j.extracted {
		extracted[path] = complete
	}
	p.mu.Unlock()
	sort.Ints(done)
	data, err := json.Marshal(map[string]interface{}{"size": j.size, "sha256": j.sha256, "done": done, "extracted": extracted, "streaming": j.streaming, "chunk_hashes": hashes})
	if err != nil {
		return err
	}
	return rootAtomicWrite(j.root, j.metaName, data)
}

func (j *FileJob) writeChunk(index int, data []byte) error {
	file, err := j.root.OpenFile(j.partName, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err = file.WriteAt(data, int64(index)*int64(j.chunkSize)); err == nil {
		err = file.Sync()
	}
	return err
}

func (p *Puller) addPaths(paths []string, policy string) (int, error) {
	return p.addRecords(paths, policy, false, 0, 0)
}

func (p *Puller) addRecords(paths []string, policy string, extract bool, files int, totalBytes int64, supplied ...Manifest) (int, error) {
	return p.addRecordsMode(paths, policy, extract, files, totalBytes, false, supplied...)
}

func (p *Puller) addRecordsMode(paths []string, policy string, extract bool, files int, totalBytes int64, streaming bool, supplied ...Manifest) (int, error) {
	if p.initErr != nil {
		return 0, p.initErr
	}
	if !validPolicy(policy) {
		return 0, errors.New("未知同名文件策略")
	}
	p.queueMu.Lock()
	defer p.queueMu.Unlock()
	p.mu.Lock()
	if policy == "" {
		policy = p.policy
	}
	p.mu.Unlock()
	added := 0
	var failures []error
	for _, original := range paths {
		rel, err := incomingPath(original)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		var man Manifest
		if len(supplied) > 0 {
			man = supplied[0]
		} else if p.passive {
			err = errors.New("上传任务缺少文件清单")
		} else {
			err = p.getJSON("/api/manifest", url.Values{"path": {rel}}, &man)
		}
		if err == nil {
			if streaming && p.passive {
				err = validateStreamingManifest(man, rel)
			} else {
				err = validateManifest(man, rel)
			}
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", rel, err))
			continue
		}
		p.mu.Lock()
		previous := p.jobs[rel]
		busy := previous != nil && previous.status != "done" && previous.status != "canceled"
		conflict := previous != nil && ((!streaming && (previous.streaming || previous.sha256 != man.SHA256)) || (streaming && (previous.size != man.Size || previous.mtime != man.MTime || previous.extract != extract || (man.SHA256 != "" && previous.sha256 != man.SHA256))))
		if streaming && previous != nil && previous.status == "done" && !conflict {
			busy = true
		}
		generation := uint64(0)
		if streaming && previous != nil {
			generation = previous.generation + 1
		}
		p.mu.Unlock()
		if busy {
			if conflict {
				failures = append(failures, fmt.Errorf("%s 正在接收另一个版本", rel))
			}
			continue
		}
		if previous != nil {
			previous.cancel()
			previous.ioMu.Lock()
			previous.ioMu.Unlock()
		}
		if !extract && policy == "skip" {
			if info, err := p.root.Stat(rel); err == nil && info.Mode().IsRegular() {
				if p.passive {
					ctx, cancel := context.WithCancel(p.ctx)
					done := make(map[int]bool, man.NChunks)
					for index := 0; index < man.NChunks; index++ {
						done[index] = true
					}
					p.mu.Lock()
					p.jobs[rel] = &FileJob{path: rel, size: man.Size, mtime: man.MTime, streaming: streaming, bytesDone: man.Size, sha256: man.SHA256, chunkHashes: append([]string(nil), man.ChunkHashes...), chunkSize: man.ChunkSize, nChunks: man.NChunks, done: done, status: "done", policy: policy, ctx: ctx, cancel: cancel}
					p.updateClock(time.Now())
					p.mu.Unlock()
				}
				continue
			}
		}
		key := cacheDirectory + "/" + p.id + "-" + sha256hex([]byte(rel+"\n"+man.SHA256))
		if streaming {
			key = cacheDirectory + "/" + p.id + "-" + sha256hex([]byte(fmt.Sprintf("stream\n%s\n%d\n%d", rel, man.Size, man.MTime)))
		}
		ctx, cancel := context.WithCancel(p.ctx)
		job := &FileJob{path: rel, size: man.Size, mtime: man.MTime, chunkSize: man.ChunkSize, nChunks: man.NChunks, sha256: man.SHA256, chunkHashes: append([]string(nil), man.ChunkHashes...), final: filepath.Join(p.dest, filepath.FromSlash(rel)), finalRel: rel, partName: key + ".part", metaName: key + ".json", done: map[int]bool{}, inflight: map[int]bool{}, status: "pending", startedAt: time.Now(), extract: extract, policy: policy, extracted: map[string]bool{}, root: p.root, ctx: ctx, cancel: cancel}
		job.streaming = streaming
		job.generation = generation
		if streaming && len(job.chunkHashes) == 0 {
			job.chunkHashes = make([]string, man.NChunks)
		}
		job.part, job.meta = filepath.Join(p.dest, job.partName), filepath.Join(p.dest, job.metaName)
		if extract {
			job.archive = &archiveMeta{Status: "transferring", TotalFiles: files, TotalBytes: totalBytes}
		}
		loaded := job.loadMeta()
		if !loaded && extract {
			if existing, err := p.root.Open(rel); err == nil {
				info, statErr := existing.Stat()
				if statErr == nil && info.Mode().IsRegular() && info.Size() == man.Size {
					digest, digestErr := fileDigest(ctx, existing)
					if digestErr == nil && digest == man.SHA256 {
						existing.Seek(0, 0)
						part, openErr := p.root.OpenFile(job.partName, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
						if openErr == nil {
							_, copyErr := io.Copy(part, contextReader{ctx: ctx, reader: existing})
							closeErr := part.Close()
							if copyErr == nil && closeErr == nil {
								for index := 0; index < man.NChunks; index++ {
									job.done[index] = true
								}
								job.bytesDone = man.Size
								loaded = true
							}
						}
					}
				}
				existing.Close()
			}
		}
		need := job.size - job.bytesDone
		p.mu.Lock()
		for _, other := range p.jobs {
			if other.status != "done" && other.status != "canceled" {
				need += other.size - other.bytesDone
			}
		}
		p.mu.Unlock()
		if free, err := freeSpace(p.dest); err == nil && need+spaceMargin > int64(free) {
			cancel()
			failures = append(failures, errors.New("目标磁盘空间不足"))
			continue
		}
		flags := os.O_CREATE | os.O_WRONLY
		if !loaded {
			flags |= os.O_TRUNC
		}
		part, err := p.root.OpenFile(job.partName, flags, 0600)
		if err == nil {
			err = part.Truncate(job.size)
			closeErr := part.Close()
			if err == nil {
				err = closeErr
			}
		}
		if err != nil {
			cancel()
			failures = append(failures, err)
			continue
		}
		if len(job.done) == job.nChunks && job.sha256 != "" {
			job.status = "verifying"
		}
		p.mu.Lock()
		if previous != nil {
			previous.cancel()
		}
		p.jobs[rel] = job
		p.updateClock(time.Now())
		p.mu.Unlock()
		added++
	}
	if added > 0 || streaming {
		failures = append(failures, p.saveJobs())
	}
	return added, errors.Join(failures...)
}

func (p *Puller) addArchive(rel string, totalFiles int, totalBytes int64, policy string) (bool, error) {
	if totalFiles < 0 || totalBytes < 0 {
		return false, errors.New("压缩包统计参数无效")
	}
	count, err := p.addRecords([]string{rel}, policy, true, totalFiles, totalBytes)
	if count > 0 {
		return true, err
	}
	p.mu.Lock()
	job := p.jobs[rel]
	p.mu.Unlock()
	return job != nil && job.extract && err == nil, err
}

func (p *Puller) start() {
	p.startOnce.Do(func() {
		for index := 0; index < workerCount; index++ {
			p.wg.Add(1)
			go func() { defer p.wg.Done(); p.worker() }()
		}
	})
}

func (p *Puller) pick() *chunkWork {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.passive {
		return nil
	}
	for _, job := range p.jobs {
		if job.status != "pending" && job.status != "active" {
			continue
		}
		if len(job.done) == job.nChunks {
			job.status = "verifying"
			continue
		}
		if time.Now().Before(job.retryAfter) {
			continue
		}
		for index := 0; index < job.nChunks; index++ {
			if !job.done[index] && !job.inflight[index] {
				job.inflight[index] = true
				job.status = "active"
				return &chunkWork{job: job, index: index, generation: job.generation, ctx: job.ctx}
			}
		}
	}
	return nil
}

func (p *Puller) worker() {
	for p.ctx.Err() == nil {
		work := p.pick()
		if work == nil {
			p.finalizeReady()
			select {
			case <-p.ctx.Done():
				return
			case <-time.After(40 * time.Millisecond):
			}
			continue
		}
		job, index := work.job, work.index
		data, err := p.getChunk(work.ctx, job.path, index)
		expected := min(int64(job.chunkSize), job.size-int64(index)*int64(job.chunkSize))
		if err == nil && (int64(len(data)) != expected || sha256hex(data) != job.chunkHashes[index]) {
			err = errors.New("块大小或哈希校验失败")
		}
		job.ioMu.Lock()
		p.mu.Lock()
		stale := job.generation != work.generation || job.status == "canceled" || job.status == "paused" || job.status == "error"
		if stale && job.generation == work.generation {
			delete(job.inflight, index)
		}
		p.mu.Unlock()
		if stale {
			job.ioMu.Unlock()
			continue
		}
		if err == nil {
			err = job.writeChunk(index, data)
		}
		p.mu.Lock()
		if job.generation == work.generation {
			delete(job.inflight, index)
		}
		stale = job.generation != work.generation || job.status == "canceled" || job.status == "paused"
		if !stale {
			if err == nil {
				if !job.done[index] {
					job.done[index] = true
					job.bytesDone += int64(len(data))
				}
				job.errors = 0
				if len(job.done) == job.nChunks {
					job.status = "verifying"
				}
			} else if p.ctx.Err() == nil {
				job.errors++
				job.lastError = err.Error()
				if job.errors >= chunkMaxErrs {
					job.retries++
					job.errors = 0
					job.retryAfter = time.Now().Add(time.Duration(job.retries) * time.Second)
					if job.retries > maxRetries {
						job.status = "error"
					}
				}
			}
		}
		p.updateClock(time.Now())
		p.mu.Unlock()
		if !stale && err == nil {
			if saveErr := p.saveMeta(job); saveErr != nil {
				p.fail(job, work.generation, saveErr, false)
			}
		}
		job.ioMu.Unlock()
		p.finalizeReady()
	}
}

func (p *Puller) fail(job *FileJob, generation uint64, err error, reset bool) {
	p.mu.Lock()
	if job.generation == generation && job.status != "done" && job.status != "canceled" && job.status != "paused" && p.ctx.Err() == nil {
		job.status = "error"
		job.lastError = err.Error()
		if reset {
			job.done = map[int]bool{}
			job.uploadCursor = 0
			job.bytesDone = 0
			job.extracted = map[string]bool{}
			if job.streaming {
				job.chunkHashes = make([]string, job.nChunks)
				job.sha256 = ""
			}
		}
		if job.archive != nil {
			job.archive.Status = "error"
			job.archive.Error = err.Error()
		}
	}
	p.updateClock(time.Now())
	p.mu.Unlock()
}

func (p *Puller) finalizeReady() {
	p.mu.Lock()
	var ready []chunkWork
	for _, job := range p.jobs {
		if job.status == "verifying" && len(job.inflight) == 0 {
			job.status = "finalizing"
			ready = append(ready, chunkWork{job: job, generation: job.generation, ctx: job.ctx})
		}
	}
	p.mu.Unlock()
	for _, work := range ready {
		p.finalize(work)
	}
}

func (p *Puller) finalize(work chunkWork) {
	job := work.job
	job.ioMu.Lock()
	defer job.ioMu.Unlock()
	file, err := p.root.Open(job.partName)
	if err == nil {
		var digest string
		digest, err = fileDigest(work.ctx, file)
		file.Close()
		if err == nil && digest != job.sha256 {
			err = errors.New("整文件校验失败")
			p.fail(job, work.generation, err, true)
			if saveErr := p.saveMeta(job); saveErr != nil {
				err = errors.Join(err, saveErr)
			}
		}
	}
	if err == nil && job.extract {
		err = p.runExtract(work)
	}
	if err == nil && !job.extract {
		lock := storageLock(p.dest)
		lock.Lock()
		p.mu.Lock()
		if job.generation != work.generation || job.status == "canceled" || job.status == "paused" || work.ctx.Err() != nil {
			err = context.Canceled
		} else {
			var target string
			target, _, err = commitFile(p.root, job.partName, job.finalRel, job.policy)
			if err == nil {
				job.finalRel = target
				job.final = filepath.Join(p.dest, target)
			}
		}
		p.mu.Unlock()
		lock.Unlock()
	}
	if err != nil {
		p.fail(job, work.generation, err, false)
	} else {
		p.mu.Lock()
		if job.generation == work.generation && job.status != "canceled" && job.status != "paused" {
			job.status = "done"
			job.bytesDone = job.size
			job.lastError = ""
			if job.archive != nil {
				job.archive.Status = "done"
			}
		}
		done := job.status == "done"
		p.updateClock(time.Now())
		p.mu.Unlock()
		if done {
			p.root.Remove(job.partName)
			p.root.Remove(job.metaName)
			if !job.extract && job.mtime > 0 {
				p.root.Chtimes(job.finalRel, time.Now(), time.Unix(job.mtime, 0))
			}
		}
	}
	p.logTransfer(job)
	p.saveJobs()
}

func (p *Puller) runExtract(work chunkWork) error {
	job := work.job
	file, err := p.root.Open(job.partName)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	archive, err := zip.NewReader(file, info.Size())
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	var total int64
	count := 0
	for _, entry := range archive.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		name, err := incomingPath(entry.Name)
		if err != nil || !entry.Mode().IsRegular() || seen[strings.ToLower(name)] {
			return fmt.Errorf("非法或重复压缩包条目：%s", entry.Name)
		}
		seen[strings.ToLower(name)] = true
		if entry.UncompressedSize64 > uint64(chunkSize)*maxChunks || uint64(total)+entry.UncompressedSize64 > uint64(chunkSize)*maxChunks {
			return errors.New("压缩包展开大小超过 1 TiB")
		}
		total += int64(entry.UncompressedSize64)
		count++
	}
	if free, err := freeSpace(p.dest); err == nil && total+spaceMargin > int64(free) {
		return errors.New("解压所需磁盘空间不足")
	}
	p.mu.Lock()
	if job.generation != work.generation || work.ctx.Err() != nil {
		p.mu.Unlock()
		return context.Canceled
	}
	job.status = "extracting"
	job.archive.Status = "extracting"
	job.archive.TotalFiles = count
	job.archive.TotalBytes = total
	job.archive.DoneFiles = len(job.extracted)
	p.mu.Unlock()
	for _, entry := range archive.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		name, _ := incomingPath(entry.Name)
		p.mu.Lock()
		complete := job.extracted[name]
		p.mu.Unlock()
		if complete {
			continue
		}
		if work.ctx.Err() != nil {
			return work.ctx.Err()
		}
		reader, err := entry.Open()
		if err != nil {
			return err
		}
		temp := cacheDirectory + "/" + p.id + "-" + sha256hex([]byte(job.path+"\n"+name)) + ".extract"
		output, err := p.root.OpenFile(temp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			reader.Close()
			return err
		}
		written, copyErr := io.Copy(output, contextReader{ctx: work.ctx, reader: io.LimitReader(reader, int64(entry.UncompressedSize64)+1)})
		if copyErr == nil && written != int64(entry.UncompressedSize64) {
			copyErr = errors.New("压缩包条目大小不匹配")
		}
		if copyErr == nil {
			copyErr = output.Sync()
		}
		closeErr := output.Close()
		reader.Close()
		if copyErr == nil {
			copyErr = closeErr
		}
		if copyErr != nil {
			p.root.Remove(temp)
			return copyErr
		}
		lock := storageLock(p.dest)
		lock.Lock()
		p.mu.Lock()
		if job.generation != work.generation || work.ctx.Err() != nil || job.status != "extracting" {
			p.mu.Unlock()
			lock.Unlock()
			p.root.Remove(temp)
			return context.Canceled
		}
		target, skipped, err := commitFile(p.root, temp, name, job.policy)
		if err == nil {
			job.extracted[name] = true
			job.archive.DoneFiles = len(job.extracted)
			job.archive.Current = append(job.archive.Current, name)
			if len(job.archive.Current) > 10 {
				job.archive.Current = job.archive.Current[len(job.archive.Current)-10:]
			}
		}
		p.mu.Unlock()
		lock.Unlock()
		p.root.Remove(temp)
		if err != nil {
			return fmt.Errorf("写入 %s 失败：%w", name, err)
		}
		if !skipped && !entry.Modified.IsZero() {
			p.root.Chtimes(target, time.Now(), entry.Modified)
		}
		if err := p.saveMeta(job); err != nil {
			return err
		}
	}
	return nil
}

func (p *Puller) logTransfer(job *FileJob) {
	p.mu.Lock()
	if job.status != "done" && job.status != "error" {
		p.mu.Unlock()
		return
	}
	record := map[string]interface{}{"time": time.Now().Format(time.RFC3339), "path": job.path, "dest": job.final, "size": job.size, "took": time.Since(job.startedAt).Round(time.Millisecond).String(), "result": job.status, "sha256": job.sha256, "error": job.lastError}
	p.mu.Unlock()
	data, err := json.Marshal(record)
	if err != nil {
		return
	}
	file, err := p.root.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		file.Write(append(data, '\n'))
		file.Close()
	}
}

func (p *Puller) readLog(count int) []string {
	if p.root == nil {
		return []string{}
	}
	file, err := p.root.Open(logFile)
	if err != nil {
		return []string{}
	}
	defer file.Close()
	if info, err := file.Stat(); err == nil && info.Size() > 1<<20 {
		file.Seek(info.Size()-(1<<20), io.SeekStart)
	}
	data, err := io.ReadAll(io.LimitReader(file, 1<<20))
	if err != nil {
		return []string{}
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return []string{}
	}
	if len(lines) > count {
		lines = lines[len(lines)-count:]
	}
	for left, right := 0, len(lines)-1; left < right; left, right = left+1, right-1 {
		lines[left], lines[right] = lines[right], lines[left]
	}
	return lines
}

func (p *Puller) saveJobs() error {
	if p.root == nil {
		return errors.New("接收存储尚未打开")
	}
	p.persistMu.Lock()
	defer p.persistMu.Unlock()
	p.mu.Lock()
	if p.restoring {
		p.mu.Unlock()
		return nil
	}
	var records []jobRecord
	for _, job := range p.jobs {
		if job.status == "done" || job.status == "canceled" {
			continue
		}
		record := jobRecord{Path: job.path, Policy: job.policy, Extract: job.extract, Streaming: job.streaming}
		if p.passive {
			record.Manifest = &Manifest{Path: job.path, Size: job.size, MTime: job.mtime, ChunkSize: job.chunkSize, NChunks: job.nChunks, SHA256: job.sha256, ChunkHashes: append([]string(nil), job.chunkHashes...)}
		}
		if job.archive != nil {
			record.Files = job.archive.TotalFiles
			record.Bytes = job.archive.TotalBytes
		}
		records = append(records, record)
	}
	p.mu.Unlock()
	sort.Slice(records, func(left, right int) bool { return records[left].Path < records[right].Path })
	data, err := json.Marshal(struct {
		URL  string      `json:"url"`
		Jobs []jobRecord `json:"jobs"`
	}{p.baseURL, records})
	if err == nil {
		err = rootAtomicWrite(p.root, cacheDirectory+"/"+p.id+".jobs.json", data)
	}
	return err
}

func (p *Puller) restoreJobs() int {
	if p.root == nil {
		return 0
	}
	data, err := p.root.ReadFile(cacheDirectory + "/" + p.id + ".jobs.json")
	if err != nil {
		return 0
	}
	var saved struct {
		URL  string      `json:"url"`
		Jobs []jobRecord `json:"jobs"`
	}
	if json.Unmarshal(data, &saved) != nil || saved.URL != p.baseURL {
		return 0
	}
	count := 0
	p.mu.Lock()
	p.restoring = true
	p.mu.Unlock()
	for _, record := range saved.Jobs {
		var supplied []Manifest
		if record.Manifest != nil {
			supplied = append(supplied, *record.Manifest)
		}
		added, _ := p.addRecordsMode([]string{record.Path}, record.Policy, record.Extract, record.Files, record.Bytes, record.Streaming, supplied...)
		count += added
	}
	p.mu.Lock()
	p.restoring = false
	p.mu.Unlock()
	return count
}

func (p *Puller) cleanStale() int { return p.cleanOwned(time.Now().Add(-tempMaxAge)) }
func (p *Puller) cleanCache() int { return p.cleanOwned(time.Time{}) }

func (p *Puller) cleanOwned(before time.Time) int {
	if p.root == nil {
		return 0
	}
	p.queueMu.Lock()
	defer p.queueMu.Unlock()
	p.mu.Lock()
	keep := map[string]bool{}
	for _, job := range p.jobs {
		if job.status != "done" && job.status != "canceled" {
			keep[job.partName] = true
			keep[job.metaName] = true
		}
	}
	p.mu.Unlock()
	dir, err := p.root.Open(cacheDirectory)
	if err != nil {
		return 0
	}
	entries, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return 0
	}
	removed := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, p.id+"-") || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		ext := filepath.Ext(name)
		key := strings.TrimSuffix(strings.TrimPrefix(name, p.id+"-"), ext)
		if ext != ".part" && ext != ".json" {
			continue
		}
		decoded, err := hex.DecodeString(key)
		if err != nil || len(decoded) != 32 {
			continue
		}
		rel := cacheDirectory + "/" + name
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || keep[rel] || (!before.IsZero() && !info.ModTime().Before(before)) {
			continue
		}
		if p.root.Remove(rel) == nil {
			removed++
		}
	}
	return removed
}

func (p *Puller) pause(path string)     { p.control("pause", path) }
func (p *Puller) resume(path string)    { p.control("resume", path) }
func (p *Puller) cancelJob(path string) { p.control("cancel", path) }

func (p *Puller) control(action, path string) {
	p.mu.Lock()
	for rel, job := range p.jobs {
		if path != "" && path != rel {
			continue
		}
		switch action {
		case "cancel", "pause":
			if job.status != "done" {
				job.cancel()
				if action == "cancel" {
					job.status = "canceled"
				} else if job.status != "canceled" {
					job.status = "paused"
				}
				if job.archive != nil {
					job.archive.Status = job.status
				}
			}
		case "resume":
			if job.status == "paused" || job.status == "error" || job.status == "canceled" {
				job.cancel()
				job.generation++
				job.ctx, job.cancel = context.WithCancel(p.ctx)
				job.inflight = map[int]bool{}
				job.status = "pending"
				job.errors = 0
				job.retries = 0
				job.retryAfter = time.Time{}
				job.lastError = ""
				if _, err := p.root.Stat(job.partName); err != nil {
					job.done = map[int]bool{}
					job.uploadCursor = 0
					job.bytesDone = 0
					job.extracted = map[string]bool{}
					p.root.WriteFile(job.partName, nil, 0600)
				}
				if len(job.done) == job.nChunks && job.sha256 != "" {
					job.status = "verifying"
				}
				if job.archive != nil {
					job.archive.Status = "transferring"
					job.archive.Error = ""
				}
			}
		}
	}
	p.updateClock(time.Now())
	p.mu.Unlock()
	p.saveJobs()
}

func (p *Puller) updateClock(now time.Time) {
	running := false
	for _, job := range p.jobs {
		switch job.status {
		case "pending", "active", "verifying", "finalizing", "extracting":
			running = true
		}
	}
	if running && p.runningSince.IsZero() {
		p.runningSince = now
	} else if !running && !p.runningSince.IsZero() {
		p.elapsedDuration += now.Sub(p.runningSince)
		p.runningSince = time.Time{}
	}
}

func (p *Puller) elapsedSeconds(now time.Time) int64 {
	elapsed := p.elapsedDuration
	if !p.runningSince.IsZero() {
		elapsed += now.Sub(p.runningSince)
	}
	return int64(elapsed.Seconds())
}

func (p *Puller) tickSpeed(doneBytes int64) {
	now := time.Now()
	p.samples = append(p.samples, speedSample{t: now, bytes: doneBytes})
	for len(p.samples) > 1 && p.samples[0].t.Before(now.Add(-3*time.Second)) {
		p.samples = p.samples[1:]
	}
	p.speed = 0
	if len(p.samples) > 1 {
		first := p.samples[0]
		if seconds := now.Sub(first.t).Seconds(); seconds > 0.2 {
			p.speed = max(0, float64(doneBytes-first.bytes)/seconds)
		}
	}
}

func (p *Puller) state() map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	var total, doneBytes int64
	pending, active, complete, failures := 0, 0, 0, 0
	allDone := len(p.jobs) > 0
	files := make([]map[string]interface{}, 0, len(p.jobs))
	archives := make([]archiveMeta, 0)
	for _, job := range p.jobs {
		total += job.size
		doneBytes += job.bytesDone
		switch job.status {
		case "done":
			complete++
		case "active", "verifying", "finalizing", "extracting":
			active++
		case "pending", "paused":
			pending++
		case "error":
			failures++
		}
		if job.status != "done" {
			allDone = false
		}
		progress := 0.0
		if job.size > 0 {
			progress = float64(job.bytesDone) / float64(job.size)
		} else if job.status == "done" {
			progress = 1
		}
		files = append(files, map[string]interface{}{"id": p.id + ":" + job.path, "path": job.path, "size": job.size, "status": job.status, "progress": progress, "bytes_done": job.bytesDone, "chunks": fmt.Sprintf("%d/%d", len(job.done), job.nChunks), "error": job.lastError, "retries": job.retries})
		if job.archive != nil {
			snapshot := *job.archive
			snapshot.Current = append([]string(nil), snapshot.Current...)
			archives = append(archives, snapshot)
		}
	}
	sort.Slice(files, func(left, right int) bool { return files[left]["path"].(string) < files[right]["path"].(string) })
	p.tickSpeed(doneBytes)
	if active == 0 && pending == 0 {
		p.speed = 0
	}
	result := map[string]interface{}{"connected": true, "url": p.baseURL, "dest": p.dest, "policy": p.policy, "files": files, "total_bytes": total, "done_bytes": doneBytes, "speed": p.speed, "all_done": allDone, "elapsed": p.elapsedSeconds(time.Now()), "pending": pending, "active": active, "done": complete, "errors": failures, "total": len(p.jobs), "archives": archives}
	if len(archives) > 0 {
		result["archive"] = archives[len(archives)-1]
	}
	return result
}
