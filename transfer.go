// FileTransfer — 两台 Windows 之间局域网传输文件夹/文件。
//
// 纯标准库（含 //go:embed）。编译成一个独立二进制，无需任何运行环境：
//
//	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o filetransfer.exe .
//
// 双击运行（无参数）自动打开浏览器，进入手机端网页：
//
//	📥 接收文件   输入对方网址 + 密码 → 浏览 → 下载 → 看进度
//	📤 发送文件   选文件夹 + 设密码 → 开始共享 → 看上传进度
//	👁 查看进度   输入对方网址 + 密码 → 只读看对方实时进度
//
// 命令行：
//
//	filetransfer.exe serve <文件夹> --password <密码> [--port 8600]
//	filetransfer.exe pull  [--port 8601] [--dest 下载目录]
//
// 安全边界：局域网明文 HTTP，密码与数据未加密。敏感数据请走 VPN/Tailscale。
package main

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed index.html
var uiHome string

const (
	defaultAdminPassword = "Admin@981"
	chunkSize            = 4 << 20 // 4 MiB
	workerCount          = 4
	httpTimeout          = 120 * time.Second
	defaultPort          = 8600
	protoVersion         = 2
	appVersion           = "2.0.0"
	maxRetries           = 5               // 单文件连续失败后的自动重试次数
	chunkMaxErrs         = 30              // 连续多少块失败算一次「重试」
	jobStateFile         = ".ft-jobs.json" // 任务列表持久化（重启续传用）
	logFile              = "filetransfer.log"
	tempMaxAge           = 7 * 24 * time.Hour // 超期临时文件清理阈值
	spaceMargin          = 32 << 20           // 空间预检留白
)

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

func newToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func lanIP() string {
	c, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer c.Close()
	host, _, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil {
		return "127.0.0.1"
	}
	return host
}

func humanBytes(n int64) string {
	f := float64(n)
	u := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for f >= 1024 && i < len(u)-1 {
		f /= 1024
		i++
	}
	return strconv.FormatFloat(f, 'f', 1, 64) + " " + u[i]
}

// checkRel 校验远端给的相对路径，防目录穿越 / 绝对路径 / 盘符 / UNC。
// 统一按 Windows 规则先查一遍（对端可能是 Windows），再按本机规则查。
func checkRel(rel string) error {
	if rel == "" || strings.ContainsRune(rel, 0) {
		return errors.New("非法路径")
	}
	norm := strings.ReplaceAll(rel, "\\", "/")
	if strings.HasPrefix(norm, "/") {
		return errors.New("非法路径") // 绝对路径 / UNC
	}
	if len(norm) >= 2 && norm[1] == ':' {
		return errors.New("非法路径") // 盘符 C:\
	}
	for _, seg := range strings.Split(norm, "/") {
		if seg == ".." {
			return errors.New("路径越界")
		}
		if strings.Contains(seg, ":") || (seg != "." && seg != "" && (strings.HasSuffix(seg, " ") || strings.HasSuffix(seg, "."))) {
			return errors.New("非法 Windows 路径组件")
		}
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if filepath.IsAbs(clean) || filepath.VolumeName(clean) != "" {
		return errors.New("非法路径")
	}
	if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return errors.New("路径越界")
	}
	return nil
}

// safeJoin 发送端把相对路径解析到 root 内，二次防穿越。
func safeJoin(root, rel string) (string, error) {
	if err := checkRel(rel); err != nil {
		return "", err
	}
	base, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	target := filepath.Join(base, filepath.FromSlash(rel))
	rc, err := filepath.Rel(base, target)
	if err != nil || rc == ".." || strings.HasPrefix(rc, ".."+string(os.PathSeparator)) {
		return "", errors.New("路径越界")
	}
	return target, nil
}

// uniqueName 同名冲突自动重命名：file.txt → file (1).txt
func uniqueName(dir, name string) string {
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	out := filepath.Join(dir, name)
	for i := 1; i <= 9999; i++ {
		if _, err := os.Stat(out); os.IsNotExist(err) {
			return out
		}
		out = filepath.Join(dir, fmt.Sprintf("%s (%d)%s", base, i, ext))
	}
	return filepath.Join(dir, fmt.Sprintf("%s (%d)%s", base, time.Now().UnixNano(), ext))
}

func atomicWrite(path string, b []byte) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	return rootAtomicWrite(root, filepath.Base(path), b)
}

func isDir(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func authed(r *http.Request, token string) bool {
	got := r.URL.Query().Get("token")
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

func openBrowser(rawURL string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", rawURL)
	case "darwin":
		cmd = exec.Command("open", rawURL)
	default:
		cmd = exec.Command("xdg-open", rawURL)
	}
	_ = cmd.Start()
}

func openFolder(path string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("explorer", path).Start()
	case "darwin":
		return exec.Command("open", path).Start()
	default:
		return exec.Command("xdg-open", path).Start()
	}
}

const windowsPickerScript = `$ErrorActionPreference = 'Stop';
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false);
Add-Type -AssemblyName System.Windows.Forms;
$owner = New-Object System.Windows.Forms.Form;
$folder = New-Object System.Windows.Forms.%s;
try {
    $owner.Text = 'FileTransfer';
    $owner.TopMost = $true;
    $owner.ShowInTaskbar = $false;
    $owner.StartPosition = 'CenterScreen';
    $owner.Width = 1;
    $owner.Height = 1;
    $folder.%s = 'FileTransfer - Select';
    $owner.Show();
    $owner.Activate();
    if ($folder.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) {
        [Console]::Write($folder.%s);
    }
} finally {
    $folder.Dispose();
    $owner.Dispose();
}`

func pickFolderWindows() (string, error) {
	return pickWindows("FolderBrowserDialog", "Description", "SelectedPath", "文件夹")
}

func pickWindows(dialog, title, selected, label string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-STA", "-Command", fmt.Sprintf(windowsPickerScript, dialog, title, selected))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return "", fmt.Errorf("选择%s超时，请重试或手动输入路径", label)
	}
	if err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return "", fmt.Errorf("无法打开%s选择窗口，请手动输入路径：%s", label, detail)
	}
	s := strings.TrimSpace(string(out))
	if s == "" {
		return "", fmt.Errorf("未选择%s", label)
	}
	return s, nil
}

// pickFolder 弹系统原生「选择文件夹」对话框：Windows 用 PowerShell，
// macOS 用 osascript，Linux 试 zenity/kdialog；都没有就报错让用户手输。
func pickFolder() (string, error) {
	switch runtime.GOOS {
	case "windows":
		return pickFolderWindows()
	case "darwin":
		out, err := exec.Command("osascript",
			"-e", `set f to choose folder`,
			"-e", `POSIX path of f`).Output()
		if err != nil {
			return "", errors.New("无法弹出选择框：" + err.Error())
		}
		s := strings.TrimSpace(string(out))
		if s == "" {
			return "", errors.New("未选择文件夹")
		}
		return s, nil
	case "linux":
		if out, err := exec.Command("zenity", "--file-selection", "--directory").Output(); err == nil {
			if s := strings.TrimSpace(string(out)); s != "" {
				return s, nil
			}
		}
		if out, err := exec.Command("kdialog", "--getexistingdirectory").Output(); err == nil {
			if s := strings.TrimSpace(string(out)); s != "" {
				return s, nil
			}
		}
		return "", errors.New("未找到图形选择工具（zenity/kdialog），请手动输入路径")
	default:
		return "", errors.New("当前系统不支持弹窗，请手动输入路径")
	}
}

func splitFolder(args []string) (folder string, flagArgs []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

// ---------------------------------------------------------------------------
// 发送方引擎
// ---------------------------------------------------------------------------

type FileInfo struct {
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"`
}

type Manifest struct {
	Path        string   `json:"path"`
	Size        int64    `json:"size"`
	MTime       int64    `json:"mtime"`
	ChunkSize   int      `json:"chunk_size"`
	NChunks     int      `json:"n_chunks"`
	SHA256      string   `json:"sha256"`
	ChunkHashes []string `json:"chunk_hashes"`
}

type activeStat struct {
	Done  int64 `json:"done"`
	Total int64 `json:"total"`
}

type SenderStats struct {
	mu        sync.Mutex
	start     time.Time
	rawBytes  int64
	wireBytes int64
	active    map[string]activeStat
}

func (s *SenderStats) add(path string, raw, wire, total int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rawBytes += raw
	s.wireBytes += wire
	a := s.active[path]
	a.Done += raw
	a.Total = total
	if a.Done >= total {
		delete(s.active, path)
	} else {
		s.active[path] = a
	}
}

func (s *SenderStats) snapshot() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	elapsed := time.Since(s.start).Seconds()
	if elapsed < 0.001 {
		elapsed = 0.001
	}
	ratio := 0.0
	if s.wireBytes > 0 {
		ratio = float64(s.rawBytes) / float64(s.wireBytes)
	}
	saved := s.rawBytes - s.wireBytes // 压缩节省的字节数（raw−wire）
	active := make(map[string]activeStat, len(s.active))
	for path, stat := range s.active {
		active[path] = stat
	}
	return map[string]interface{}{
		"uptime":           int64(elapsed),
		"raw_bytes":        s.rawBytes,
		"wire_bytes":       s.wireBytes,
		"compressed_saved": saved,
		"speed":            float64(s.wireBytes) / elapsed,
		"ratio":            ratio,
		"active":           active,
	}
}

// sharedRoot 一个共享根：虚拟顶层名 → 真实路径。
type sharedRoot struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Test bool   `json:"test,omitempty"` // 测试文件夹不列入对外清单
	File bool   `json:"file,omitempty"`
}

type Sender struct {
	roots         []sharedRoot
	password      string
	token         string
	mu            sync.Mutex
	manifestCache map[string]Manifest
	stats         SenderStats
}

func NewSender(password string) *Sender {
	return &Sender{
		password:      password,
		token:         newToken(),
		manifestCache: map[string]Manifest{},
		stats:         SenderStats{start: time.Now(), active: map[string]activeStat{}},
	}
}

// addRoot 添加一个共享根；同名自动改名（folder → folder (1)），返回虚拟名。
func (s *Sender) addRoot(path string) (string, error) {
	return s.addRootFlagged(path, false)
}

// addTestRoot 添加一个「测试」根：不列入对外清单，仅供连通测试推小文件。
// 同一目录幂等：已存在同名测试根时直接复用，避免根数量波动改变路径前缀。
func (s *Sender) addTestRoot(path string) (string, error) {
	abs, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return "", err
	}
	for _, r := range s.rootList() {
		if r.Test && filepath.Clean(r.Path) == filepath.Clean(abs) {
			return r.Name, nil
		}
	}
	return s.addRootFlagged(path, true)
}

func (s *Sender) addRootFlagged(path string, test bool) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("请选择文件或文件夹，路径不能为空")
	}
	abs, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("文件或文件夹不可访问：%s：%w", path, err)
	}
	singleFile := !info.IsDir()
	if singleFile {
		linkInfo, err := os.Lstat(abs)
		if err != nil || !linkInfo.Mode().IsRegular() || test {
			return "", fmt.Errorf("不支持的文件类型：%s", path)
		}
	}
	base := filepath.Base(abs)
	name := base
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 1; ; i++ {
		taken := false
		for _, r := range s.roots {
			if strings.EqualFold(r.Name, name) {
				taken = true
				break
			}
		}
		if !taken {
			break
		}
		if singleFile {
			ext := filepath.Ext(base)
			name = fmt.Sprintf("%s (%d)%s", strings.TrimSuffix(base, ext), i, ext)
		} else {
			name = fmt.Sprintf("%s (%d)", base, i)
		}
	}
	s.roots = append(s.roots, sharedRoot{Name: name, Path: abs, Test: test, File: singleFile})
	return name, nil
}

func (s *Sender) removeRoot(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.roots[:0]
	for _, r := range s.roots {
		if r.Name != name {
			out = append(out, r)
		}
	}
	s.roots = out
}

func (s *Sender) rootList() []sharedRoot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]sharedRoot{}, s.roots...)
}

// resolve 把虚拟相对路径映射到真实文件路径。
// 路径一律带「根名/」前缀（稳定，不受后续根数量变化影响）；单根时也兼容无前缀旧路径。
func (s *Sender) resolve(rel string) (string, error) {
	roots := s.rootList()
	if len(roots) == 0 {
		return "", errors.New("尚未添加共享文件夹")
	}
	idx := strings.IndexByte(rel, '/')
	top, rest := rel, ""
	if idx >= 0 {
		top, rest = rel[:idx], rel[idx+1:]
	}
	for _, r := range roots {
		if r.Name == top {
			if r.File {
				if idx >= 0 {
					return "", errors.New("单文件选择不支持子路径")
				}
				return r.Path, nil
			}
			return safeJoin(r.Path, rest)
		}
	}
	if len(roots) == 1 && !roots[0].File {
		return safeJoin(roots[0].Path, rel)
	}
	return "", errors.New("未知文件夹：" + top)
}

func (s *Sender) walk() ([]FileInfo, error) {
	roots := s.rootList()
	if len(roots) == 0 {
		return []FileInfo{}, nil
	}
	var files []FileInfo
	for _, r := range roots {
		if r.Test {
			continue // 测试文件夹不列入对外清单
		}
		if r.File {
			info, err := os.Lstat(r.Path)
			if err != nil {
				return nil, err
			}
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("不支持的文件类型：%s", r.Path)
			}
			files = append(files, FileInfo{Path: r.Name, Size: info.Size(), MTime: info.ModTime().Unix()})
			continue
		}
		// 一律带「根名/」前缀：路径稳定，不随根数量变化
		filepath.Walk(r.Path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // 单个文件读不到不阻断整体列举
			}
			if info.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(r.Path, path)
			if err != nil {
				return nil
			}
			files = append(files, FileInfo{Path: r.Name + "/" + filepath.ToSlash(rel), Size: info.Size(), MTime: info.ModTime().Unix()})
			return nil
		})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func (s *Sender) open(rel string) (*os.File, error) {
	if err := checkRel(rel); err != nil {
		return nil, err
	}
	roots := s.rootList()
	for _, root := range roots {
		if root.File {
			if rel == root.Name {
				return openSelectedFile(root.Path)
			}
			continue
		}
		prefix := root.Name + "/"
		if strings.HasPrefix(rel, prefix) {
			handle, err := os.OpenRoot(root.Path)
			if err != nil {
				return nil, err
			}
			defer handle.Close()
			return openSourceFile(handle, strings.TrimPrefix(rel, prefix))
		}
	}
	if len(roots) == 1 && !roots[0].File {
		handle, err := os.OpenRoot(roots[0].Path)
		if err != nil {
			return nil, err
		}
		defer handle.Close()
		return openSourceFile(handle, strings.ReplaceAll(rel, "\\", "/"))
	}
	return nil, errors.New("未知共享文件夹")
}

func (s *Sender) manifest(rel string) (Manifest, error) {
	file, err := s.open(rel)
	if err != nil {
		return Manifest{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Manifest{}, err
	}
	if !info.Mode().IsRegular() {
		return Manifest{}, errors.New("不是普通文件")
	}
	key := fmt.Sprintf("%s|%d|%d", rel, info.Size(), info.ModTime().UnixNano())
	s.mu.Lock()
	cached, exists := s.manifestCache[key]
	s.mu.Unlock()
	if exists {
		return cached, nil
	}
	whole := sha256.New()
	hashes := make([]string, 0)
	buffer := make([]byte, chunkSize)
	var size int64
	for {
		count, readErr := io.ReadFull(file, buffer)
		if count > 0 {
			whole.Write(buffer[:count])
			hashes = append(hashes, sha256hex(buffer[:count]))
			size += int64(count)
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return Manifest{}, readErr
		}
	}
	after, err := file.Stat()
	if err != nil || size != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return Manifest{}, errors.New("源文件在校验期间发生变化，请重试")
	}
	manifest := Manifest{Path: rel, Size: size, MTime: info.ModTime().Unix(), ChunkSize: chunkSize, NChunks: len(hashes), SHA256: hex.EncodeToString(whole.Sum(nil)), ChunkHashes: hashes}
	s.mu.Lock()
	if len(s.manifestCache) >= 1024 {
		s.manifestCache = map[string]Manifest{}
	}
	s.manifestCache[key] = manifest
	s.mu.Unlock()
	return manifest, nil
}

// chunk 读一块并压缩；压不动就原样发。0 字节文件不压缩。
func (s *Sender) chunk(rel string, idx int) ([]byte, string, int, int64, error) {
	man, err := s.manifest(rel)
	if err != nil {
		return nil, "", 0, 0, err
	}
	if idx < 0 || idx >= man.NChunks {
		return nil, "", 0, 0, errors.New("分块索引越界")
	}
	f, err := s.open(rel)
	if err != nil {
		return nil, "", 0, 0, err
	}
	defer f.Close()
	if _, err := f.Seek(int64(idx)*int64(chunkSize), 0); err != nil {
		return nil, "", 0, 0, err
	}
	raw := make([]byte, chunkSize)
	n, err := io.ReadFull(f, raw)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, "", 0, 0, err
	}
	raw = raw[:n]
	if len(raw) == 0 {
		return raw, "r", 0, man.Size, nil
	}
	var buf bytes.Buffer
	zw, err := zlib.NewWriterLevel(&buf, 6)
	if err != nil {
		return nil, "", 0, 0, err
	}
	zw.Write(raw)
	zw.Close()
	if buf.Len() < len(raw) {
		return buf.Bytes(), "z", len(raw), man.Size, nil
	}
	return raw, "r", len(raw), man.Size, nil
}

// buildArchive 把选定的文件夹打包成一个 zip（条目名 = 虚拟路径，带根名前缀）。
// 返回 (zip 路径, 包内文件数, 原始总字节, error)。
func (s *Sender) buildArchive(folders []string) (string, int, int64, error) {
	return s.buildArchiveProgress(folders, nil)
}

func (s *Sender) buildArchiveProgress(folders []string, progress *preparation) (string, int, int64, error) {
	dir := filepath.Join(os.TempDir(), "FileTransfer发送")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", 0, 0, err
	}
	file, err := os.CreateTemp(dir, "packing-*.zip")
	if err != nil {
		return "", 0, 0, err
	}
	temp := file.Name()
	defer func() { file.Close(); os.Remove(temp) }()
	writer := zip.NewWriter(file)
	items, err := s.selectedFiles(folders, progress)
	if err != nil {
		writer.Close()
		return "", 0, 0, err
	}
	if len(items) == 0 {
		writer.Close()
		return "", 0, 0, errors.New("所选内容里没有可发送的文件")
	}
	progress.update(func(state *preparationState) { state.Stage = "compressing" })
	var total int64
	for _, item := range items {
		progress.update(func(state *preparationState) { state.Current = item.name })
		input, err := s.open(item.name)
		if err != nil {
			writer.Close()
			return "", 0, 0, fmt.Errorf("读取源文件 %s 失败：%w", item.path, err)
		}
		info, err := input.Stat()
		if err != nil || !info.Mode().IsRegular() {
			input.Close()
			writer.Close()
			return "", 0, 0, errors.New("源文件不可读")
		}
		progress.update(func(state *preparationState) { state.TotalBytes += info.Size() - item.size })
		header := &zip.FileHeader{Name: item.name, Method: zip.Deflate}
		header.SetModTime(info.ModTime())
		output, err := writer.CreateHeader(header)
		var copied int64
		if err == nil {
			copied, err = io.Copy(&progressWriter{writer: output, advance: func(count int64) {
				progress.update(func(state *preparationState) { state.DoneBytes += count })
			}}, input)
		}
		after, statErr := input.Stat()
		closeErr := input.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil && (statErr != nil || copied != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime())) {
			err = errors.New("源文件在打包时发生变化")
		}
		if err != nil {
			writer.Close()
			return "", 0, 0, fmt.Errorf("打包 %s 失败：%w", item.name, err)
		}
		total += copied
		progress.update(func(state *preparationState) { state.DoneFiles++ })
	}
	progress.update(func(state *preparationState) {
		state.Stage = "finalizing"
		state.Current = "正在写入压缩包目录并同步磁盘"
	})
	if err := writer.Close(); err != nil {
		return "", 0, 0, err
	}
	if err := file.Sync(); err != nil {
		return "", 0, 0, err
	}
	if _, err := file.Seek(0, 0); err != nil {
		return "", 0, 0, err
	}
	archiveInfo, err := file.Stat()
	if err != nil {
		return "", 0, 0, err
	}
	progress.update(func(state *preparationState) {
		state.Stage = "verifying"
		state.Current = "正在校验生成的压缩包"
		state.ZipBytes = archiveInfo.Size()
	})
	digest, err := fileDigest(context.Background(), io.TeeReader(file, &progressWriter{writer: io.Discard, advance: func(count int64) {
		progress.update(func(state *preparationState) { state.VerifyBytes += count })
	}}))
	if err != nil {
		return "", 0, 0, err
	}
	if err := file.Close(); err != nil {
		return "", 0, 0, err
	}
	target := filepath.Join(dir, "FileTransfer-"+digest+".zip")
	lock := storageLock(dir)
	lock.Lock()
	defer lock.Unlock()
	if existing, err := os.Open(target); err == nil {
		progress.update(func(state *preparationState) { state.Current = "正在检查已有压缩包缓存" })
		current, digestErr := fileDigest(context.Background(), existing)
		existing.Close()
		if digestErr == nil && current == digest {
			return target, len(items), total, nil
		}
	}
	if err := os.Rename(temp, target); err != nil {
		return "", 0, 0, err
	}
	return target, len(items), total, nil
}

// ---------------------------------------------------------------------------
// 接收方引擎
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 远端认证 / 只读监控
// ---------------------------------------------------------------------------

type remoteInfo struct {
	Token string
	Name  string
	Proto int
	Ver   string
}

// authRemote 用密码向远端换 token，并做协议版本握手。
func authRemote(rawURL, password string) (remoteInfo, error) {
	var ri remoteInfo
	var err error
	rawURL, err = remoteURL(rawURL)
	if err != nil {
		return ri, err
	}
	body, _ := json.Marshal(map[string]string{"password": password})
	req, _ := http.NewRequest("POST", rawURL+"/api/auth", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ri, errors.New("无法连接（检查对方是否已启动、防火墙是否放行）：" + err.Error())
	}
	defer resp.Body.Close()
	var a struct {
		Ok    bool   `json:"ok"`
		Token string `json:"token"`
		Name  string `json:"name"`
		Error string `json:"error"`
		Proto int    `json:"proto"`
		Ver   string `json:"ver"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&a); err != nil {
		return ri, err
	}
	if !a.Ok {
		msg := a.Error
		if msg == "" {
			msg = "认证失败"
		}
		return ri, errors.New(msg)
	}
	if a.Token == "" {
		return ri, errors.New("对方没有提供有效访问凭证")
	}
	if a.Proto != protoVersion {
		return ri, fmt.Errorf("版本不兼容：对方协议 v%d，本机 v%d，请两台机器用同一版本", a.Proto, protoVersion)
	}
	return remoteInfo{Token: a.Token, Name: a.Name, Proto: a.Proto, Ver: a.Ver}, nil
}

type Monitor struct {
	baseURL string
	token   string
	name    string
	client  *http.Client
	source  string
}

func (m *Monitor) getJSON(endpoint string, out interface{}) error {
	query := url.Values{"token": {m.token}}
	if m.source != "" {
		query.Set("source", m.source)
	}
	u := m.baseURL + endpoint + "?" + query.Encode()
	resp, err := m.client.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxJSONBytes)).Decode(out)
}

// ---------------------------------------------------------------------------
// 统一 App
// ---------------------------------------------------------------------------

// Receiver 接收端配置：存储目录 + 密码，等待发送方推送。
type Receiver struct {
	dest     string
	password string
	token    string
	policy   string
}

type App struct {
	mu          sync.Mutex
	sender      *Sender
	receiver    *Receiver
	puller      *Puller
	monitor     *Monitor
	port        int
	adminKey    string
	defaultDest string
	noBrowser   bool
	pullers     map[string]*Puller
	outgoing    map[string]*Monitor
	uploaders   map[string]*Uploader
	preparing   *preparation
}

func (a *App) getSender(r *http.Request) (*Sender, bool) {
	a.mu.Lock()
	s := a.sender
	a.mu.Unlock()
	if s == nil || !authed(r, s.token) {
		return nil, false
	}
	return s, true
}

func (a *App) getPuller() *Puller {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.puller
}

func newAppMux(a *App) *http.ServeMux {
	a.mu.Lock()
	if a.adminKey == "" {
		a.adminKey = defaultAdminPassword
	}
	a.mu.Unlock()
	mux := http.NewServeMux()
	a.uploadRoutes(mux)
	mux.HandleFunc("/api/session", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]interface{}{"authorized": a.isAdmin(r), "ver": appVersion})
	})
	mux.HandleFunc("/api/send-state", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, a.sendState()) })
	mux.HandleFunc("/api/prepare-state", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, a.preparationState()) })

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, uiHome)
			return
		}
		http.NotFound(w, r)
	})

	mux.HandleFunc("/api/info", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		res := map[string]interface{}{
			"sender": false, "receiver": false, "puller": false, "port": a.port,
			"proto": protoVersion, "ver": appVersion, "role": "idle",
		}
		res["default_dest"] = a.defaultDest
		res["outgoing"] = len(a.outgoing) > 0
		if a.sender != nil {
			res["sender"] = true
			res["role"] = "sender"
			roots := a.sender.rootList()
			res["roots"] = roots
			if len(roots) > 0 {
				res["sender_name"] = roots[0].Name
			}
		}
		if a.receiver != nil {
			res["receiver"] = true
			res["role"] = "receiver"
			res["receiver_dest"] = a.receiver.dest
			res["receiver_policy"] = a.receiver.policy
			res["receiver_password"] = a.receiver.password
			res["my_url"] = fmt.Sprintf("http://%s:%d", lanIP(), a.port)
		}
		if a.puller != nil {
			res["puller"] = true
			res["puller_url"] = a.puller.baseURL
			res["puller_dest"] = a.puller.dest
		}
		a.mu.Unlock()
		writeJSON(w, 200, res)
	})

	mux.HandleFunc("/api/pick-folder", func(w http.ResponseWriter, r *http.Request) {
		p, err := pickFolder()
		if err != nil {
			writeJSON(w, 200, map[string]interface{}{"path": "", "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"path": p})
	})
	mux.HandleFunc("/api/pick-file", func(w http.ResponseWriter, r *http.Request) {
		path, err := pickFile()
		if err != nil {
			writeJSON(w, 200, map[string]interface{}{"path": "", "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"path": path})
	})

	mux.HandleFunc("/api/open-folder", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		target := ""
		if a.puller != nil {
			target = a.puller.dest
		} else if a.sender != nil {
			if roots := a.sender.rootList(); len(roots) > 0 {
				target = roots[0].Path
			}
		}
		a.mu.Unlock()
		if target == "" {
			writeJSON(w, 200, map[string]interface{}{"ok": false, "error": "还没有可打开的目录"})
			return
		}
		if err := openFolder(target); err != nil {
			writeJSON(w, 200, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"ok": true, "path": target})
	})

	mux.HandleFunc("/api/start-serve", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Folders  []string `json:"folders"`
			Folder   string   `json:"folder"` // 兼容传单个
			Password string   `json:"password"`
		}
		if !decodeRequest(w, r, &in) {
			return
		}
		folders := in.Folders
		if len(folders) == 0 && strings.TrimSpace(in.Folder) != "" {
			folders = []string{in.Folder}
		}
		if len(folders) == 0 || in.Password == "" {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "请至少添加一个文件夹并设置密码"})
			return
		}
		s := NewSender(in.Password)
		var names []string
		for _, f := range folders {
			if name, err := s.addRoot(f); err == nil {
				names = append(names, name)
			}
		}
		if len(names) == 0 {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "所选文件夹均无效"})
			return
		}
		a.mu.Lock()
		a.sender = s
		a.mu.Unlock()
		writeJSON(w, 200, map[string]interface{}{
			"ok": true, "token": s.token, "name": names[0],
			"roots":     s.rootList(),
			"share_url": fmt.Sprintf("http://%s:%d", lanIP(), a.port),
			"proto":     protoVersion, "ver": appVersion,
		})
	})

	// 已开始共享后，继续追加文件夹（可多次添加）
	mux.HandleFunc("/api/add-folder", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Folder string `json:"folder"`
		}
		if !decodeRequest(w, r, &in) {
			return
		}
		a.mu.Lock()
		s := a.sender
		a.mu.Unlock()
		if s == nil {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "请先开始共享"})
			return
		}
		name, err := s.addRoot(in.Folder)
		if err != nil {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"ok": true, "name": name, "roots": s.rootList()})
	})

	mux.HandleFunc("/api/remove-folder", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Name string `json:"name"`
		}
		if !decodeRequest(w, r, &in) {
			return
		}
		a.mu.Lock()
		s := a.sender
		a.mu.Unlock()
		if s == nil {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "未共享"})
			return
		}
		s.removeRoot(in.Name)
		writeJSON(w, 200, map[string]interface{}{"ok": true, "roots": s.rootList()})
	})

	// 接收端：设置存储目录 + 密码，等待发送方推送
	mux.HandleFunc("/api/receive-config", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Dest     string `json:"dest"`
			Password string `json:"password"`
			Policy   string `json:"policy"`
		}
		if !decodeRequest(w, r, &in) {
			return
		}
		if !validPolicy(in.Policy) {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "未知同名文件策略"})
			return
		}
		if in.Policy == "" {
			in.Policy = "rename"
		}
		if in.Dest == "" {
			in.Dest = a.defaultDest
		}
		if in.Dest == "" {
			cwd, _ := os.Getwd()
			in.Dest = filepath.Join(cwd, "received")
		}
		if in.Password == "" {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "请设置接收密码（发给发送方用）"})
			return
		}
		abs, err := filepath.Abs(in.Dest)
		if err != nil {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		in.Dest = abs
		root, err := openStore(in.Dest)
		if err != nil {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "无法创建目录：" + err.Error()})
			return
		}
		root.Close()
		recv := &Receiver{dest: in.Dest, password: in.Password, token: newToken(), policy: in.Policy}
		a.mu.Lock()
		a.receiver = recv
		a.mu.Unlock()
		writeJSON(w, 200, map[string]interface{}{
			"ok": true, "my_url": fmt.Sprintf("http://%s:%d", lanIP(), a.port),
			"dest": recv.dest,
		})
	})

	// 接收端：发送方请求推送（发送方把文件和自身地址告诉我们，我们拉取）
	mux.HandleFunc("/api/push-request", func(response http.ResponseWriter, request *http.Request) {
		writeJSON(response, http.StatusGone, map[string]string{"error": "旧版回连传输已停用，请将发送端与接收端都升级到 v2 主动上传版本"})
	})

	// 发送端：把选中的文件夹推给接收方（接收方在其本地拉取）
	mux.HandleFunc("/api/push", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			RemoteURL  string   `json:"remote_url"`
			RemotePass string   `json:"remote_password"`
			Folders    []string `json:"folders"`
			Paths      []string `json:"paths"`
			Compress   *bool    `json:"compress"` // 默认压缩传输（打包 zip，接收端自动解压）
		}
		if !decodeRequest(w, r, &in) {
			return
		}
		in.RemoteURL = strings.TrimSpace(in.RemoteURL)
		in.Folders = append(in.Folders, in.Paths...)
		if len(in.Folders) == 0 || in.RemoteURL == "" || in.RemotePass == "" {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "请填写接收方地址、密码并选择要发送的文件或文件夹"})
			return
		}
		validatedURL, urlErr := remoteURL(in.RemoteURL)
		if urlErr != nil {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "error": urlErr.Error()})
			return
		}
		in.RemoteURL = validatedURL
		compress := true
		if in.Compress != nil {
			compress = *in.Compress
		}
		progress, started := a.startPreparation(in.RemoteURL, compress)
		if !started {
			writeJSON(w, 409, map[string]interface{}{"ok": false, "error": "已有任务正在准备，请等待完成后再追加"})
			return
		}
		failure := "发送准备未完成，请重试"
		defer func() { progress.finish(failure) }()
		fail := func(status int, message string) {
			failure = message
			writeJSON(w, status, map[string]interface{}{"ok": false, "error": message})
		}
		a.mu.Lock()
		s := a.sender
		if s == nil {
			s = NewSender(newToken()) // 随机传输密码，给接收方内部拉取用
			a.sender = s
		}
		a.mu.Unlock()
		for _, f := range in.Folders {
			already := false
			if abs, err := filepath.Abs(strings.TrimSpace(f)); err == nil {
				for _, root := range s.rootList() {
					if !root.Test && sourcePathKey(abs) == sourcePathKey(root.Path) {
						already = true
						break
					}
				}
			}
			if !already {
				if _, err := s.addRoot(f); err != nil {
					fail(400, err.Error())
					return
				}
			}
		}
		totalFiles := 0
		var totalBytes int64
		var paths []string
		archive := false

		if compress {
			// 压缩传输：把选定文件夹打包成 zip，接收方下载后自动解压
			zipPath, n, b, berr := s.buildArchiveProgress(in.Folders, progress)
			if berr != nil {
				fail(400, "打包失败："+berr.Error())
				return
			}
			name, aerr := s.addTestRoot(filepath.Dir(zipPath))
			if aerr != nil {
				fail(500, aerr.Error())
				return
			}
			paths = []string{name + "/" + filepath.Base(zipPath)}
			totalFiles, totalBytes, archive = n, b, true
		} else {
			files, err := s.selectedFiles(in.Folders, progress)
			if err != nil {
				fail(400, err.Error())
				return
			}
			for _, file := range files {
				paths = append(paths, file.name)
				totalFiles++
				totalBytes += file.size
			}
		}
		if len(paths) == 0 {
			fail(400, "所选内容里没有可发送的文件")
			return
		}
		progress.update(func(state *preparationState) {
			state.Stage = "connecting"
			state.Current = "正在生成分块校验信息并提交接收方，尚未全部入队"
		})
		added, uploadErr := a.beginUpload(in.RemoteURL, in.RemotePass, s, paths, archive, totalFiles, totalBytes)
		if uploadErr != nil {
			failure = uploadErr.Error()
			writeJSON(w, 502, map[string]interface{}{"ok": false, "error": uploadErr.Error(), "added": added})
			return
		}
		failure = ""
		writeJSON(w, 200, map[string]interface{}{
			"ok": true, "count": totalFiles, "added": added,
			"token": s.token, "transport": "upload",
			"compressed": archive, "total_bytes": totalBytes,
		})
	})

	// 发送端：连通测试 —— 推一个小测试文件到接收方，验证地址/密码/链路
	mux.HandleFunc("/api/push-test", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			RemoteURL  string `json:"remote_url"`
			RemotePass string `json:"remote_password"`
		}
		if !decodeRequest(w, r, &in) {
			return
		}
		validatedURL, urlErr := remoteURL(in.RemoteURL)
		if urlErr != nil {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "error": urlErr.Error()})
			return
		}
		in.RemoteURL = validatedURL
		if strings.TrimSpace(in.RemoteURL) == "" || in.RemotePass == "" {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "请先填写接收方地址和密码"})
			return
		}
		testDir := filepath.Join(os.TempDir(), "FileTransfer连通测试")
		os.MkdirAll(testDir, 0755)
		testName := "FileTransfer-连通测试.txt"
		os.WriteFile(filepath.Join(testDir, testName),
			[]byte("FileTransfer 连通测试 OK — "+time.Now().Format(time.RFC3339)+"\n收到此文件说明连接正常（地址、密码、传输链路都没问题），可删除。\n"), 0644)
		a.mu.Lock()
		s := a.sender
		if s == nil {
			s = NewSender(newToken())
			a.sender = s
		}
		a.mu.Unlock()
		if _, err := s.addTestRoot(testDir); err != nil {
			writeJSON(w, 500, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		// 测试文件服务路径：一律带测试根名前缀（稳定）
		tPath := testName
		for _, root := range s.rootList() {
			if root.Test && filepath.Clean(root.Path) == filepath.Clean(testDir) {
				tPath = root.Name + "/" + testName
				break
			}
		}
		added, uploadErr := a.beginUpload(in.RemoteURL, in.RemotePass, s, []string{tPath}, false, 1, 0)
		if uploadErr != nil {
			writeJSON(w, 502, map[string]interface{}{"ok": false, "error": uploadErr.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"ok": true, "name": testName, "added": added, "transport": "upload"})
	})

	// 统一进度：发送端返回上传统计+文件列表；接收端返回接收进度（token 授权，供「查看进度」）
	mux.HandleFunc("/api/progress", func(w http.ResponseWriter, r *http.Request) {
		tok := r.URL.Query().Get("token")
		a.mu.Lock()
		s := a.sender
		recv := a.receiver
		a.mu.Unlock()
		if s != nil && authed(r, s.token) {
			a.mu.Lock()
			hasOutgoing := len(a.outgoing) > 0
			a.mu.Unlock()
			if hasOutgoing {
				writeJSON(w, 200, map[string]interface{}{"role": "sender", "state": a.sendState()})
				return
			}
			files, _ := s.walk()
			writeJSON(w, 200, map[string]interface{}{
				"role": "sender", "stats": s.stats.snapshot(), "files": files,
			})
			return
		}
		if recv != nil && subtle.ConstantTimeCompare([]byte(tok), []byte(recv.token)) == 1 {
			res := map[string]interface{}{"role": "receiver", "dest": recv.dest}
			state := a.receiveState(r.URL.Query().Get("source"))
			state["connected"] = true
			state["dest"] = recv.dest
			res["state"] = state
			writeJSON(w, 200, res)
			return
		}
		writeJSON(w, 401, map[string]string{"error": "未授权"})
	})

	// 远端用密码换 token（附带协议版本，供握手）
	mux.HandleFunc("/api/auth", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Password string `json:"password"`
		}
		if !decodeRequest(w, r, &in) {
			return
		}
		a.mu.Lock()
		s := a.sender
		recv := a.receiver
		a.mu.Unlock()
		// 发送端（推送时给接收方的拉取器用）
		if s != nil && subtle.ConstantTimeCompare([]byte(in.Password), []byte(s.password)) == 1 {
			name := "共享"
			if roots := s.rootList(); len(roots) > 0 {
				name = roots[0].Name
			}
			writeJSON(w, 200, map[string]interface{}{
				"ok": true, "token": s.token, "name": name, "role": "sender",
				"proto": protoVersion, "ver": appVersion,
			})
			return
		}
		// 接收端（查看进度/推送请求用）
		if recv != nil && subtle.ConstantTimeCompare([]byte(in.Password), []byte(recv.password)) == 1 {
			writeJSON(w, 200, map[string]interface{}{
				"ok": true, "token": recv.token, "name": "接收端", "role": "receiver",
				"proto": protoVersion, "ver": appVersion,
			})
			return
		}
		if s == nil && recv == nil {
			writeJSON(w, 403, map[string]interface{}{"ok": false, "error": "尚未启动发送或接收"})
			return
		}
		writeJSON(w, 403, map[string]interface{}{"ok": false, "error": "密码错误"})
	})

	mux.HandleFunc("/api/tree", func(w http.ResponseWriter, r *http.Request) {
		s, ok := a.getSender(r)
		if !ok {
			writeJSON(w, 401, map[string]string{"error": "未授权"})
			return
		}
		files, err := s.walk()
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"files": files})
	})

	mux.HandleFunc("/api/manifest", func(w http.ResponseWriter, r *http.Request) {
		s, ok := a.getSender(r)
		if !ok {
			writeJSON(w, 401, map[string]string{"error": "未授权"})
			return
		}
		m, err := s.manifest(r.URL.Query().Get("path"))
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, m)
	})

	mux.HandleFunc("/api/chunk", func(w http.ResponseWriter, r *http.Request) {
		s, ok := a.getSender(r)
		if !ok {
			writeJSON(w, 401, map[string]string{"error": "未授权"})
			return
		}
		rel := r.URL.Query().Get("path")
		idx, _ := strconv.Atoi(r.URL.Query().Get("idx"))
		payload, enc, rawLen, total, err := s.chunk(rel, idx)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Enc", enc)
		w.Header().Set("X-Len", strconv.Itoa(rawLen))
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.WriteHeader(200)
		w.Write(payload)
		s.stats.add(rel, int64(rawLen), int64(len(payload)), total)
	})

	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		s, ok := a.getSender(r)
		if !ok {
			writeJSON(w, 401, map[string]string{"error": "未授权"})
			return
		}
		writeJSON(w, 200, s.stats.snapshot())
	})

	// 接收方：连接（连上后自动恢复上次任务 + 清理超期临时文件）
	mux.HandleFunc("/api/connect", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			URL      string `json:"url"`
			Password string `json:"password"`
			Dest     string `json:"dest"`
			Policy   string `json:"policy"`
		}
		if !decodeRequest(w, r, &in) {
			return
		}
		ri, err := authRemote(in.URL, in.Password)
		if err != nil {
			writeJSON(w, 200, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		if in.Dest == "" {
			in.Dest = a.defaultDest
		}
		if in.Dest == "" {
			cwd, _ := os.Getwd()
			in.Dest = filepath.Join(cwd, "received")
		}
		p, fresh, err := a.acquirePuller(in.URL, ri.Token, in.Dest, in.Policy)
		if err != nil {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		restored := 0
		if fresh {
			restored = p.restoreJobs()
		}
		cleaned := p.cleanStale()
		p.start()
		writeJSON(w, 200, map[string]interface{}{
			"ok": true, "name": ri.Name, "proto": ri.Proto, "ver": ri.Ver,
			"restored": restored, "cleaned": cleaned,
		})
	})

	mux.HandleFunc("/api/monitor", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			URL      string `json:"url"`
			Password string `json:"password"`
		}
		if !decodeRequest(w, r, &in) {
			return
		}
		ri, err := authRemote(in.URL, in.Password)
		if err != nil {
			writeJSON(w, 200, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		m := &Monitor{baseURL: strings.TrimRight(strings.TrimSpace(in.URL), "/"), token: ri.Token, name: ri.Name, client: &http.Client{Timeout: 5 * time.Second}}
		a.mu.Lock()
		a.monitor = m
		a.mu.Unlock()
		writeJSON(w, 200, map[string]interface{}{"ok": true, "name": ri.Name})
	})

	// monitor-state：统一拉取对方 /api/progress（发送端=上传统计，接收端=接收进度）
	mux.HandleFunc("/api/monitor-state", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		m := a.monitor
		a.mu.Unlock()
		if m == nil {
			writeJSON(w, 200, map[string]interface{}{"connected": false})
			return
		}
		var prog map[string]interface{}
		if err := m.getJSON("/api/progress", &prog); err != nil {
			writeJSON(w, 200, map[string]interface{}{"connected": false, "error": "读取进度失败"})
			return
		}
		prog["connected"] = true
		writeJSON(w, 200, prog)
	})

	mux.HandleFunc("/api/remote", func(w http.ResponseWriter, r *http.Request) {
		p := a.getPuller()
		if p == nil {
			writeJSON(w, 401, map[string]interface{}{"connected": false, "error": "未连接"})
			return
		}
		files, err := p.remoteTree()
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"files": files})
	})

	mux.HandleFunc("/api/download", func(w http.ResponseWriter, r *http.Request) {
		p := a.getPuller()
		if p == nil {
			writeJSON(w, 401, map[string]interface{}{"connected": false, "error": "未连接"})
			return
		}
		var in struct {
			Paths  []string `json:"paths"`
			Policy string   `json:"policy"`
		}
		if !decodeRequest(w, r, &in) {
			return
		}
		added, err := p.addPaths(in.Paths, in.Policy)
		if err != nil {
			writeJSON(w, 200, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"ok": true, "added": added})
	})

	mux.HandleFunc("/api/pause", func(w http.ResponseWriter, r *http.Request) {
		p := a.getPuller()
		if p == nil {
			writeJSON(w, 200, map[string]interface{}{"connected": false})
			return
		}
		var in struct {
			Path string `json:"path"`
		}
		if !decodeRequest(w, r, &in) {
			return
		}
		a.control("pause", in.Path)
		writeJSON(w, 200, map[string]interface{}{"ok": true})
	})

	mux.HandleFunc("/api/resume", func(w http.ResponseWriter, r *http.Request) {
		p := a.getPuller()
		if p == nil {
			writeJSON(w, 200, map[string]interface{}{"connected": false})
			return
		}
		var in struct {
			Path string `json:"path"`
		}
		if !decodeRequest(w, r, &in) {
			return
		}
		a.control("resume", in.Path)
		writeJSON(w, 200, map[string]interface{}{"ok": true})
	})

	mux.HandleFunc("/api/cancel", func(w http.ResponseWriter, r *http.Request) {
		p := a.getPuller()
		if p == nil {
			writeJSON(w, 200, map[string]interface{}{"connected": false})
			return
		}
		var in struct {
			Path string `json:"path"`
		}
		if !decodeRequest(w, r, &in) {
			return
		}
		a.control("cancel", in.Path)
		writeJSON(w, 200, map[string]interface{}{"ok": true})
	})

	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		p := a.getPuller()
		if p == nil {
			writeJSON(w, 200, map[string]interface{}{"connected": false})
			return
		}
		writeJSON(w, 200, a.receiveState(""))
	})

	mux.HandleFunc("/api/log", func(w http.ResponseWriter, r *http.Request) {
		p := a.getPuller()
		if p == nil {
			writeJSON(w, 200, map[string]interface{}{"log": []string{}})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"log": p.readLog(50), "dest": p.dest})
	})

	mux.HandleFunc("/api/clean-cache", func(w http.ResponseWriter, r *http.Request) {
		p := a.getPuller()
		if p == nil {
			writeJSON(w, 200, map[string]interface{}{"ok": false, "error": "未连接"})
			return
		}
		removed := 0
		for _, puller := range a.pullerList() {
			removed += puller.cleanCache()
		}
		writeJSON(w, 200, map[string]interface{}{"ok": true, "removed": removed})
	})

	return a.protect(mux)
}

// ---------------------------------------------------------------------------
// 入口
// ---------------------------------------------------------------------------

func banner(port int) string {
	ip := lanIP()
	return fmt.Sprintf(`========================================================
  FileTransfer v%s 已启动
  本机界面:  http://localhost:%d
  手机访问:  http://%s:%d
  给对方填:  http://%s:%d
  （浏览器应已自动打开，没打开就手动访问上面的地址）
  首次运行若弹出防火墙提示，必须点「允许」，否则对方连不上。
  按 Ctrl+C 退出。
========================================================`, appVersion, port, ip, port, ip, port)
}

func serveAndOpen(addr string, port int, app *App) {
	mux := newAppMux(app)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "启动失败:", err)
		os.Exit(1)
	}
	port = listener.Addr().(*net.TCPAddr).Port
	app.port = port
	fmt.Println(banner(port))
	fmt.Println("Admin password:", app.adminKey)
	if !app.noBrowser {
		go openBrowser(fmt.Sprintf("http://localhost:%d/#admin=%s", port, app.adminKey))
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	defer app.Close()
	go func() { <-ctx.Done(); server.Close() }()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "启动失败:", err)
		os.Exit(1)
	}
}

func runGUI() {
	app := &App{port: defaultPort}
	serveAndOpen(fmt.Sprintf("0.0.0.0:%d", defaultPort), defaultPort, app)
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	password := fs.String("password", "", "共享密码")
	port := fs.Int("port", 8600, "监听端口")
	host := fs.String("host", "0.0.0.0", "监听地址")
	noBrowser := fs.Bool("no-browser", false, "不自动打开系统浏览器")
	folder, flagArgs := splitFolder(args)
	fs.Parse(flagArgs)
	if folder == "" {
		folder = fs.Arg(0)
	}
	if folder == "" || *password == "" {
		fmt.Println("用法: filetransfer serve <文件夹> --password <密码> [--port 8600]")
		os.Exit(2)
	}
	abs, err := filepath.Abs(folder)
	if err != nil || !isDir(abs) {
		fmt.Println("文件夹不存在:", folder)
		os.Exit(1)
	}
	app := &App{port: *port, noBrowser: *noBrowser}
	s := NewSender(*password)
	s.addRoot(abs)
	app.sender = s
	serveAndOpen(fmt.Sprintf("%s:%d", *host, *port), *port, app)
}

func runPull(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	port := fs.Int("port", 8600, "监听端口")
	host := fs.String("host", "0.0.0.0", "监听地址")
	noBrowser := fs.Bool("no-browser", false, "不自动打开系统浏览器")
	dest := fs.String("dest", "", "默认下载目录（页面可改）")
	fs.Parse(args)
	if *dest != "" {
		os.MkdirAll(*dest, 0755)
	}
	app := &App{port: *port, defaultDest: *dest, noBrowser: *noBrowser}
	serveAndOpen(fmt.Sprintf("%s:%d", *host, *port), *port, app)
}

func main() {
	if len(os.Args) < 2 {
		runGUI()
		return
	}
	switch os.Args[1] {
	case "serve":
		runServe(os.Args[2:])
	case "pull", "server":
		runPull(os.Args[2:])
	default:
		fmt.Println("用法: filetransfer  （双击/无参数：打开网页界面）")
		fmt.Println("      filetransfer serve <文件夹> --password <密码>")
		fmt.Println("      filetransfer pull [--port 8601]")
		os.Exit(2)
	}
}
