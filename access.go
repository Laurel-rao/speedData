package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func decodeRequest(response http.ResponseWriter, request *http.Request, target interface{}) bool {
	decoder := json.NewDecoder(request.Body)
	if err := decoder.Decode(target); err != nil {
		writeJSON(response, 400, map[string]string{"error": "请求 JSON 格式无效"})
		return false
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		writeJSON(response, 400, map[string]string{"error": "请求必须仅含一个 JSON 对象"})
		return false
	}
	return true
}

func callbackURL(remote string, port int) (string, error) {
	return callbackURLWithRoute(remote, port, func(address string) (net.IP, error) {
		connection, err := net.DialTimeout("udp", address, 3*time.Second)
		if err != nil {
			return nil, err
		}
		defer connection.Close()
		local, ok := connection.LocalAddr().(*net.UDPAddr)
		if !ok {
			return nil, errors.New("无法识别本机出口地址")
		}
		return local.IP, nil
	})
}

func callbackURLWithRoute(remote string, port int, routeIP func(string) (net.IP, error)) (string, error) {
	validated, err := remoteURL(remote)
	if err != nil {
		return "", err
	}
	parsed, _ := url.Parse(validated)
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") || net.ParseIP(host).IsLoopback() {
		return fmt.Sprintf("http://127.0.0.1:%d", port), nil
	}
	remotePort := parsed.Port()
	if remotePort == "" {
		remotePort = "80"
		if parsed.Scheme == "https" {
			remotePort = "443"
		}
	}
	local, err := routeIP(net.JoinHostPort(host, remotePort))
	if err != nil {
		return "", fmt.Errorf("无法选择连接接收方 %s 的本机网卡：%w", host, err)
	}
	if local == nil || local.IsUnspecified() || local.IsLoopback() {
		return "", errors.New("未找到可供接收方回连的本机网卡地址")
	}
	return "http://" + net.JoinHostPort(local.String(), strconv.Itoa(port)), nil
}

func (a *App) isAdmin(request *http.Request) bool {
	return a.adminKey != "" && subtle.ConstantTimeCompare([]byte(request.Header.Get("X-FT-Admin")), []byte(a.adminKey)) == 1
}

func (a *App) protect(mux *http.ServeMux) *http.ServeMux {
	publicRead := map[string]bool{"/": true, "/api/session": true, "/api/tree": true, "/api/manifest": true, "/api/chunk": true, "/api/stats": true, "/api/progress": true}
	publicWrite := map[string]bool{"/api/auth": true, "/api/push-request": true, "/api/upload/start": true, "/api/upload/open": true, "/api/upload/finish": true, "/api/upload/status": true, "/api/upload/chunk": true, "/api/upload/fail": true}
	readRoutes := map[string]bool{"/api/info": true, "/api/state": true, "/api/log": true, "/api/monitor-state": true, "/api/send-state": true, "/api/prepare-state": true, "/api/remote": true}
	outer := http.NewServeMux()
	outer.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Frame-Options", "DENY")
		response.Header().Set("Cache-Control", "no-store")
		if origin := request.Header.Get("Origin"); origin != "" {
			parsed, err := url.Parse(origin)
			if err != nil || !strings.EqualFold(parsed.Host, request.Host) {
				writeJSON(response, 403, map[string]string{"error": "跨站请求已拒绝"})
				return
			}
		}
		if request.Header.Get("Sec-Fetch-Site") == "cross-site" && request.URL.Path != "/" {
			writeJSON(response, 403, map[string]string{"error": "跨站请求已拒绝"})
			return
		}
		path := request.URL.Path
		readOnly := publicRead[path] || readRoutes[path]
		if (readOnly && request.Method != http.MethodGet && request.Method != http.MethodPost) || (!readOnly && request.Method != http.MethodPost) || (publicRead[path] && request.Method != http.MethodGet) {
			writeJSON(response, 405, map[string]string{"error": "请求方法不允许"})
			return
		}
		if !publicRead[path] && !publicWrite[path] && !a.isAdmin(request) {
			writeJSON(response, 401, map[string]string{"error": "请先输入本机管理密码", "code": "admin_required"})
			return
		}
		if request.Method == http.MethodPost {
			contentType := "application/json"
			limit := int64(4 << 20)
			if path == "/api/upload/start" || path == "/api/upload/open" {
				limit = maxJSONBytes
			}
			if path == "/api/upload/chunk" {
				contentType = "application/octet-stream"
			}
			if !strings.HasPrefix(strings.ToLower(request.Header.Get("Content-Type")), contentType) {
				writeJSON(response, 415, map[string]string{"error": "需要 JSON 请求"})
				return
			}
			request.Body = http.MaxBytesReader(response, request.Body, limit)
		}
		mux.ServeHTTP(response, request)
	})
	return outer
}

func (a *App) pullerList() []*Puller {
	a.mu.Lock()
	defer a.mu.Unlock()
	list := make([]*Puller, 0, len(a.pullers)+1)
	for _, puller := range a.pullers {
		list = append(list, puller)
	}
	if len(list) == 0 && a.puller != nil {
		list = append(list, a.puller)
	}
	return list
}

func (a *App) Close() {
	a.mu.Lock()
	uploaders := make([]*Uploader, 0, len(a.uploaders))
	for _, uploader := range a.uploaders {
		uploaders = append(uploaders, uploader)
	}
	a.mu.Unlock()
	for _, uploader := range uploaders {
		uploader.Close()
	}
	for _, puller := range a.pullerList() {
		puller.Close()
	}
}

func (a *App) acquirePuller(baseURL, token, dest, policy string) (*Puller, bool, error) {
	abs, err := filepath.Abs(dest)
	if err != nil {
		return nil, false, err
	}
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	key := baseURL + "\n" + abs
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pullers == nil {
		a.pullers = map[string]*Puller{}
	}
	if existing := a.pullers[key]; existing != nil {
		existing.mu.Lock()
		existing.token = token
		existing.mu.Unlock()
		a.puller = existing
		return existing, false, nil
	}
	puller := NewPuller(baseURL, token, abs, policy)
	if puller.initErr != nil {
		puller.Close()
		return nil, false, puller.initErr
	}
	a.pullers[key] = puller
	a.puller = puller
	return puller, true, nil
}

func combineStates(states []map[string]interface{}) map[string]interface{} {
	files := make([]map[string]interface{}, 0)
	archives := make([]archiveMeta, 0)
	var totalBytes, doneBytes, elapsed int64
	var speed float64
	total, done, active, pending, failed := 0, 0, 0, 0, 0
	allDone := len(states) > 0
	dest := ""
	for _, state := range states {
		if values, ok := state["files"].([]map[string]interface{}); ok {
			files = append(files, values...)
		}
		if values, ok := state["archives"].([]archiveMeta); ok {
			archives = append(archives, values...)
		}
		totalBytes += numberInt64(state["total_bytes"])
		doneBytes += numberInt64(state["done_bytes"])
		elapsed = max(elapsed, numberInt64(state["elapsed"]))
		total += int(numberInt64(state["total"]))
		done += int(numberInt64(state["done"]))
		active += int(numberInt64(state["active"]))
		pending += int(numberInt64(state["pending"]))
		failed += int(numberInt64(state["errors"]))
		if value, ok := state["speed"].(float64); ok {
			speed += value
		}
		if state["all_done"] != true {
			allDone = false
		}
		if value, ok := state["dest"].(string); ok {
			dest = value
		}
	}
	sort.Slice(files, func(left, right int) bool { return fmt.Sprint(files[left]["id"]) < fmt.Sprint(files[right]["id"]) })
	result := map[string]interface{}{"connected": len(states) > 0, "files": files, "archives": archives, "total_bytes": totalBytes, "done_bytes": doneBytes, "speed": speed, "elapsed": elapsed, "total": total, "done": done, "active": active, "pending": pending, "errors": failed, "all_done": allDone && total > 0, "dest": dest}
	if len(archives) > 0 {
		result["archive"] = archives[len(archives)-1]
	}
	return result
}

func numberInt64(value interface{}) int64 {
	switch typed := value.(type) {
	case int:
		return int64(typed)
	case int64:
		return typed
	case float64:
		return int64(typed)
	}
	return 0
}

func (a *App) receiveState(source string) map[string]interface{} {
	var states []map[string]interface{}
	for _, puller := range a.pullerList() {
		if source == "" || puller.baseURL == source {
			states = append(states, puller.state())
		}
	}
	return combineStates(states)
}

func (a *App) control(action, path string) {
	for _, puller := range a.pullerList() {
		if path == "" {
			puller.control(action, "")
			continue
		}
		prefix := puller.id + ":"
		if strings.HasPrefix(path, prefix) {
			puller.control(action, strings.TrimPrefix(path, prefix))
		}
	}
}

func (a *App) sendState() map[string]interface{} {
	a.mu.Lock()
	monitors := make([]*Monitor, 0, len(a.outgoing))
	for _, monitor := range a.outgoing {
		monitors = append(monitors, monitor)
	}
	a.mu.Unlock()
	var states []map[string]interface{}
	for _, monitor := range monitors {
		var progress struct {
			Role  string                 `json:"role"`
			State map[string]interface{} `json:"state"`
		}
		if err := monitor.getJSON("/api/progress", &progress); err != nil || progress.Role != "receiver" || progress.State == nil {
			return map[string]interface{}{"connected": false, "error": "与接收方连接中断，正在重试"}
		}
		state := progress.State
		if values, ok := state["files"].([]interface{}); ok {
			files := make([]map[string]interface{}, 0, len(values))
			for _, value := range values {
				if file, ok := value.(map[string]interface{}); ok {
					file["id"] = monitor.baseURL + ":" + fmt.Sprint(file["id"])
					files = append(files, file)
				}
			}
			state["files"] = files
		}
		if values, ok := state["archives"]; ok {
			data, _ := json.Marshal(values)
			var archives []archiveMeta
			if json.Unmarshal(data, &archives) == nil {
				state["archives"] = archives
			}
		}
		states = append(states, state)
	}
	return combineStates(states)
}

func remoteURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed == nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("请输入完整的 http:// 或 https:// 主机地址（不带路径或查询参数）")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func (a *App) registerOutgoing(remote, password, source string) error {
	info, err := authRemote(remote, password)
	if err != nil {
		return err
	}
	monitor := &Monitor{baseURL: remote, token: info.Token, name: info.Name, source: source, client: &http.Client{Timeout: 5 * time.Second}}
	a.mu.Lock()
	if a.outgoing == nil {
		a.outgoing = map[string]*Monitor{}
	}
	a.outgoing[remote] = monitor
	a.mu.Unlock()
	return nil
}
