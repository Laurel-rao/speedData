# FileTransfer

[English README](README.md)

FileTransfer 是一款面向可信网络的跨平台文件与文件夹传输工具，支持 Windows、macOS 和 Linux。

它采用简单可靠的工作模式：**接收方运行服务器，发送方主动上传**。接收方不需要反向连接发送方，适合网络分区、跨网段和常见防火墙环境。

> **安全边界：**默认传输协议为明文 HTTP。仅建议在可信局域网使用；处理敏感数据时，请先通过 VPN、Tailscale 或支持 TLS 的反向代理保护连接。

## 核心特性

- **跨平台：**提供 Windows、macOS、Linux 独立二进制，无需额外运行环境。
- **浏览器界面：**可在电脑或手机浏览器中管理发送、接收和进度查看。
- **文件与文件夹：**支持多选、重复添加、保留目录结构，并安全处理同名冲突。
- **可恢复传输：**支持分块传输、暂停/继续/取消、重启恢复、自动重试和完整性校验。
- **压缩传输：**可将选择内容打包为 ZIP 上传，并在接收端安全解压。
- **安全控制：**提供路径穿越防护、ZIP-slip 防护、鉴权、存储空间检查和私有缓存标记。
- **运行可观测：**显示实时进度、平滑速度、耗时、浏览器通知和传输日志。
- **协议握手：**传输开始前检查发送端与接收端版本是否兼容。

## 快速开始

### 1. 启动接收端

在用于保存文件的电脑上运行：

```bash
./filetransfer-linux-amd64
```

Windows 用户可以直接双击可执行文件。打开“接收文件”页，选择存储目录，设置接收密码，然后点击“保存并开始接收”。

复制接收地址和密码，通过可信渠道发送给发送方。

### 2. 发送文件

在发送方电脑打开 FileTransfer，粘贴接收地址和密码，测试连接，选择文件或文件夹，然后点击“发送”。

所有认证、清单、分块和进度请求均由发送方发起，接收方不需要访问发送方的入站端口。

### 3. 无桌面运行

```bash
./filetransfer-linux-amd64 serve --no-browser --port 8600
```

然后在同一可信网络中的其他设备打开 `http://服务器IP:8600`。

## 命令行

```text
filetransfer serve [directory] [--dest DIRECTORY] [--password PASSWORD] [--port 8600]
filetransfer pull  [--dest DIRECTORY] [--port 8600] [--no-browser]
```

`pull` 保留为兼容别名。使用正在运行的二进制执行 `--help` 查看完整参数。

## 从源码构建

需要 Go 1.25 或更高版本：

```bash
go test -race -cover ./...
go vet ./...
sh build-unix.sh
```

构建脚本会生成：

- `dist/filetransfer-darwin-arm64`
- `dist/filetransfer-darwin-amd64`
- `dist/filetransfer-linux-arm64`
- `dist/filetransfer-linux-amd64`

Windows 构建：

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o filetransfer.exe .
CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o filetransfer-arm64.exe .
```

## 工作原理

1. 接收端提供 HTTP API 和浏览器界面。
2. 发送端完成认证，并提交描述源文件的清单。
3. 文件通过受限并发的工作池按 4 MiB 分块上传。
4. 接收端校验分块和最终 SHA-256，再提交文件。
5. ZIP 上传在校验完成后才解压，并执行路径和目标目录检查。
6. 任务状态和私有缓存支持符合条件的任务重启后继续。

协议细节请查看 [UPLOAD_PROTOCOL.md](UPLOAD_PROTOCOL.md)。

## 项目结构

| 文件 | 作用 |
| --- | --- |
| `transfer.go` | 程序入口、内嵌界面、发送 API 和命令行 |
| `upload_server.go` | 接收端上传接口 |
| `upload_client.go` | 发送端调度器和重试逻辑 |
| `upload_stream.go` | 流式上传支持 |
| `receiver.go` | 接收端校验、持久化和恢复 |
| `storage.go` | 安全存储和冲突处理 |
| `access.go` | 鉴权和进度访问 |
| `index.html` | 浏览器界面 |
| `*_test.go` | 单元、回归、上传和平台相关测试 |

## 安全说明

- 默认 HTTP 不加密，不可信网络可能窃听密码和文件内容。
- 内置管理密码仅适合可信局域网，不应视为随机密钥。
- 应结合防火墙、VPN 或私有反向代理限制 `8600` 端口。
- 如需重启恢复，请保留 `.filetransfer-cache` 和 `.ft-jobs.json`。
- 漏洞报告请查看 [SECURITY.md](SECURITY.md)。

## 参与贡献

欢迎提交问题报告和聚焦的 Pull Request。提交前请运行格式化、静态检查、竞态测试以及相关构建。详见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可证

FileTransfer 使用 [MIT License](LICENSE) 开源。
