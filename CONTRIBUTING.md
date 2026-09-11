# 参与贡献

感谢参与 FileTransfer。提交 Issue 或 Pull Request 前，请先确认问题可以在当前版本复现，并尽量提供操作系统、Go 版本、日志片段和最小复现步骤。

## 开发检查

```bash
gofmt -w .
go vet ./...
go test -race -cover ./...
sh build-unix.sh
```

请不要提交本地日志、任务状态文件、缓存目录或未说明来源的二进制文件。涉及协议、鉴权、路径安全和断点续传的改动，应同时补充测试与 `UPLOAD_PROTOCOL.md` 文档。
