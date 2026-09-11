# FileTransfer

[中文说明](README.zh-CN.md)

A secure-by-design, peer-directed file and folder transfer tool for Windows, macOS, and Linux over trusted networks.

FileTransfer uses a simple model: the **receiver runs a server**, while the **sender actively uploads** files to it. The receiver never needs to connect back to the sender, which makes the tool practical across segmented LANs and common firewall configurations.

> **Current security boundary:** the default transport is plain HTTP. Use FileTransfer only on a trusted network, or protect it with a VPN/Tailscale/reverse-proxy TLS layer before handling sensitive data.

## Highlights

- **Cross-platform:** standalone binaries for Windows, macOS, and Linux; no runtime installation required.
- **Browser UI:** manage sending, receiving, and progress monitoring from a desktop or phone browser.
- **Files and folders:** select multiple files and folders, preserve directory structure, and handle name conflicts safely.
- **Resumable uploads:** chunked transfer, pause/resume/cancel, restart recovery, retries, and integrity verification.
- **Compression:** optionally package a selection as ZIP before upload and extract it safely on the receiver.
- **Safety controls:** path traversal protection, ZIP-slip protection, authentication, storage checks, and private cache ownership markers.
- **Operational visibility:** live progress, smoothed speed, elapsed time, browser notifications, and transfer logs.
- **Protocol handshake:** incompatible sender/receiver versions are detected before a transfer begins.

## Quick Start

### 1. Start the receiver

On the computer that will store the files:

```bash
./filetransfer-linux-amd64
```

Or double-click the Windows executable. Open the **Receive** tab, choose a destination directory, set a receiving password, and click **Save and Start Receiving**.

Copy the receiver address and password, then send them to the sender through a trusted channel.

### 2. Send files

On the sender computer, open FileTransfer, paste the receiver address and password, test the connection, select files or folders, and click **Send**.

The sender initiates all authentication, manifest, chunk, and progress requests. The receiver does not need an inbound connection to the sender.

### 3. Run without a desktop

```bash
./filetransfer-linux-amd64 serve --no-browser --port 8600
```

Then open `http://SERVER_IP:8600` from a browser on the same trusted network.

## Command Line

```text
filetransfer serve [directory] [--dest DIRECTORY] [--password PASSWORD] [--port 8600]
filetransfer pull  [--dest DIRECTORY] [--port 8600] [--no-browser]
```

`pull` is retained as a compatibility alias. Use `--help` for the options supported by the binary you are running.

## Build from Source

Requires Go 1.25 or newer:

```bash
go test -race -cover ./...
go vet ./...
sh build-unix.sh
```

The build script produces:

- `dist/filetransfer-darwin-arm64`
- `dist/filetransfer-darwin-amd64`
- `dist/filetransfer-linux-arm64`
- `dist/filetransfer-linux-amd64`

Windows builds:

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o filetransfer.exe .
CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o filetransfer-arm64.exe .
```

## How It Works

1. The receiver exposes the HTTP API and browser UI.
2. The sender authenticates and submits a manifest describing each source.
3. Files are uploaded in 4 MiB chunks using a bounded worker pool.
4. The receiver validates chunks and final SHA-256 integrity before committing data.
5. ZIP uploads are extracted only after validation, with path and destination checks.
6. Job state and private cache data allow eligible transfers to resume after restart.

The wire-level details are documented in [UPLOAD_PROTOCOL.md](UPLOAD_PROTOCOL.md).

## Project Layout

| File | Purpose |
| --- | --- |
| `transfer.go` | Application entry point, embedded UI, sender API, and CLI |
| `upload_server.go` | Receiver upload endpoints |
| `upload_client.go` | Sender upload scheduler and retries |
| `upload_stream.go` | Streaming upload support |
| `receiver.go` | Receiver-side validation, persistence, and recovery |
| `storage.go` | Safe storage and conflict handling |
| `access.go` | Authentication and progress access |
| `index.html` | Browser interface |
| `*_test.go` | Unit, regression, upload, and platform-specific tests |

## Security Notes

- Default HTTP traffic is not encrypted; passwords and file contents can be observed on an untrusted network.
- The built-in management password is intended for trusted LAN use only and should not be treated as a random secret.
- Restrict port `8600` with a firewall, VPN, or private reverse proxy when appropriate.
- Keep `.filetransfer-cache` and `.ft-jobs.json` together if you need restart recovery.
- See [SECURITY.md](SECURITY.md) for responsible vulnerability reporting.

## Contributing

Bug reports and focused pull requests are welcome. Before submitting changes, run formatting, static analysis, race-enabled tests, and the relevant build targets. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

FileTransfer is released under the [MIT License](LICENSE).
