# 文件与文件夹选择版本

此目录是本次功能的独立可运行构建：以本任务开始时的稳定传输引擎为基础，加入文件选择、文件夹混选、重叠选择去重及既有压缩进度。没有合入工作区中尚未通过测试的并行流式上传改动，也没有回退或覆盖该部分源码。

## 运行文件

| 平台 | 文件 |
| --- | --- |
| Windows x64 | `filetransfer.exe` |
| Windows ARM64 | `filetransfer-arm64.exe` |
| Mac M 系列 | `filetransfer-darwin-arm64` |
| Mac Intel | `filetransfer-darwin-amd64` |
| Linux x64 | `filetransfer-linux-amd64` |
| Linux ARM64 | `filetransfer-linux-arm64` |

Windows 双击对应 exe。Mac/Linux 在终端中进入此目录后运行对应文件，例如 `./filetransfer-darwin-arm64`。程序默认使用 8600 端口，替换使用前请先关闭占用该端口的旧程序；也可使用 `pull --port 8601` 在其他端口启动。

发送页可分别选择文件和文件夹，可重复添加并混合发送。文件夹保留结构，单独选择的文件直接按文件名落盘，不会发送同级其他文件。两种压缩模式、追加文件、中文与含分号文件名均有测试覆盖。系统选择窗口出现在运行程序的电脑上。

## 验证范围

该快照通过 `go test -race ./...` 和 `go vet ./...`，并成功构建六个系统/架构版本。界面在应用内浏览器以 1280×900 和 390×844 验证，文件选择回填和取消使用模拟系统命令返回；真实本机文件读取、混合上传与接收内容校验已经验证。没有声称完成 Windows/Linux 或 Mac 原生文件选择对话框的实机交互验收。

`SHA256SUMS` 用于检查运行文件；`source-snapshot.tar.gz` 保存本次构建的源码与测试，`SOURCE_SHA256SUMS` 对应该源码快照，而非并行修改中的当前工作区。
