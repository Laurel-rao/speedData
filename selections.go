package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

func pickFile() (string, error) {
	if runtime.GOOS == "windows" {
		return pickWindows("OpenFileDialog", "Title", "FileName", "文件")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.CommandContext(ctx, "osascript", "-e", "set f to choose file", "-e", "POSIX path of f")
	case "linux":
		if executable, err := exec.LookPath("zenity"); err == nil {
			command = exec.CommandContext(ctx, executable, "--file-selection", "--title=FileTransfer - Select file")
		} else if executable, err := exec.LookPath("kdialog"); err == nil {
			command = exec.CommandContext(ctx, executable, "--getopenfilename")
		} else {
			return "", errors.New("未找到图形选择工具（zenity/kdialog），请手动输入文件路径")
		}
	default:
		return "", errors.New("当前系统不支持弹窗，请手动输入文件路径")
	}
	output, err := command.Output()
	if ctx.Err() != nil {
		return "", errors.New("选择文件超时，请重试或手动输入路径")
	}
	if err != nil {
		return "", fmt.Errorf("未选择文件或无法打开选择窗口，请重试或手动输入路径：%w", err)
	}
	path := strings.TrimSpace(string(output))
	if path == "" {
		return "", errors.New("未选择文件")
	}
	return path, nil
}

func openSelectedFile(path string) (*os.File, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	name := filepath.Base(path)
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("所选文件已变为不支持的文件类型")
	}
	file, err := openSourceFile(root, name)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		file.Close()
		return nil, errors.New("所选文件在打开期间发生变化，请重试")
	}
	return file, nil
}

type selectedFile struct {
	path string
	name string
	size int64
}

func sourcePathKey(path string) string {
	key := filepath.Clean(path)
	if runtime.GOOS == "windows" {
		key = strings.ToLower(key)
	}
	return key
}

func (sender *Sender) selectedFiles(paths []string, progress *preparation) ([]selectedFile, error) {
	var selected []sharedRoot
	roots := sender.rootList()
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			return nil, errors.New("请选择文件或文件夹，路径不能为空")
		}
		abs, err := filepath.Abs(strings.TrimSpace(path))
		if err != nil {
			return nil, err
		}
		found := false
		for _, root := range roots {
			if !root.Test && sourcePathKey(root.Path) == sourcePathKey(abs) {
				selected = append(selected, root)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("文件或文件夹未添加：%s", path)
		}
	}
	sort.SliceStable(selected, func(left, right int) bool {
		if selected[left].File != selected[right].File {
			return !selected[left].File
		}
		return len(selected[left].Path) < len(selected[right].Path)
	})
	seen := map[string]bool{}
	var files []selectedFile
	for _, root := range selected {
		err := filepath.Walk(root.Path, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if root.File && !info.Mode().IsRegular() {
				return fmt.Errorf("所选文件已变为不支持的文件类型：%s", path)
			}
			if info.IsDir() {
				if info.Name() == cacheDirectory {
					return filepath.SkipDir
				}
				return nil
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("不支持的文件类型：%s", path)
			}
			key := sourcePathKey(path)
			if seen[key] {
				return nil
			}
			name := root.Name
			if !root.File {
				rel, err := filepath.Rel(root.Path, path)
				if err != nil {
					return err
				}
				name += "/" + filepath.ToSlash(rel)
			}
			if _, err := incomingPath(name); err != nil {
				return err
			}
			seen[key] = true
			files = append(files, selectedFile{path: path, name: name, size: info.Size()})
			progress.update(func(state *preparationState) {
				state.Current = name
				state.TotalFiles++
				state.TotalBytes += info.Size()
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(files, func(left, right int) bool { return files[left].name < files[right].name })
	return files, nil
}
