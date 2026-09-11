package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var finalPathByHandle = syscall.NewLazyDLL("kernel32.dll").NewProc("GetFinalPathNameByHandleW")

func sourceHandlePath(file *os.File) (string, error) {
	buffer := make([]uint16, 512)
	for {
		length, _, callErr := finalPathByHandle.Call(file.Fd(), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0)
		if length == 0 {
			return "", callErr
		}
		if length < uintptr(len(buffer)) {
			return syscall.UTF16ToString(buffer[:length]), nil
		}
		if length > 32768 {
			return "", errors.New("实际路径过长")
		}
		buffer = make([]uint16, length+1)
	}
}

func openSourceCompatibility(base, name string, original error) (*os.File, error) {
	if !errors.Is(original, syscall.Errno(87)) {
		return nil, original
	}
	file, err := openVerifiedSource(base, name)
	if err != nil {
		return nil, fmt.Errorf("安全读取失败（%v），Windows 兼容读取失败：%w", original, err)
	}
	return file, nil
}

func openVerifiedSource(base, name string) (*os.File, error) {
	if err := checkRel(name); err != nil {
		return nil, err
	}
	directory, err := os.Open(base)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	info, err := directory.Stat()
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("共享根不是目录")
	}
	rootPath, err := sourceHandlePath(directory)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(filepath.Join(rootPath, filepath.FromSlash(name)))
	if err != nil {
		return nil, err
	}
	accepted := false
	defer func() {
		if !accepted {
			file.Close()
		}
	}()
	filePath, err := sourceHandlePath(file)
	if err != nil {
		return nil, err
	}
	currentRoot, err := sourceHandlePath(directory)
	if err != nil {
		return nil, err
	}
	if currentRoot != rootPath || !strings.HasPrefix(filePath, strings.TrimRight(rootPath, `\`)+`\`) {
		return nil, errors.New("源文件实际路径越出共享目录")
	}
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !fileInfo.Mode().IsRegular() {
		return nil, errors.New("源文件不是普通文件")
	}
	accepted = true
	return file, nil
}
