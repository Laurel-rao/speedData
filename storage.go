package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const cacheDirectory = ".filetransfer-cache"
const cacheMarker = "FileTransfer private cache v2\n"

var storageLocks sync.Map
var cacheSetup sync.Mutex

func storageLock(dest string) *sync.Mutex {
	key := filepath.Clean(dest)
	value, _ := storageLocks.LoadOrStore(key, &sync.Mutex{})
	return value.(*sync.Mutex)
}

func incomingPath(rel string) (string, error) {
	if err := checkRel(rel); err != nil {
		return "", err
	}
	rel = filepath.ToSlash(filepath.Clean(filepath.FromSlash(strings.ReplaceAll(rel, "\\", "/"))))
	first := strings.Split(rel, "/")[0]
	if rel == "." || strings.EqualFold(first, cacheDirectory) || strings.EqualFold(first, jobStateFile) || strings.EqualFold(first, logFile) {
		return "", errors.New("路径使用了程序保留名称")
	}
	return rel, nil
}

func openStore(dest string) (*os.Root, error) {
	if err := os.MkdirAll(dest, 0755); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		return nil, err
	}
	cacheSetup.Lock()
	defer cacheSetup.Unlock()
	info, statErr := root.Lstat(cacheDirectory)
	if errors.Is(statErr, os.ErrNotExist) {
		if err = root.Mkdir(cacheDirectory, 0700); err == nil {
			err = root.WriteFile(cacheDirectory+"/owner", []byte(cacheMarker), 0600)
		}
	} else if statErr != nil {
		err = statErr
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		err = errors.New("缓存路径不是安全目录")
	} else {
		var marker []byte
		marker, err = root.ReadFile(cacheDirectory + "/owner")
		if err == nil && string(marker) != cacheMarker {
			err = errors.New("已有同名目录不属于 FileTransfer，拒绝使用或清理")
		}
	}
	if err != nil {
		root.Close()
		return nil, err
	}
	return root, nil
}

func rootAtomicWrite(root *os.Root, path string, data []byte) error {
	temp := path + "." + newToken() + ".tmp"
	file, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(temp)
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return root.Rename(temp, path)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextReader) Read(data []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(data)
}

func fileDigest(ctx context.Context, reader io.Reader) (string, error) {
	hash := sha256.New()
	_, err := io.Copy(hash, contextReader{ctx: ctx, reader: reader})
	return hex.EncodeToString(hash.Sum(nil)), err
}

func copyExclusive(root *os.Root, source, target string) error {
	input, err := root.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := root.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	_, err = io.Copy(output, input)
	if err == nil {
		err = output.Sync()
	}
	closeErr := output.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		root.Remove(target)
	}
	return err
}

func commitFile(root *os.Root, source, target, policy string) (string, bool, error) {
	if err := root.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return "", false, err
	}
	if policy == "overwrite" {
		return target, false, root.Rename(source, target)
	}
	ext := filepath.Ext(target)
	base := strings.TrimSuffix(target, ext)
	for index := 0; index < 100000; index++ {
		candidate := target
		if index > 0 {
			candidate = fmt.Sprintf("%s (%d)%s", base, index, ext)
		}
		if info, err := root.Lstat(candidate); err == nil {
			if policy == "skip" && info.Mode().IsRegular() {
				return candidate, true, nil
			}
			if policy == "skip" {
				return "", false, errors.New("目标已存在且不是普通文件")
			}
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", false, err
		}
		err := root.Link(source, candidate)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			err = copyExclusive(root, source, candidate)
			if errors.Is(err, os.ErrExist) {
				continue
			}
		}
		if err != nil {
			return "", false, err
		}
		root.Remove(source)
		return candidate, false, nil
	}
	return "", false, errors.New("同名文件过多，无法安全选择目标名称")
}
