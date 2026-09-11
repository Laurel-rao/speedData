//go:build !windows

package main

import "syscall"

// freeSpace 返回 path 所在文件系统对当前用户可用的空闲字节数。
func freeSpace(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}
