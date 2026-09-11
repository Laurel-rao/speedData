//go:build !windows

package main

import "os"

func openSourceCompatibility(base, name string, original error) (*os.File, error) {
	return nil, original
}
