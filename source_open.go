package main

import (
	"os"
	"path/filepath"
)

func openSourceFile(root *os.Root, rel string) (*os.File, error) {
	if err := checkRel(rel); err != nil {
		return nil, err
	}
	name := filepath.FromSlash(rel)
	file, err := root.Open(name)
	if err == nil {
		return file, nil
	}
	return openSourceCompatibility(root.Name(), name, err)
}
