package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckRel(t *testing.T) {
	bad := []string{
		"", "..", "../x", "..\\x", "a/../../b", "a\\..\\..\\b",
		"/etc/passwd", "//server/share/x", "C:\\Windows\\x", "C:/Windows/x",
		"d:evil.txt",
	}
	for _, s := range bad {
		if err := checkRel(s); err == nil {
			t.Errorf("checkRel(%q) 应当被拒绝", s)
		}
	}
	good := []string{
		"a.txt", "sub/a.txt", "a/b/c.txt", "中文 文件.txt", "emoji😀/x.y",
		"a/./b.txt", `back\slash ok.txt`,
	}
	for _, s := range good {
		if err := checkRel(s); err != nil {
			t.Errorf("checkRel(%q) 误拒: %v", s, err)
		}
	}
}

func TestUniqueName(t *testing.T) {
	dir := t.TempDir()
	name := "file.txt"
	os.WriteFile(filepath.Join(dir, name), []byte("x"), 0644)
	os.WriteFile(filepath.Join(dir, "file (1).txt"), []byte("x"), 0644)

	got := uniqueName(dir, name)
	want := filepath.Join(dir, "file (2).txt")
	if got != want {
		t.Fatalf("uniqueName 期望 %s 得到 %s", want, got)
	}
}

func TestFreeSpace(t *testing.T) {
	free, err := freeSpace(t.TempDir())
	if err != nil {
		t.Fatalf("freeSpace: %v", err)
	}
	if free == 0 {
		t.Fatal("freeSpace 返回 0，磁盘检测可能有问题")
	}
	t.Logf("free space: %d", free)
}

// TestSenderMultiRoot 验证：多根共享时列表带「根名/」前缀、可解析、可移除。
func TestSenderMultiRoot(t *testing.T) {
	d1 := t.TempDir()
	d2 := t.TempDir()
	os.WriteFile(filepath.Join(d1, "a.txt"), []byte("one"), 0644)
	os.WriteFile(filepath.Join(d2, "b.txt"), []byte("two"), 0644)

	s := NewSender("pw")
	if _, err := s.addRoot(d1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.addRoot(d2); err != nil {
		t.Fatal(err)
	}
	if len(s.rootList()) != 2 {
		t.Fatalf("应有 2 个根，实际 %d", len(s.rootList()))
	}
	files, err := s.walk()
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, f := range files {
		paths[f.Path] = true
	}
	// 多根时必须带虚拟前缀
	if !paths[filepath.Base(d1)+"/a.txt"] || !paths[filepath.Base(d2)+"/b.txt"] {
		t.Fatalf("多根列表应为 根名/文件 形式，实际: %v", files)
	}
	// 能按虚拟路径解析并取到清单
	man, err := s.manifest(filepath.Base(d1) + "/a.txt")
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if man.Size != 3 {
		t.Fatalf("a.txt 大小应为 3，实际 %d", man.Size)
	}
	// 未知根必须报错
	if _, err := s.manifest("不存在的根/x.txt"); err == nil {
		t.Fatal("未知根应报错")
	}
	// 移除一个根后，剩余文件仍带「根名/」前缀（路径稳定，不随根数量变化）
	s.removeRoot(filepath.Base(d1))
	files, _ = s.walk()
	flat := map[string]bool{}
	for _, f := range files {
		flat[f.Path] = true
	}
	if !flat[filepath.Base(d2)+"/b.txt"] {
		t.Fatalf("移除根后仍应带根名前缀，实际: %v", files)
	}
	// 单根时也兼容无前缀的旧路径
	if _, err := s.manifest("b.txt"); err != nil {
		t.Fatalf("单根应兼容无前缀路径: %v", err)
	}
}
