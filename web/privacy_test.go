package web

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

func TestBundlePrivacy(t *testing.T) {
	urlRe := regexp.MustCompile(`https?://[^\s"'<>)]+`)
	protoRel := regexp.MustCompile(`(?:src|href)\s*=\s*["']//`)
	err := fs.WalkDir(FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := FS.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(b)
		for _, m := range urlRe.FindAllString(text, -1) {
			if m == "http://www.w3.org/2000/svg" || m == "http://www.w3.org/1999/xlink" || strings.HasPrefix(m, "http://www.w3.org/2000/svg") {
				continue
			}
			t.Errorf("%s contains external URL %s", path, m)
		}
		if protoRel.MatchString(text) {
			t.Errorf("%s contains a protocol-relative URL", path)
		}
		low := strings.ToLower(text)
		if strings.Contains(low, "<script") {
			for _, part := range strings.Split(low, "<script")[1:] {
				tag := part
				if i := strings.Index(tag, ">"); i >= 0 {
					tag = tag[:i]
				}
				if !strings.Contains(tag, "src=") {
					continue
				}
				if strings.Contains(tag, "http:") || strings.Contains(tag, "https:") || strings.Contains(tag, "src=\"//") || strings.Contains(tag, "src='//") {
					t.Errorf("%s loads a third-party script", path)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
