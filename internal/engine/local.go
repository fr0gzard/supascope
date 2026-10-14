package engine

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"supascope/internal/detect"
	"supascope/internal/model"
)

var scanExtensions = map[string]bool{
	".html": true, ".js": true, ".mjs": true, ".cjs": true, ".jsx": true,
	".ts": true, ".tsx": true, ".css": true, ".json": true, ".map": true,
	".env": true,
}

func ScanLocal(root string) ([]model.Discovery, error) {
	var discoveries []model.Discovery

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "node_modules" || name == "dist" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !shouldScan(path) {
			return nil
		}
		// Mirror the 8MB static fetch cap: build output can contain huge
		// bundles that would otherwise OOM the scanner.
		content, err := readFileCapped(path, 8*1024*1024)
		if err != nil {
			return nil
		}
		text := string(content)
		if strings.EqualFold(filepath.Ext(path), ".map") {
			if mapDiscoveries, ok := scanSourceMap(path, text); ok {
				discoveries = append(discoveries, mapDiscoveries...)
				return nil
			}
		}
		discoveries = append(discoveries, detect.Artifacts(text, model.Evidence{Source: "local", File: path})...)
		return nil
	})

	return discoveries, err
}

// readFileCapped reads a file up to maxBytes, skipping files that exceed the
// cap instead of loading them fully into memory.
func readFileCapped(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > maxBytes {
		return nil, fmt.Errorf("file %s exceeds size cap (%d bytes), skipped", path, maxBytes)
	}
	return io.ReadAll(io.LimitReader(f, maxBytes))
}

func shouldScan(path string) bool {
	base := filepath.Base(path)
	if strings.HasPrefix(base, ".env") {
		return true
	}
	return scanExtensions[strings.ToLower(filepath.Ext(path))]
}
