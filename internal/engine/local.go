package engine

import (
	"os"
	"path/filepath"
	"strings"

	"supascope/internal/detect"
	"supascope/internal/model"
)

var scanExtensions = map[string]bool{
	".html": true, ".js": true, ".jsx": true, ".ts": true, ".tsx": true,
	".css": true, ".json": true, ".map": true, ".env": true,
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
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		text := string(content)
		discoveries = append(discoveries, detect.Artifacts(text, model.Evidence{Source: "local", File: path})...)
		if strings.EqualFold(filepath.Ext(path), ".map") {
			discoveries = append(discoveries, scanSourceMap(path, text)...)
		}
		return nil
	})

	return discoveries, err
}

func shouldScan(path string) bool {
	base := filepath.Base(path)
	if strings.HasPrefix(base, ".env") {
		return true
	}
	return scanExtensions[strings.ToLower(filepath.Ext(path))]
}
