package engine

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFindChromePathViaEnv(t *testing.T) {
	tempFile := filepath.Join(t.TempDir(), "fake-chrome")
	if err := os.WriteFile(tempFile, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SUPASCOPE_CHROME_PATH", tempFile)
	path, err := FindChromePath()
	if err != nil {
		t.Fatalf("expected chrome path %q, got error: %v", tempFile, err)
	}
	if path != tempFile {
		t.Fatalf("expected %q, got %q", tempFile, path)
	}
}

func TestFindChromePathNotFound(t *testing.T) {
	t.Setenv("SUPASCOPE_CHROME_PATH", "/nonexistent/fake-chrome-path-12345")
	_, err := FindChromePath()
	if err == nil {
		t.Fatal("expected error for nonexistent chrome path")
	}
	var notFound *ChromeNotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ChromeNotFoundError, got %T: %v", err, err)
	}
}

func TestFindChromeProfileViaEnv(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("SUPASCOPE_CHROME_PROFILE", tempDir)
	profile, err := FindChromeProfile()
	if err != nil {
		t.Fatalf("expected profile %q, got error: %v", tempDir, err)
	}
	if profile != tempDir {
		t.Fatalf("expected %q, got %q", tempDir, profile)
	}
}

func TestCheckLiveBrowserPrereqsChromeNotFound(t *testing.T) {
	t.Setenv("SUPASCOPE_CHROME_PATH", "/nonexistent/fake-chrome-path-67890")
	err := CheckLiveBrowserPrereqs()
	if err == nil {
		t.Fatal("expected error when chrome not found")
	}
	var notFound *ChromeNotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ChromeNotFoundError, got %T: %v", err, err)
	}
}
