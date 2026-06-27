package engine

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const harSuggestion = "Use --har for offline scanning with an exported browser network log."

type ChromeNotFoundError struct {
	msg string
}

func (e *ChromeNotFoundError) Error() string {
	return e.msg
}

type ChromeRunningError struct {
	msg string
}

func (e *ChromeRunningError) Error() string {
	return e.msg
}

func FindChromePath() (string, error) {
	candidates := chromePathCandidates()
	for _, candidate := range candidates {
		if fileExists(candidate) {
			return candidate, nil
		}
	}
	return "", &ChromeNotFoundError{
		msg: fmt.Sprintf("Chrome not found. Install Google Chrome or use --har for offline scanning. %s", harSuggestion),
	}
}

func chromePathCandidates() []string {
	if path := strings.TrimSpace(os.Getenv("SUPASCOPE_CHROME_PATH")); path != "" {
		return []string{path}
	}

	switch runtime.GOOS {
	case "windows":
		return windowsChromePaths()
	case "darwin":
		return []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			filepath.Join(os.Getenv("HOME"), "Applications", "Google Chrome.app", "Contents", "MacOS", "Google Chrome"),
		}
	default:
		return []string{
			"/usr/bin/google-chrome",
			"/usr/bin/google-chrome-stable",
			"/usr/bin/chromium",
			"/usr/bin/chromium-browser",
			"/snap/bin/chromium",
			"/snap/bin/google-chrome",
		}
	}
}

func windowsChromePaths() []string {
	var paths []string
	localAppData := os.Getenv("LOCALAPPDATA")
	programFiles := os.Getenv("ProgramFiles")
	programFilesX86 := os.Getenv("ProgramFiles(x86)")

	if localAppData != "" {
		paths = append(paths, filepath.Join(localAppData, "Google", "Chrome", "Application", "chrome.exe"))
	}
	if programFiles != "" {
		paths = append(paths, filepath.Join(programFiles, "Google", "Chrome", "Application", "chrome.exe"))
	}
	if programFilesX86 != "" {
		paths = append(paths, filepath.Join(programFilesX86, "Google", "Chrome", "Application", "chrome.exe"))
	}
	return paths
}

func FindChromeProfile() (string, error) {
	profile := chromeProfilePath()
	if profile == "" {
		return "", errors.New("could not determine Chrome user profile directory")
	}
	return profile, nil
}

func chromeProfilePath() string {
	if path := strings.TrimSpace(os.Getenv("SUPASCOPE_CHROME_PROFILE")); path != "" {
		return path
	}

	switch runtime.GOOS {
	case "windows":
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData == "" {
			return ""
		}
		return filepath.Join(localAppData, "Google", "Chrome", "User Data")
	case "darwin":
		home := os.Getenv("HOME")
		if home == "" {
			return ""
		}
		return filepath.Join(home, "Library", "Application Support", "Google", "Chrome")
	default:
		home := os.Getenv("HOME")
		if home == "" {
			return ""
		}
		return filepath.Join(home, ".config", "google-chrome")
	}
}

func IsChromeRunning() bool {
	switch runtime.GOOS {
	case "windows":
		return windowsChromeRunning()
	default:
		return unixChromeRunning()
	}
}

func windowsChromeRunning() bool {
	cmd := exec.Command("tasklist", "/FI", "IMAGENAME eq chrome.exe", "/FO", "CSV", "/NH")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(output)), "chrome.exe")
}

func unixChromeRunning() bool {
	for _, name := range []string{"google-chrome", "chrome", "chromium", "chromium-browser"} {
		cmd := exec.Command("pgrep", "-x", name)
		if err := cmd.Run(); err == nil {
			return true
		}
	}
	return false
}

func CheckLiveBrowserPrereqs() error {
	if _, err := FindChromePath(); err != nil {
		return err
	}
	if IsChromeRunning() {
		return &ChromeRunningError{
			msg: "Chrome is already running. Close all Chrome windows so SupaScope can launch with debugging enabled, then re-run. Alternatively, use --har for offline scanning.",
		}
	}
	return nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
