package engine

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"supascope/internal/detect"
	"supascope/internal/model"
)

type harFile struct {
	Log struct {
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}

type harEntry struct {
	Request struct {
		Method   string      `json:"method"`
		URL      string      `json:"url"`
		Headers  []harHeader `json:"headers"`
		PostData struct {
			Text string `json:"text"`
		} `json:"postData"`
	} `json:"request"`
	Response struct {
		Content struct {
			Text     string `json:"text"`
			Encoding string `json:"encoding"`
		} `json:"content"`
	} `json:"response"`
}

type harHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func ScanHAR(path string) ([]model.Discovery, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var parsed harFile
	if err := json.Unmarshal(content, &parsed); err != nil {
		return nil, fmt.Errorf("invalid HAR file %q: %w", path, err)
	}

	var discoveries []model.Discovery
	for _, entry := range parsed.Log.Entries {
		entryURL := strings.TrimSpace(entry.Request.URL)
		if entryURL == "" {
			continue
		}
		detail := strings.TrimSpace(strings.Join([]string{entry.Request.Method, entryURL}, " "))
		evidence := model.Evidence{Source: "har", File: path, URL: entryURL, Detail: detail}
		discoveries = append(discoveries, detect.Artifacts(entryURL, evidence)...)

		if headers := harHeadersText(entry.Request.Headers); headers != "" {
			discoveries = append(discoveries, detect.Artifacts(headers, evidence)...)
		}
		if entry.Request.PostData.Text != "" {
			discoveries = append(discoveries, detect.Artifacts(entry.Request.PostData.Text, evidence)...)
		}
		if responseText := harResponseText(entry.Response.Content.Text, entry.Response.Content.Encoding); responseText != "" {
			discoveries = append(discoveries, detect.Artifacts(responseText, evidence)...)
		}
	}

	return discoveries, nil
}

func harHeadersText(headers []harHeader) string {
	var b strings.Builder
	for _, header := range headers {
		name := strings.TrimSpace(header.Name)
		value := strings.TrimSpace(header.Value)
		if name == "" || value == "" {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\n", name, value)
	}
	return b.String()
}

func harResponseText(text string, encoding string) string {
	if !strings.EqualFold(strings.TrimSpace(encoding), "base64") {
		return text
	}
	decoded, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return ""
	}
	return string(decoded)
}
