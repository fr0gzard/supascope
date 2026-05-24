package engine

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"supascope/internal/detect"
	"supascope/internal/model"
)

type DynamicOptions struct {
	UserAgent          string
	Headers            map[string]string
	Wait               time.Duration
	BrowserDebuggerURL string
	Interactive        bool
	Debug              bool
}

type networkObservation struct {
	Source string
	URL    string
	Detail string
	Text   string
}

func ScanDynamic(ctx context.Context, target string, opts DynamicOptions) ([]model.Discovery, error) {
	var allocCtx context.Context
	var cancelAlloc context.CancelFunc
	if strings.TrimSpace(opts.BrowserDebuggerURL) != "" {
		allocCtx, cancelAlloc = chromedp.NewRemoteAllocator(ctx, opts.BrowserDebuggerURL)
	} else {
		allocOptions := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("headless", !opts.Interactive))
		allocCtx, cancelAlloc = chromedp.NewExecAllocator(ctx, allocOptions...)
	}
	defer cancelAlloc()

	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()

	if opts.Wait <= 0 {
		opts.Wait = 2 * time.Second
	}
	browserCtx, cancelTimeout := context.WithTimeout(browserCtx, opts.Wait+30*time.Second)
	defer cancelTimeout()

	var mu sync.Mutex
	observations := make([]networkObservation, 0)
	addObservation := func(observation networkObservation) {
		if strings.TrimSpace(observation.Text) == "" {
			return
		}
		mu.Lock()
		observations = append(observations, observation)
		mu.Unlock()
	}

	chromedp.ListenTarget(browserCtx, func(event any) {
		switch event := event.(type) {
		case *network.EventRequestWillBeSent:
			if event.Request == nil {
				return
			}
			detail := strings.TrimSpace(strings.Join([]string{event.Request.Method, event.Request.URL}, " "))
			addObservation(networkObservation{Source: "dynamic_network", URL: event.Request.URL, Detail: detail, Text: event.Request.URL})
			addObservation(networkObservation{Source: "dynamic_network", URL: event.Request.URL, Detail: detail, Text: headersText(event.Request.Headers)})
			addObservation(networkObservation{Source: "dynamic_network", URL: event.Request.URL, Detail: detail, Text: postDataEntriesText(event.Request.PostDataEntries)})
		case *network.EventResponseReceived:
			if event.Response == nil {
				return
			}
			detail := fmt.Sprintf("response %d %s", event.Response.Status, event.Response.URL)
			addObservation(networkObservation{Source: "dynamic_network", URL: event.Response.URL, Detail: detail, Text: event.Response.URL})
			addObservation(networkObservation{Source: "dynamic_network", URL: event.Response.URL, Detail: detail, Text: headersText(event.Response.Headers)})
		case *network.EventLoadingFinished:
			requestID := event.RequestID
			go func() {
				body, err := network.GetResponseBody(requestID).Do(browserCtx)
				if err != nil {
					debugDynamic(opts.Debug, "dynamic response body unavailable: request_id=%s err=%v", requestID, err)
					return
				}
				addObservation(networkObservation{Source: "dynamic_network", Detail: "response body", Text: string(body)})
			}()
		}
	})

	actions := []chromedp.Action{network.Enable()}
	if len(opts.Headers) > 0 {
		actions = append(actions, network.SetExtraHTTPHeaders(networkHeaders(opts.Headers)))
	}
	if strings.TrimSpace(opts.UserAgent) != "" {
		actions = append(actions, emulation.SetUserAgentOverride(opts.UserAgent))
	}
	actions = append(actions, chromedp.Navigate(target), chromedp.Sleep(opts.Wait))

	if err := chromedp.Run(browserCtx, actions...); err != nil {
		return nil, err
	}
	time.Sleep(250 * time.Millisecond)

	mu.Lock()
	snapshot := append([]networkObservation(nil), observations...)
	mu.Unlock()
	return networkObservationsToDiscoveries(snapshot), nil
}

func networkObservationsToDiscoveries(observations []networkObservation) []model.Discovery {
	var discoveries []model.Discovery
	for _, observation := range observations {
		evidence := model.Evidence{Source: observation.Source, URL: observation.URL, Detail: observation.Detail}
		discoveries = append(discoveries, detect.Artifacts(observation.Text, evidence)...)
	}
	return discoveries
}

func networkHeaders(headers map[string]string) network.Headers {
	out := network.Headers{}
	for name, value := range headers {
		out[name] = value
	}
	return out
}

func headersText(headers map[string]any) string {
	var b strings.Builder
	for name, value := range headers {
		name = strings.TrimSpace(name)
		if name == "" || value == nil {
			continue
		}
		fmt.Fprintf(&b, "%s: %v\n", name, value)
	}
	return b.String()
}

func postDataEntriesText(entries []*network.PostDataEntry) string {
	var b strings.Builder
	for _, entry := range entries {
		if entry != nil && entry.Bytes != "" {
			b.WriteString(entry.Bytes)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func debugDynamic(debug bool, format string, args ...any) {
	if debug {
		fmt.Fprintf(os.Stderr, "[debug] "+format+"\n", args...)
	}
}
