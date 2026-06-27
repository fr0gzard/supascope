package engine

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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
	IdleTimeout        time.Duration
	BrowserDebuggerURL string
	Live               bool
	Debug              bool
}

type networkObservation struct {
	Source string
	URL    string
	Detail string
	Text   string
}

func ScanDynamic(ctx context.Context, target string, opts DynamicOptions) ([]model.Discovery, error) {
	if opts.Wait <= 0 {
		opts.Wait = 2 * time.Second
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 20 * time.Second
	}

	isAttachMode := strings.TrimSpace(opts.BrowserDebuggerURL) != ""
	isLiveMode := opts.Live || isAttachMode

	var allocCtx context.Context
	var cancelAlloc context.CancelFunc
	if isAttachMode {
		allocCtx, cancelAlloc = chromedp.NewRemoteAllocator(ctx, opts.BrowserDebuggerURL)
	} else if opts.Live {
		if err := CheckLiveBrowserPrereqs(); err != nil {
			return nil, err
		}
		chromePath, _ := FindChromePath()
		profile, _ := FindChromeProfile()
		allocOptions := append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.ExecPath(chromePath),
			chromedp.Flag("headless", false),
			chromedp.Flag("user-data-dir", profile),
		)
		allocCtx, cancelAlloc = chromedp.NewExecAllocator(ctx, allocOptions...)
	} else {
		allocOptions := append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("headless", true),
		)
		allocCtx, cancelAlloc = chromedp.NewExecAllocator(ctx, allocOptions...)
	}
	defer cancelAlloc()

	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()

	browserCtx, cancelTimeout := context.WithTimeout(browserCtx, opts.Wait+30*time.Second)
	defer cancelTimeout()

	var mu sync.Mutex
	var wg sync.WaitGroup
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	observations := make([]networkObservation, 0)
	wsURLs := map[network.RequestID]string{}
	acceptingBodies := true

	addObservation := func(obs networkObservation) {
		if strings.TrimSpace(obs.Text) == "" {
			return
		}
		mu.Lock()
		observations = append(observations, obs)
		mu.Unlock()
	}

	touchActivity := func() {
		lastActivity.Store(time.Now().UnixNano())
	}

	getWSURL := func(requestID network.RequestID) string {
		mu.Lock()
		url := wsURLs[requestID]
		mu.Unlock()
		return url
	}

	chromedp.ListenTarget(browserCtx, func(event any) {
		switch ev := event.(type) {
		case *network.EventRequestWillBeSent:
			if ev.Request == nil {
				return
			}
			touchActivity()
			detail := strings.TrimSpace(strings.Join([]string{ev.Request.Method, ev.Request.URL}, " "))
			addObservation(networkObservation{Source: "dynamic_network", URL: ev.Request.URL, Detail: detail, Text: ev.Request.URL})
			addObservation(networkObservation{Source: "dynamic_network", URL: ev.Request.URL, Detail: detail, Text: headersText(ev.Request.Headers)})
			addObservation(networkObservation{Source: "dynamic_network", URL: ev.Request.URL, Detail: detail, Text: postDataEntriesText(ev.Request.PostDataEntries)})

		case *network.EventResponseReceived:
			if ev.Response == nil {
				return
			}
			touchActivity()
			detail := fmt.Sprintf("response %d %s", ev.Response.Status, ev.Response.URL)
			addObservation(networkObservation{Source: "dynamic_network", URL: ev.Response.URL, Detail: detail, Text: ev.Response.URL})
			addObservation(networkObservation{Source: "dynamic_network", URL: ev.Response.URL, Detail: detail, Text: headersText(ev.Response.Headers)})

		case *network.EventLoadingFinished:
			touchActivity()
			mu.Lock()
			if !acceptingBodies {
				mu.Unlock()
				return
			}
			wg.Add(1)
			mu.Unlock()
			requestID := ev.RequestID
			go func() {
				defer wg.Done()
				body, err := network.GetResponseBody(requestID).Do(browserCtx)
				if err != nil {
					debugDynamic(opts.Debug, "dynamic response body unavailable: request_id=%s err=%v", requestID, err)
					return
				}
				addObservation(networkObservation{Source: "dynamic_network", Detail: "response body", Text: string(body)})
			}()

		case *network.EventWebSocketCreated:
			touchActivity()
			mu.Lock()
			wsURLs[ev.RequestID] = ev.URL
			mu.Unlock()
			detail := "websocket created: " + ev.URL
			addObservation(networkObservation{Source: "dynamic_network", URL: ev.URL, Detail: detail, Text: ev.URL})

		case *network.EventWebSocketWillSendHandshakeRequest:
			touchActivity()
			wsURL := getWSURL(ev.RequestID)
			if ev.Request != nil {
				addObservation(networkObservation{Source: "dynamic_network", URL: wsURL, Detail: "websocket handshake request", Text: headersText(ev.Request.Headers)})
			}

		case *network.EventWebSocketHandshakeResponseReceived:
			touchActivity()
			wsURL := getWSURL(ev.RequestID)
			if ev.Response != nil {
				detail := fmt.Sprintf("websocket handshake response: %d %s", ev.Response.Status, ev.Response.StatusText)
				addObservation(networkObservation{Source: "dynamic_network", URL: wsURL, Detail: detail, Text: headersText(ev.Response.Headers)})
			}

		case *network.EventWebSocketFrameReceived:
			touchActivity()
			wsURL := getWSURL(ev.RequestID)
			if ev.Response != nil && ev.Response.PayloadData != "" {
				addObservation(networkObservation{Source: "dynamic_network", URL: wsURL, Detail: "websocket frame received", Text: ev.Response.PayloadData})
			}

		case *network.EventWebSocketFrameSent:
			touchActivity()
			wsURL := getWSURL(ev.RequestID)
			if ev.Response != nil && ev.Response.PayloadData != "" {
				addObservation(networkObservation{Source: "dynamic_network", URL: wsURL, Detail: "websocket frame sent", Text: ev.Response.PayloadData})
			}
		}
	})

	actions := []chromedp.Action{network.Enable()}
	if len(opts.Headers) > 0 {
		actions = append(actions, network.SetExtraHTTPHeaders(networkHeaders(opts.Headers)))
	}
	if strings.TrimSpace(opts.UserAgent) != "" {
		actions = append(actions, emulation.SetUserAgentOverride(opts.UserAgent))
	}
	if !isAttachMode {
		actions = append(actions, chromedp.Navigate(target))
	}

	if err := chromedp.Run(browserCtx, actions...); err != nil {
		return nil, err
	}

	if isLiveMode {
		if isAttachMode {
			fmt.Fprintf(os.Stderr, "Live capture active via attached browser. Use the app, then wait for idle auto-completion (%s).\n", opts.IdleTimeout)
		} else {
			fmt.Fprintf(os.Stderr, "Live capture active. Use the app in the browser, then wait for idle auto-completion (%s).\n", opts.IdleTimeout)
		}

		done := make(chan struct{})
		go func() {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			var lastReport time.Time
			for {
				select {
				case <-ticker.C:
					idle := time.Since(time.Unix(0, lastActivity.Load()))
					mu.Lock()
					count := len(observations)
					mu.Unlock()
					if idle >= opts.IdleTimeout {
						fmt.Fprintf(os.Stderr, "[live] idle for %s, completing capture (%d observations)\n", idle.Round(time.Second), count)
						close(done)
						return
					}
					if time.Since(lastReport) >= 5*time.Second {
						fmt.Fprintf(os.Stderr, "[live] captured %d observations, idle for %s\n", count, idle.Round(time.Second))
						lastReport = time.Now()
					}
				case <-browserCtx.Done():
					close(done)
					return
				}
			}
		}()
		<-done
	} else {
		if err := chromedp.Run(browserCtx, chromedp.Sleep(opts.Wait)); err != nil {
			return nil, err
		}
		time.Sleep(250 * time.Millisecond)
	}

	mu.Lock()
	acceptingBodies = false
	mu.Unlock()

	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
	case <-time.After(5 * time.Second):
		debugDynamic(opts.Debug, "timed out waiting for pending response bodies")
	}

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
