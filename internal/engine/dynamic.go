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
	"github.com/chromedp/cdproto/target"
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

	cap := newNetworkCapture(opts.Debug)
	// storageCtx is the tab whose cookies/localStorage get captured in live
	// mode. In attach mode that's the user's first real tab, not our blank one.
	storageCtx := browserCtx

	if isAttachMode {
		// A remote-allocator context only watches a fresh blank tab, so
		// attach the network listener to every existing page target instead.
		// Otherwise the user's own tabs are never observed.
		targets, err := openPageTargets(browserCtx)
		if err != nil {
			return nil, fmt.Errorf("listing attached browser targets: %w", err)
		}
		if len(targets) == 0 {
			return nil, fmt.Errorf("no open pages in the attached browser: open the app in a tab and re-run")
		}
		for i, tid := range targets {
			tctx, cancel := chromedp.NewContext(browserCtx, chromedp.WithTargetID(tid))
			defer cancel()
			cap.listen(tctx)
			// Don't touch the user's session: no custom headers or UA here.
			if err := chromedp.Run(tctx, network.Enable()); err != nil {
				return nil, fmt.Errorf("enabling network on attached tab: %w", err)
			}
			if i == 0 {
				storageCtx = tctx
			}
		}
	} else {
		cap.listen(browserCtx)
		actions := []chromedp.Action{network.Enable()}
		if len(opts.Headers) > 0 {
			actions = append(actions, network.SetExtraHTTPHeaders(networkHeaders(opts.Headers)))
		}
		if strings.TrimSpace(opts.UserAgent) != "" {
			actions = append(actions, emulation.SetUserAgentOverride(opts.UserAgent))
		}
		actions = append(actions, chromedp.Navigate(target))
		if err := chromedp.Run(browserCtx, actions...); err != nil {
			return nil, err
		}
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
					idle := time.Since(time.Unix(0, cap.lastActivity.Load()))
					count := cap.observationCount()
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

	if isLiveMode {
		cap.appendObservations(captureBrowserStorage(storageCtx, target, opts.Debug))
	}

	cap.stopAcceptingBodies()
	if !cap.waitForBodies(5 * time.Second) {
		debugDynamic(opts.Debug, "timed out waiting for pending response bodies")
	}

	return networkObservationsToDiscoveries(cap.snapshot()), nil
}

// openPageTargets lists the page targets of an attached browser, skipping the
// blank tab chromedp creates on first use of a remote allocator.
func openPageTargets(ctx context.Context) ([]target.ID, error) {
	infos, err := target.GetTargets().Do(ctx)
	if err != nil {
		return nil, err
	}
	var ids []target.ID
	for _, info := range infos {
		if info.Type == "page" && !strings.HasPrefix(info.URL, "about:") {
			ids = append(ids, info.TargetID)
		}
	}
	return ids, nil
}

// maxDynamicBodyBytes caps the total response-body bytes buffered during a
// dynamic scan. Without it, a long headed session on a media-heavy app can
// balloon into hundreds of MB of images, fonts, and video.
const maxDynamicBodyBytes = 32 << 20

// networkCapture accumulates network observations from one or more browser
// target sessions. Attach mode listens on several tabs at once, so the state
// lives here instead of in ScanDynamic's closures.
type networkCapture struct {
	debug bool

	mu              sync.Mutex
	wg              sync.WaitGroup
	lastActivity    atomic.Int64
	bufferedBytes   atomic.Int64
	observations    []networkObservation
	wsURLs          map[network.RequestID]string
	mimeTypes       map[network.RequestID]string
	acceptingBodies bool
}

func newNetworkCapture(debug bool) *networkCapture {
	c := &networkCapture{
		debug:           debug,
		wsURLs:          map[network.RequestID]string{},
		mimeTypes:       map[network.RequestID]string{},
		acceptingBodies: true,
	}
	c.lastActivity.Store(time.Now().UnixNano())
	return c
}

// listen attaches the network event handler to a target session.
func (c *networkCapture) listen(ctx context.Context) {
	chromedp.ListenTarget(ctx, func(event any) { c.handle(ctx, event) })
}

func (c *networkCapture) addObservation(obs networkObservation) {
	if strings.TrimSpace(obs.Text) == "" {
		return
	}
	c.mu.Lock()
	c.observations = append(c.observations, obs)
	c.mu.Unlock()
}

func (c *networkCapture) appendObservations(obs []networkObservation) {
	c.mu.Lock()
	c.observations = append(c.observations, obs...)
	c.mu.Unlock()
}

func (c *networkCapture) observationCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.observations)
}

func (c *networkCapture) snapshot() []networkObservation {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]networkObservation(nil), c.observations...)
}

func (c *networkCapture) stopAcceptingBodies() {
	c.mu.Lock()
	c.acceptingBodies = false
	c.mu.Unlock()
}

func (c *networkCapture) waitForBodies(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (c *networkCapture) touchActivity() {
	c.lastActivity.Store(time.Now().UnixNano())
}

func (c *networkCapture) wsURL(id network.RequestID) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wsURLs[id]
}

func (c *networkCapture) handle(ctx context.Context, event any) {
	switch ev := event.(type) {
	case *network.EventRequestWillBeSent:
		if ev.Request == nil {
			return
		}
		c.touchActivity()
		detail := strings.TrimSpace(strings.Join([]string{ev.Request.Method, ev.Request.URL}, " "))
		c.addObservation(networkObservation{Source: "dynamic_network", URL: ev.Request.URL, Detail: detail, Text: ev.Request.URL})
		c.addObservation(networkObservation{Source: "dynamic_network", URL: ev.Request.URL, Detail: detail, Text: headersText(ev.Request.Headers)})
		c.addObservation(networkObservation{Source: "dynamic_network", URL: ev.Request.URL, Detail: detail, Text: postDataEntriesText(ev.Request.PostDataEntries)})

	case *network.EventResponseReceived:
		if ev.Response == nil {
			return
		}
		c.touchActivity()
		c.mu.Lock()
		c.mimeTypes[ev.RequestID] = ev.Response.MimeType
		c.mu.Unlock()
		detail := fmt.Sprintf("response %d %s", ev.Response.Status, ev.Response.URL)
		c.addObservation(networkObservation{Source: "dynamic_network", URL: ev.Response.URL, Detail: detail, Text: ev.Response.URL})
		c.addObservation(networkObservation{Source: "dynamic_network", URL: ev.Response.URL, Detail: detail, Text: headersText(ev.Response.Headers)})

	case *network.EventLoadingFinished:
		c.touchActivity()
		c.mu.Lock()
		if !c.acceptingBodies {
			c.mu.Unlock()
			return
		}
		mime := c.mimeTypes[ev.RequestID]
		delete(c.mimeTypes, ev.RequestID)
		c.wg.Add(1)
		c.mu.Unlock()
		// Skip bodies we know are binary (images, fonts, video): they carry
		// no scannable text and dominate memory usage.
		if mime != "" && !textualMime(mime) {
			c.wg.Done()
			return
		}
		requestID := ev.RequestID
		go func() {
			defer c.wg.Done()
			body, err := network.GetResponseBody(requestID).Do(ctx)
			if err != nil {
				debugDynamic(c.debug, "dynamic response body unavailable: request_id=%s err=%v", requestID, err)
				return
			}
			if c.bufferedBytes.Add(int64(len(body))) > maxDynamicBodyBytes {
				c.stopAcceptingBodies()
				debugDynamic(c.debug, "dynamic body buffer cap (%d bytes) reached, skipping further bodies", maxDynamicBodyBytes)
				return
			}
			c.addObservation(networkObservation{Source: "dynamic_network", Detail: "response body", Text: string(body)})
		}()

	case *network.EventWebSocketCreated:
		c.touchActivity()
		c.mu.Lock()
		c.wsURLs[ev.RequestID] = ev.URL
		c.mu.Unlock()
		detail := "websocket created: " + ev.URL
		c.addObservation(networkObservation{Source: "dynamic_network", URL: ev.URL, Detail: detail, Text: ev.URL})

	case *network.EventWebSocketWillSendHandshakeRequest:
		c.touchActivity()
		wsURL := c.wsURL(ev.RequestID)
		if ev.Request != nil {
			c.addObservation(networkObservation{Source: "dynamic_network", URL: wsURL, Detail: "websocket handshake request", Text: headersText(ev.Request.Headers)})
		}

	case *network.EventWebSocketHandshakeResponseReceived:
		c.touchActivity()
		wsURL := c.wsURL(ev.RequestID)
		if ev.Response != nil {
			detail := fmt.Sprintf("websocket handshake response: %d %s", ev.Response.Status, ev.Response.StatusText)
			c.addObservation(networkObservation{Source: "dynamic_network", URL: wsURL, Detail: detail, Text: headersText(ev.Response.Headers)})
		}

	case *network.EventWebSocketFrameReceived:
		c.touchActivity()
		wsURL := c.wsURL(ev.RequestID)
		if ev.Response != nil && ev.Response.PayloadData != "" {
			c.addObservation(networkObservation{Source: "dynamic_network", URL: wsURL, Detail: "websocket frame received", Text: ev.Response.PayloadData})
		}

	case *network.EventWebSocketFrameSent:
		c.touchActivity()
		wsURL := c.wsURL(ev.RequestID)
		if ev.Response != nil && ev.Response.PayloadData != "" {
			c.addObservation(networkObservation{Source: "dynamic_network", URL: wsURL, Detail: "websocket frame sent", Text: ev.Response.PayloadData})
		}
	}
}

func captureBrowserStorage(ctx context.Context, pageURL string, debug bool) []networkObservation {
	var observations []networkObservation
	var cookieText, localStorageText string

	if err := chromedp.Run(ctx,
		chromedp.EvaluateAsDevTools("document.cookie", &cookieText),
	); err != nil {
		debugDynamic(debug, "browser storage capture failed: %v", err)
		return observations
	}
	if cookieText != "" {
		observations = append(observations, networkObservation{
			Source: "browser_storage",
			URL:    pageURL,
			Detail: "document.cookie captured from live browser session",
			Text:   cookieText,
		})
	}

	if err := chromedp.Run(ctx,
		chromedp.EvaluateAsDevTools(`
                        (() => {
                                const items = [];
                                for (let i = 0; i < localStorage.length; i++) {
                                        const key = localStorage.key(i);
                                        items.push(key + "=" + localStorage.getItem(key));
                                }
                                return items.join("; ");
                        })()
                `, &localStorageText),
	); err != nil {
		debugDynamic(debug, "localStorage capture failed: %v", err)
	}
	if localStorageText != "" {
		observations = append(observations, networkObservation{
			Source: "browser_storage",
			URL:    pageURL,
			Detail: "localStorage captured from live browser session",
			Text:   localStorageText,
		})
	}

	return observations
}

// textualMime reports whether a response body is worth buffering for
// artifact scanning. Unknown/empty mime types are treated as textual;
// only positively-identified binary types are skipped.
func textualMime(mime string) bool {
	mime = strings.ToLower(strings.TrimSpace(mime))
	if mime == "" {
		return true
	}
	if strings.HasPrefix(mime, "text/") {
		return true
	}
	for _, sub := range []string{"json", "javascript", "xml", "ecmascript"} {
		if strings.Contains(mime, sub) {
			return true
		}
	}
	return false
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
