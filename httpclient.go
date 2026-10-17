package moonitogo

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Only reaching the API is timed. Once connected the SDK waits for the
// decision however long it takes, because a check that gives up early lets the
// visitor through unchecked, and blocking them is the reason this library is
// installed. The request still ends when the visitor goes away, since it
// carries the visitor's request context.
var httpClient = &http.Client{
	Transport: &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     90 * time.Second,
	},
}

// contentClient fetches the unwanted-visitor page for action 3, which is
// somebody else's site and gets a normal bounded timeout.
var contentClient = &http.Client{Timeout: 15 * time.Second}

// visitorContext carries the optional inputs the rotation detectors need.
// Without them the API can only judge a request on its own address and user
// agent, which is exactly what a rotating residential pool is built to defeat.
// A zero value sends nothing extra.
type visitorContext struct {
	ClientToken   string
	ChallengePass string
	Headers       map[string]string
	Method        string
	Path          string
	Context       context.Context
}

// requestAnalyticsAPI asks the decision API what to do with this visitor.
//
// v2 rather than v1, because v1 has no way to say "challenge". The two
// endpoints are metered the same and return the same body; v2 adds
// challenge_url, decision_id and nonce. On v1 a challenge verdict collapses to
// allow before it reaches the caller, since the server will not hand back an
// instruction the client cannot carry out. A v1 SDK therefore lets a suspected
// rotating proxy through while the log records it as challenged, which reads
// like the visitor was stopped when they were not.
func (c *Client) requestAnalyticsAPI(ip, userAgent, event, domain string, ctx visitorContext) (string, error) {
	body := map[string]any{
		"ip":     ip,
		"ua":     bounded(userAgent, 2048),
		"events": bounded(event, 4096),
		"domain": domain,
		"sdk":    "go/" + SDKVersion,
	}

	if ctx.ClientToken != "" {
		body["client_token"] = ctx.ClientToken
	}

	// Proof this visitor already solved a challenge. Without it they are asked
	// again on the very next request, which is a loop.
	if ctx.ChallengePass != "" {
		body["challenge_pass"] = ctx.ChallengePass
	}

	if ctx.Method != "" {
		body["method"] = bounded(ctx.Method, 16)
	}

	if ctx.Path != "" {
		body["path"] = bounded(ctx.Path, 512)
	}

	headers := map[string]string{}
	names := make([]string, 0, len(ctx.Headers))
	for name := range ctx.Headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		switch strings.ToLower(name) {
		case "cookie", "authorization", "proxy-authorization":
			continue
		}
		headers[name] = bounded(ctx.Headers[name], 2048)
		if len(headers) >= 64 {
			break
		}
	}
	if len(headers) > 0 {
		body["headers"] = headers
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", c.endpoint()+"/api/v2/decision", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "moonito-go-sdk/"+SDKVersion)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Public-Key", c.cfg.APIPublicKey)
	req.Header.Set("X-Secret-Key", c.cfg.APISecretKey)

	if ctx.Context != nil {
		req = req.WithContext(ctx.Context)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	buf := &bytes.Buffer{}
	if _, err := io.Copy(buf, resp.Body); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// endpoint is the API base, overridable so a test or a self hosted install can
// point somewhere else.
func (c *Client) endpoint() string {
	if c.cfg.Endpoint != "" {
		return strings.TrimRight(c.cfg.Endpoint, "/")
	}
	return defaultEndpoint
}

// httpRequestWithBypass will call a URL and include bypass headers to avoid loops
func (c *Client) httpRequestWithBypass(rawURL string) (string, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(BYPASS_HEADER, "1")
	req.Header.Set(BYPASS_TOKEN_HEADER, c.bypassToken)

	resp, err := contentClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	buf := &bytes.Buffer{}
	if _, err := io.Copy(buf, resp.Body); err != nil {
		return "", err
	}
	return buf.String(), nil
}
