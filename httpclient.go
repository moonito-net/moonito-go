package moonitogo

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

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
		"ua":     userAgent,
		"events": event,
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
		body["method"] = ctx.Method
	}

	if ctx.Path != "" {
		body["path"] = ctx.Path
	}

	headers := map[string]string{}
	for name, value := range ctx.Headers {
		if len(value) <= 2048 {
			headers[name] = value
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

	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	} else {
		req.Header.Set("User-Agent", "moonito-go-sdk/"+SDKVersion)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Public-Key", c.cfg.APIPublicKey)
	req.Header.Set("X-Secret-Key", c.cfg.APISecretKey)

	resp, err := http.DefaultClient.Do(req)
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

	resp, err := http.DefaultClient.Do(req)
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
