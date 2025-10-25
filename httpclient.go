package moonitogo

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
)

// requestAnalyticsAPI makes the GET request to Moonito analytics endpoint and returns response body.
func (c *Client) requestAnalyticsAPI(ip, userAgent, event, domain string) (string, error) {
	values := url.Values{}
	values.Set("ip", ip)
	// Do not double-encode: url.Values will encode properly
	values.Set("ua", userAgent)
	values.Set("events", event)
	values.Set("domain", domain)

	u := apiBaseURL + "?" + values.Encode()

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", err
	}

	// set headers
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	} else {
		req.Header.Set("User-Agent", "moonito-go-sdk/1.0")
	}
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
