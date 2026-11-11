package moonitogo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The browser sensor this release adds to HTML pages (same as the PHP SDK).
const (
	// A sensor tag pasted by hand from the CDN; recognised so it is never doubled.
	sensorPath     = "/gh/moonito-net/sensor@"
	sensorMarker   = "data-guard-sensor"
	sensorMaxBytes = 5 << 20
	maxBeacon      = 8192
)

var (
	headClose = regexp.MustCompile(`(?i)</head>`)
	bodyOpen  = regexp.MustCompile(`(?i)<body\b[^>]*>`)
	metaCSP   = regexp.MustCompile(`(?i)<meta[^>]+http-equiv\s*=\s*["']?content-security-policy`)
)

// WithSensor wraps w so the browser sensor is added to the HTML page the
// handler writes. Call finish after the handler returns. When the sensor does
// not apply (switched off, not a page request) w comes back unchanged and
// finish does nothing.
//
// Middleware and the Echo middleware call this for every visitor they let
// through, so the sensor tag no longer has to be pasted into templates.
func (c *Client) WithSensor(w http.ResponseWriter, r *http.Request) (http.ResponseWriter, func()) {
	if c.cfg.DisableSensor || c.cfg.APIPublicKey == "" || !wantsPage(r) {
		return w, func() {}
	}

	s := &sensorWriter{ResponseWriter: w, client: c, status: http.StatusOK, path: pagePath(r)}

	return s, s.finish
}

// InsertSensor returns the page with the sensor tag added, or ok=false when it
// should be left alone (already tagged, a meta CSP, no head or body).
func (c *Client) InsertSensor(html string) (string, bool) {
	return c.insertSensorAt(html, "")
}

var safePath = regexp.MustCompile(`^/[^\s"<>\\]*$`)

// pagePath is this page's own path, known to reach this SDK. Written into the
// tag so the sensor always comes back to it, even on a page with a <base href>
// or after a single-page app changes the address.
func pagePath(r *http.Request) string {
	p := r.URL.EscapedPath()
	if len(p) > 2048 || !safePath.MatchString(p) {
		return "/"
	}
	return p
}

// cspAllowsSelf reports whether a Content-Security-Policy lets the sensor run.
// It is served from the site itself, so 'self' for scripts and requests is all
// it needs. A policy built on nonces or 'strict-dynamic' is left alone.
func cspAllowsSelf(header string) bool {
	if header == "" {
		return true
	}

	directives := map[string][]string{}
	for _, part := range strings.Split(header, ";") {
		tokens := strings.Fields(strings.ToLower(part))
		if len(tokens) == 0 {
			continue
		}
		if _, seen := directives[tokens[0]]; !seen {
			directives[tokens[0]] = tokens[1:]
		}
	}

	pick := func(names ...string) []string {
		for _, n := range names {
			if v, ok := directives[n]; ok {
				return v
			}
		}
		return nil
	}
	has := func(list []string, want string) bool {
		for _, v := range list {
			if v == want {
				return true
			}
		}
		return false
	}
	allows := func(list []string) bool {
		return list == nil || (!has(list, "'none'") && (has(list, "'self'") || has(list, "*")))
	}

	script := pick("script-src-elem", "script-src", "default-src")
	connect := pick("connect-src", "default-src")

	return !has(script, "'strict-dynamic'") && allows(script) && allows(connect)
}

func (c *Client) insertSensorAt(html, path string) (string, bool) {
	if html == "" || strings.Contains(html, sensorPath) || strings.Contains(html, sensorMarker) || metaCSP.MatchString(html) {
		return html, false
	}

	// Served by this SDK from the page's own URL (ServeRelay): no other
	// host, nothing that names the service.
	param := c.relayParam()
	at := htmlEscape(path)
	endpoint := ""
	if at != "" {
		endpoint = ` data-endpoint="` + at + `"`
	}
	tag := `<script defer src="` + at + `?` + param + `=s&amp;v=` + sensorScriptVersion + `"` + endpoint + ` data-key="` + htmlEscape(c.cfg.APIPublicKey) +
		`" data-p="` + param + `" ` + sensorMarker + `></script>`

	if loc := headClose.FindStringIndex(html); loc != nil {
		return html[:loc[0]] + tag + html[loc[0]:], true
	}

	if loc := bodyOpen.FindStringIndex(html); loc != nil {
		return html[:loc[1]] + tag + html[loc[1]:], true
	}

	return html, false
}

// wantsPage reports whether the request is one a page is served for, not an
// API call or an asset.
func wantsPage(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		return false
	}

	if strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest") {
		return false
	}

	accept := strings.ToLower(r.Header.Get("Accept"))
	if accept != "" && !strings.Contains(accept, "text/html") && !strings.Contains(accept, "*/*") {
		return false
	}

	dest := strings.ToLower(r.Header.Get("Sec-Fetch-Dest"))

	return dest == "" || dest == "document" || dest == "iframe"
}

const (
	sensorPending = iota
	sensorBuffer
	sensorPass
)

// sensorWriter holds an HTML page until the handler is done, then writes it
// with the tag added. Anything else is passed through as it is written: the
// first write decides, from the headers set by then.
type sensorWriter struct {
	http.ResponseWriter
	client      *Client
	status      int
	headerSet   bool
	mode        int
	buf         bytes.Buffer
	passStarted bool
	path        string
}

func (s *sensorWriter) decide(first []byte) {
	if s.mode != sensorPending {
		return
	}

	h := s.Header()

	if h.Get("Content-Type") == "" && first != nil {
		// What net/http would send anyway; decided here so we can see it.
		h.Set("Content-Type", http.DetectContentType(first))
	}

	skip := s.status < 200 || s.status >= 300 || s.status == http.StatusNoContent ||
		!strings.Contains(strings.ToLower(h.Get("Content-Type")), "text/html") ||
		h.Get("Content-Encoding") != "" ||
		!cspAllowsSelf(h.Get("Content-Security-Policy")) ||
		strings.Contains(strings.ToLower(h.Get("Content-Disposition")), "attachment")

	if skip {
		s.mode = sensorPass
	} else {
		s.mode = sensorBuffer
	}
}

func (s *sensorWriter) startPass() {
	if s.passStarted {
		return
	}

	s.passStarted = true

	if s.headerSet {
		s.ResponseWriter.WriteHeader(s.status)
	}
}

func (s *sensorWriter) WriteHeader(code int) {
	if s.headerSet {
		return
	}

	s.status = code
	s.headerSet = true

	if s.Header().Get("Content-Type") != "" {
		s.decide(nil)
	}

	if s.mode == sensorPass {
		s.startPass()
	}
}

func (s *sensorWriter) Write(b []byte) (int, error) {
	if s.mode == sensorPending {
		s.decide(b)
	}

	if s.mode == sensorPass {
		s.startPass()

		return s.ResponseWriter.Write(b)
	}

	n, _ := s.buf.Write(b)

	if s.buf.Len() > sensorMaxBytes {
		// Too large to hold: send what was held, then stream as is.
		s.mode = sensorPass
		s.startPass()
		if _, err := s.ResponseWriter.Write(s.buf.Bytes()); err != nil {
			return 0, err
		}
		s.buf.Reset()
	}

	return n, nil
}

// Flush gives up on the page: a handler that flushes wants bytes on the wire
// now, and holding them would break streaming.
func (s *sensorWriter) Flush() {
	if s.mode != sensorPass {
		s.mode = sensorPass
		s.startPass()
		if s.buf.Len() > 0 {
			_, _ = s.ResponseWriter.Write(s.buf.Bytes())
			s.buf.Reset()
		}
	}

	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the original writer.
func (s *sensorWriter) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

func (s *sensorWriter) finish() {
	switch s.mode {
	case sensorPending:
		// Nothing was written; pass on a bare status if one was set.
		if s.headerSet {
			s.ResponseWriter.WriteHeader(s.status)
		}
	case sensorBuffer:
		body := s.buf.Bytes()

		if page, ok := s.client.insertSensorAt(string(body), s.path); ok {
			body = []byte(page)

			if s.Header().Get("Content-Length") != "" {
				s.Header().Set("Content-Length", strconv.Itoa(len(body)))
			}
		}

		s.ResponseWriter.WriteHeader(s.status)
		_, _ = s.ResponseWriter.Write(body)
		s.buf.Reset()
		s.mode = sensorPass
	}
}

// relayParam is the query parameter the sensor's requests use on this site.
// Derived from the public key, so every site has its own: no URL pattern an ad
// blocker list could match across customers, and no clash with the site's own
// parameters. Same rule in every SDK.
func (c *Client) relayParam() string {
	sum := sha256.Sum256([]byte("sensor|" + c.cfg.APIPublicKey))
	return "_" + hex.EncodeToString(sum[:])[:7]
}

// relayKind is "s" (script), "p" (ping), "t" (beacon), or "" for any other request.
func (c *Client) relayKind(r *http.Request) string {
	param := c.relayParam()
	if !strings.Contains(r.URL.RawQuery, param+"=") {
		return ""
	}

	kind := r.URL.Query().Get(param)
	switch {
	case (kind == "s" || kind == "p") && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		return kind
	case kind == "t" && r.Method == http.MethodPost:
		return "t"
	}

	return ""
}

// ServeRelay answers the browser sensor's own requests (its script, timing and
// beacon), which come to the page's own URL. It returns true when it answered,
// and then the request needs nothing else. Middleware and the Echo middleware
// call it before any decision, so the browser only ever talks to this site.
func (c *Client) ServeRelay(w http.ResponseWriter, r *http.Request) bool {
	if c.cfg.DisableSensor || !c.cfg.IsProtected || c.cfg.APIPublicKey == "" {
		return false
	}

	switch c.relayKind(r) {
	case "s":
		h := w.Header()
		h.Set("Content-Type", "application/javascript; charset=utf-8")
		// Versioned URL, so the browser keeps it for a year.
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
		h.Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, sensorScript)
		}
		return true
	case "p":
		w.Header().Set("Cache-Control", "no-store, private")
		w.WriteHeader(http.StatusNoContent)
		return true
	case "t":
		body, _ := io.ReadAll(io.LimitReader(r.Body, maxBeacon+1))
		w.Header().Set("Cache-Control", "no-store, private")
		w.WriteHeader(http.StatusNoContent)
		if len(body) > 0 && len(body) <= maxBeacon {
			// After the browser has its answer.
			go c.relayBeacon(c.clientIP(r), string(body))
		}
		return true
	}

	return false
}

var relayHTTP = &http.Client{Timeout: 2 * time.Second}

// relayBeacon forwards a sensor beacon to Moonito, server to server.
func (c *Client) relayBeacon(ip, beacon string) {
	if !isValidIP(ip) || beacon == "" {
		return
	}

	payload, err := json.Marshal(map[string]string{"ip": ip, "p": beacon})
	if err != nil {
		return
	}

	req, err := http.NewRequest(http.MethodPost, c.endpoint()+"/api/v2/telemetry/relay", bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "moonito-go-sdk/"+SDKVersion)
	req.Header.Set("X-Public-Key", c.cfg.APIPublicKey)
	req.Header.Set("X-Secret-Key", c.cfg.APISecretKey)

	resp, err := relayHTTP.Do(req)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}
