package moonitogo

import (
	"bytes"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// The browser sensor this release adds to HTML pages (same as the PHP SDK).
const (
	sensorVersion  = "1.1.1"
	sensorSRI      = "sha384-/7UZbqrpJUAKrkuftEAXE/7FurwiJ7NUyeokkvYnYClNLTXAvBCAKqo9pKzC1Zkv"
	sensorPath     = "/gh/moonito-net/sensor@"
	sensorMarker   = "data-guard-sensor"
	sensorMaxBytes = 5 << 20
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

	s := &sensorWriter{ResponseWriter: w, client: c, status: http.StatusOK}

	return s, s.finish
}

// InsertSensor returns the page with the sensor tag added, or ok=false when it
// should be left alone (already tagged, a meta CSP, no head or body).
func (c *Client) InsertSensor(html string) (string, bool) {
	if html == "" || strings.Contains(html, sensorPath) || strings.Contains(html, sensorMarker) || metaCSP.MatchString(html) {
		return html, false
	}

	endpoint := ""
	if e := strings.TrimRight(c.cfg.Endpoint, "/"); e != "" && e != "https://moonito.net" {
		endpoint = ` data-endpoint="` + htmlEscape(e) + `"`
	}

	tag := `<script defer src="https://cdn.jsdelivr.net` + sensorPath + sensorVersion + `/t.js" integrity="` + sensorSRI +
		`" crossorigin="anonymous" data-key="` + htmlEscape(c.cfg.APIPublicKey) + `"` + endpoint + ` ` + sensorMarker + `></script>`

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
		h.Get("Content-Security-Policy") != "" ||
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

		if page, ok := s.client.InsertSensor(string(body)); ok {
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
