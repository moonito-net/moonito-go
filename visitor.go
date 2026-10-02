package moonitogo

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// Header constants
const (
	BYPASS_HEADER       = "X-VTF-Bypass"
	BYPASS_TOKEN_HEADER = "X-VTF-Token"
	defaultEndpoint     = "https://moonito.net"
	identityCookie      = "__mo_ct"
	passCookie          = "__mo_pass"
	// SDKVersion is reported to the API so support can tell which build a
	// customer is running.
	SDKVersion = "1.3.0"
)

// API response partial struct (adapted for the API contract)
type analyticsAPIResponse struct {
	Data struct {
		Status struct {
			NeedToBlock    bool   `json:"need_to_block"`
			DetectActivity string `json:"detect_activity"`
		} `json:"status"`
		SetClientToken *struct {
			Name   string `json:"name"`
			Value  string `json:"value"`
			MaxAge int    `json:"max_age"`
		} `json:"set_client_token"`
		ChallengeURL string `json:"challenge_url"`
	} `json:"data"`
	Error *struct {
		Message any `json:"message"`
	} `json:"error"`
}

// Middleware protects every route behind it. A blocked visitor gets the
// unwanted-visitor response and next is never called, so the protected page is
// not sent to them. This is the easiest way to install the SDK:
//
//	http.ListenAndServe(":3000", client.Middleware(mux))
func (c *Client) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracked := &writeTracker{ResponseWriter: w}
		_ = c.EvaluateVisitor(tracked, r)

		if tracked.wrote {
			return
		}

		next.ServeHTTP(w, r)
	})
}

// writeTracker records whether EvaluateVisitor answered the request itself.
type writeTracker struct {
	http.ResponseWriter
	wrote bool
}

func (t *writeTracker) WriteHeader(code int) {
	t.wrote = true
	t.ResponseWriter.WriteHeader(code)
}

func (t *writeTracker) Write(b []byte) (int, error) {
	t.wrote = true
	return t.ResponseWriter.Write(b)
}

// EvaluateVisitor inspects the incoming HTTP request and writes the
// unwanted-visitor response when the visitor must be blocked.
//
// It fails open and always returns nil: when the check cannot run (the API is
// unreachable or refuses, for example on an expired plan) the visitor is let
// through and the reason is logged. The error return is kept so existing code
// still compiles. When calling it directly, check whether a response was
// written before serving the page; Middleware does that for you.
func (c *Client) EvaluateVisitor(w http.ResponseWriter, r *http.Request) error {
	if err := c.evaluateVisitor(w, r); err != nil {
		log.Printf("moonito: check could not run, visitor allowed: %v", err)
	}

	return nil
}

func (c *Client) evaluateVisitor(w http.ResponseWriter, r *http.Request) error {
	if !c.cfg.IsProtected {
		return nil
	}

	// Bypass header check (server-to-server)
	if r.Header.Get(BYPASS_HEADER) == "1" && c.isValidBypassToken(r.Header.Get(BYPASS_TOKEN_HEADER)) {
		return nil
	}

	// Prevent infinite loop
	currentURL := getCurrentURL(r)
	if c.cfg.UnwantedVisitorTo != "" && urlsMatch(currentURL, c.cfg.UnwantedVisitorTo) {
		return nil
	}

	clientIP := c.clientIP(r)
	ua := r.UserAgent()
	event := r.URL.RequestURI()
	domain := strings.ToLower(r.Host)

	if !isValidIP(clientIP) {
		return errors.New("invalid IP address")
	}

	respBody, err := c.requestAnalyticsAPI(clientIP, ua, event, domain, visitorContext{
		ClientToken:   readClientToken(r),
		ChallengePass: readChallengePass(r),
		Headers:       collectHeaders(r),
		Method:        r.Method,
		Path:          r.URL.Path,
		Context:       r.Context(),
	})
	if err != nil {
		return fmt.Errorf("request analytics API: %w", err)
	}

	var apiResp analyticsAPIResponse
	if err := json.Unmarshal([]byte(respBody), &apiResp); err != nil {
		return fmt.Errorf("invalid analytics response: %w", err)
	}

	if apiResp.Error != nil {
		return fmt.Errorf("analytics error: %v", apiResp.Error.Message)
	}

	writeClientToken(w, apiResp.Data.SetClientToken)

	if apiResp.Data.Status.NeedToBlock {
		c.handleBlockedVisitor(w, r)
		return nil
	}

	// A challenge is outranked by a block, so it is only considered once the
	// visitor was not blocked outright.
	if apiResp.Data.ChallengeURL != "" {
		switch c.cfg.ChallengeAction {
		case "challenge":
			renderChallenge(w, r, apiResp.Data.ChallengeURL)
		case "block":
			c.handleBlockedVisitor(w, r)
		}
		// Anything else, including the empty default, is an allow: the verdict
		// is logged server side and the visitor is not interrupted.
	}

	return nil
}

// readChallengePass returns the proof that this visitor already passed a
// challenge. Forwarded without validation: the pass is signed with the domain
// secret, so checking it here would mean reimplementing the MAC in every
// language. The server checks it, and a forged one simply fails there.
func readChallengePass(r *http.Request) string {
	cookie, err := r.Cookie(passCookie)
	if err != nil || cookie == nil || len(cookie.Value) > 1024 {
		return ""
	}
	return cookie.Value
}

// renderChallenge sends the visitor to the challenge, keeping their request.
//
// A plain redirect would be simpler and would lose every POST. Somebody halfway
// through a checkout would return to an empty form and blame the site, so the
// body is stashed in sessionStorage on the customer's own origin and replayed
// when the challenge sends them back.
//
// The stash cannot hold a file input, because script cannot put a file back
// into a form. That is said plainly rather than silently dropped.
func renderChallenge(w http.ResponseWriter, r *http.Request, challengeURL string) {
	fields := map[string]string{}
	hasUpload := false

	if r.Method == http.MethodPost {
		contentType := r.Header.Get("Content-Type")
		hasUpload = strings.HasPrefix(contentType, "multipart/form-data")

		if !hasUpload {
			// ParseForm consumes the body. That is acceptable here because the
			// response is this interstitial and the original request is being
			// replayed rather than served.
			if err := r.ParseForm(); err == nil {
				for name, values := range r.PostForm {
					if len(fields) >= 200 {
						break
					}
					if len(values) > 0 && len(values[0]) <= 8192 {
						fields[name] = values[0]
					}
				}
			}
		}
	}

	stash, err := json.Marshal(map[string]any{
		"u": r.URL.RequestURI(),
		"m": r.Method,
		"f": fields,
	})
	if err != nil {
		stash = []byte("{}")
	}

	// Encoded twice: once for the value, once so the result is a JavaScript
	// string literal. Then < is escaped so it cannot close the script element.
	payload, _ := json.Marshal(string(stash))
	target, _ := json.Marshal(challengeURL)

	safe := func(b []byte) string {
		return strings.ReplaceAll(string(b), "<", `\u003c`)
	}

	note := ""
	if hasUpload {
		note = "<p>You will need to choose your file again after this check.</p>"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)

	fmt.Fprint(w, `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">`+
		`<meta name="viewport" content="width=device-width, initial-scale=1">`+
		`<meta name="robots" content="noindex, nofollow">`+
		`<title>Checking your browser</title></head>`+
		`<body><p>Checking your browser before you continue.</p>`+note+
		`<script>(function(){try{sessionStorage.setItem("__mo_resume",`+safe(payload)+
		`);}catch(e){}location.replace(`+safe(target)+`);})();</script>`+
		`<noscript><p>JavaScript is required to continue.</p></noscript>`+
		`</body></html>`)
}

// readClientToken returns the visitor's identity token, if they carry one.
//
// Read without any attempt to validate it. The SDK cannot: the signing key is
// server side and shipping it to every install would make it public. Holding a
// token confers no trust, it only tells the API whose history to consult, so
// passing a forged one along is harmless.
func readClientToken(r *http.Request) string {
	cookie, err := r.Cookie(identityCookie)
	if err != nil || cookie == nil {
		return ""
	}

	if len(cookie.Value) == 0 || len(cookie.Value) > 96 {
		return ""
	}

	return cookie.Value
}

// collectHeaders returns the request headers for server side fingerprinting,
// minus anything that carries the visitor's own credentials.
func collectHeaders(r *http.Request) map[string]string {
	out := make(map[string]string, len(r.Header))

	for name, values := range r.Header {
		switch strings.ToLower(name) {
		case "cookie", "authorization", "proxy-authorization":
			continue
		}

		if len(values) > 0 {
			out[name] = values[0]
		}
	}

	return out
}

// writeClientToken stores the token the API handed back, so the next request
// from this visitor carries it.
func writeClientToken(w http.ResponseWriter, descriptor *struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	MaxAge int    `json:"max_age"`
}) {
	if descriptor == nil || descriptor.Value == "" {
		return
	}

	name := descriptor.Name
	if name == "" {
		name = identityCookie
	}

	maxAge := descriptor.MaxAge
	if maxAge <= 0 {
		maxAge = 7776000
	}

	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    descriptor.Value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
	})
}

// EvaluateVisitorManually: useful for offline checks, background jobs, or tests.
func (c *Client) EvaluateVisitorManually(ip, userAgent, event, domain string) (map[string]any, error) {
	result := map[string]any{
		"need_to_block":   false,
		"detect_activity": nil,
		"content":         nil,
	}

	if !c.cfg.IsProtected {
		return result, nil
	}

	// Avoid unwanted URL loops
	if c.cfg.UnwantedVisitorTo != "" {
		var currentURL string
		if strings.HasPrefix(event, "http://") || strings.HasPrefix(event, "https://") {
			currentURL = event
		} else {
			if !strings.HasPrefix(event, "/") {
				event = "/" + event
			}
			currentURL = "https://" + domain + event
		}

		if urlsMatch(currentURL, c.cfg.UnwantedVisitorTo) {
			return result, nil
		}
	}

	// Only an unusable input is an error. When the check itself cannot run
	// the visitor is reported as allowed, the same fail-open rule as
	// EvaluateVisitor, and the reason is logged.
	if !isValidIP(ip) {
		return nil, errors.New("invalid IP address")
	}

	respBody, err := c.requestAnalyticsAPI(ip, userAgent, event, domain, visitorContext{})
	if err != nil {
		log.Printf("moonito: check could not run, visitor allowed: %v", err)
		return result, nil
	}

	var apiResp analyticsAPIResponse
	if err := json.Unmarshal([]byte(respBody), &apiResp); err != nil {
		log.Printf("moonito: unusable API response, visitor allowed: %v", err)
		return result, nil
	}

	if apiResp.Error != nil {
		log.Printf("moonito: API refused the check, visitor allowed: %v", apiResp.Error.Message)
		return result, nil
	}

	need := apiResp.Data.Status.NeedToBlock
	detect := apiResp.Data.Status.DetectActivity

	if need {
		content, _ := c.getBlockedContent()
		result["need_to_block"] = true
		result["detect_activity"] = detect
		result["content"] = content
		return result, nil
	}

	result["detect_activity"] = detect
	return result, nil
}

// handleBlockedVisitor writes an appropriate HTTP response (status, iframe, redirect, or fetched content)
func (c *Client) handleBlockedVisitor(w http.ResponseWriter, r *http.Request) {
	if c.cfg.UnwantedVisitorTo != "" {
		// Handle numeric code first
		if code, err := strconv.Atoi(c.cfg.UnwantedVisitorTo); err == nil {
			if code >= 100 && code <= 599 {
				w.WriteHeader(code)
				return
			}
			http.Error(w, "Invalid HTTP status code.", http.StatusInternalServerError)
			return
		}

		// Non-numeric, handle based on unwantedVisitorAction
		switch c.cfg.UnwantedVisitorAction {
		case 2:
			// iframe action
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			html := fmt.Sprintf(`
				<iframe src="%s" width="100%%" height="100%%" align="left"></iframe>
				<style>body {padding:0;margin:0;} iframe{margin:0;padding:0;border:0;}</style>
			`, htmlEscape(c.cfg.UnwantedVisitorTo))
			_, _ = w.Write([]byte(strings.TrimSpace(html)))
			return

		case 3:
			// fetch content with bypass token
			content, err := c.httpRequestWithBypass(c.cfg.UnwantedVisitorTo)
			if err != nil {
				log.Printf("[Moonito] Error fetching unwanted content: %v", err)
				http.Error(w, "Error fetching unwanted content.", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(content))
			return

		default:
			// redirect
			http.Redirect(w, r, c.cfg.UnwantedVisitorTo, http.StatusFound)
			return
		}
	}

	// Default 403 fallback
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(strings.TrimSpace(`
		<!DOCTYPE html>
		<html lang="en">
		<head>
			<title>Access Denied</title>
			<style>
				body { font-family: sans-serif; text-align: center; padding-top: 10%; }
				.sep { border-bottom: 5px black dotted; margin: 20px auto; width: 80%; }
			</style>
		</head>
		<body>
			<div><b>Access Denied!</b></div>
			<div class="sep"></div>
		</body>
		</html>
	`)))
}

// getBlockedContent returns HTML/string content for manual evaluations
func (c *Client) getBlockedContent() (string, error) {
	if c.cfg.UnwantedVisitorTo == "" {
		return "<p>Access Denied!</p>", nil
	}

	// If numeric code
	if code, err := strconv.Atoi(c.cfg.UnwantedVisitorTo); err == nil {
		if code >= 100 && code <= 599 {
			return strconv.Itoa(code), nil
		}
		return "500", nil
	}

	switch c.cfg.UnwantedVisitorAction {
	case 2:
		return `<iframe src="` + htmlEscape(c.cfg.UnwantedVisitorTo) + `" width="100%" height="100%"></iframe>`, nil

	case 3:
		content, err := c.httpRequestWithBypass(c.cfg.UnwantedVisitorTo)
		if err != nil {
			return "<p>Content not available</p>", nil
		}
		return content, nil

	default:
		return fmt.Sprintf(
			`<p>Redirecting to <a href="%s">%s</a></p>
			<script>setTimeout(function(){window.location.href="%s";},1000);</script>`,
			htmlEscape(c.cfg.UnwantedVisitorTo),
			htmlEscape(c.cfg.UnwantedVisitorTo),
			htmlEscape(c.cfg.UnwantedVisitorTo),
		), nil
	}
}

// helper simple HTML escape for bare usage (avoids importing html/template)
func htmlEscape(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"\"", "&#34;",
		"'", "&#39;",
		"<", "&lt;",
		">", "&gt;",
	)
	return replacer.Replace(s)
}
