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
	apiBaseURL          = "https://moonito.net/api/v1/analytics"
	identityCookie      = "__mo_ct"
	// SDKVersion is reported to the API so support can tell which build a
	// customer is running.
	SDKVersion = "2.0.0"
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
	} `json:"data"`
	Error *struct {
		Message any `json:"message"`
	} `json:"error"`
}

// EvaluateVisitor inspects the incoming HTTP request and optionally writes a response
// if the visitor needs to be blocked. Returns nil on normal flow or an error on internal problems.
func (c *Client) EvaluateVisitor(w http.ResponseWriter, r *http.Request) error {
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

	clientIP := getClientIP(r)
	ua := r.UserAgent()
	event := r.URL.RequestURI()
	domain := strings.ToLower(r.Host)

	if !isValidIP(clientIP) {
		return errors.New("invalid IP address")
	}

	respBody, err := c.requestAnalyticsAPI(clientIP, ua, event, domain, visitorContext{
		ClientToken: readClientToken(r),
		Headers:     collectHeaders(r),
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
	}

	return nil
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

	if !isValidIP(ip) {
		return nil, errors.New("invalid IP address")
	}

	respBody, err := c.requestAnalyticsAPI(ip, userAgent, event, domain, visitorContext{})
	if err != nil {
		return nil, fmt.Errorf("request analytics API: %w", err)
	}

	var apiResp analyticsAPIResponse
	if err := json.Unmarshal([]byte(respBody), &apiResp); err != nil {
		return nil, fmt.Errorf("invalid analytics response: %w", err)
	}

	if apiResp.Error != nil {
		return nil, fmt.Errorf("analytics error: %v", apiResp.Error.Message)
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
