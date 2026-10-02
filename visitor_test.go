package moonitogo

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUrlsMatch(t *testing.T) {
	cases := []struct {
		current string
		target  string
		want    bool
	}{
		{"https://example.com/path?x=1", "https://example.com/path?x=1", true},
		{"https://example.com/path?x=1", "/path?x=1", true},
		{"https://example.com/path", "/path", true},
		{"https://example.com/path", "/other", false},
	}

	for _, tc := range cases {
		if got := urlsMatch(tc.current, tc.target); got != tc.want {
			t.Fatalf("urlsMatch(%q, %q) = %v; want %v", tc.current, tc.target, got, tc.want)
		}
	}
}

func TestEvaluateVisitor_NoProtect(t *testing.T) {
	client := New(Config{IsProtected: false})
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	rec := httptest.NewRecorder()

	if err := client.EvaluateVisitor(rec, req); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestIsValidIP(t *testing.T) {
	valids := []string{"127.0.0.1", "::1", "8.8.8.8"}
	for _, ip := range valids {
		if !isValidIP(ip) {
			t.Fatalf("expected ip %s to be valid", ip)
		}
	}
	if isValidIP("not-an-ip") {
		t.Fatalf("expected invalid ip to be false")
	}
}

func TestClientIP(t *testing.T) {
	c := New(Config{TrustedProxies: []string{"203.0.113.10"}})
	cases := []struct {
		name, remote, cf, xff, want string
	}{
		{"direct visitor, forged XFF ignored", "8.8.8.8:1234", "", "1.2.3.4", "8.8.8.8"},
		{"direct visitor, forged CF ignored", "8.8.8.8:1234", "1.2.3.4", "", "8.8.8.8"},
		{"via Cloudflare", "172.70.1.1:443", "36.85.5.5", "36.85.5.5, 172.70.1.1", "36.85.5.5"},
		{"via local nginx", "127.0.0.1:5555", "", "36.85.5.5", "36.85.5.5"},
		{"via CDN chain behind nginx", "10.0.0.2:5555", "", "1.2.3.4, 36.85.5.5, 10.0.0.9", "36.85.5.5"},
		{"via listed public proxy", "203.0.113.10:80", "", "36.85.5.5", "36.85.5.5"},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		r.RemoteAddr = tc.remote
		if tc.cf != "" {
			r.Header.Set("CF-Connecting-IP", tc.cf)
		}
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		if got := c.clientIP(r); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}

func apiReturning(status int, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
}

func protectedPage(client *Client) http.Handler {
	return client.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("SECRET PAGE"))
	}))
}

func TestMiddlewareBlocksWithoutLeakingPage(t *testing.T) {
	api := apiReturning(200, `{"data":{"status":{"need_to_block":true}}}`)
	defer api.Close()
	client := New(Config{IsProtected: true, APIPublicKey: "p", APISecretKey: "s", UnwantedVisitorTo: "https://google.com", UnwantedVisitorAction: 1, Endpoint: api.URL})

	rec := httptest.NewRecorder()
	protectedPage(client).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))

	if rec.Code != http.StatusFound || strings.Contains(rec.Body.String(), "SECRET PAGE") {
		t.Fatalf("blocked visitor got %d %q", rec.Code, rec.Body.String())
	}
}

func TestMiddlewareFailsOpen(t *testing.T) {
	for _, api := range []*httptest.Server{
		apiReturning(403, `{"error":{"message":["The example.com domain is not verified."]}}`),
		apiReturning(502, `<html>Bad Gateway</html>`),
	} {
		client := New(Config{IsProtected: true, APIPublicKey: "p", APISecretKey: "s", Endpoint: api.URL})
		rec := httptest.NewRecorder()
		protectedPage(client).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
		api.Close()

		if rec.Code != http.StatusOK || rec.Body.String() != "SECRET PAGE" {
			t.Fatalf("API failure should let the visitor through, got %d %q", rec.Code, rec.Body.String())
		}
	}
}
