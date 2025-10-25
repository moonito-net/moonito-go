package moonitogo

import (
	"net/http"
	"net/http/httptest"
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
