package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	moonitogo "github.com/moonito-net/moonito-go"
)

// The Echo middleware as the README wires it: pages get the sensor, the
// sensor's requests are answered, and the app's own routes keep working.
func TestEchoMiddleware(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/telemetry/relay" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"status":{"need_to_block":false}}}`)
	}))
	defer api.Close()

	client := moonitogo.New(moonitogo.Config{IsProtected: true, APIPublicKey: "pub_123", APISecretKey: "s", Endpoint: api.URL})
	e := echo.New()
	e.Use(EchoTrafficFilter(client))
	e.GET("/", func(c echo.Context) error {
		return c.HTML(http.StatusOK, "<!DOCTYPE html><html><head><title>E</title></head><body>echo</body></html>")
	})
	e.GET("/api", func(c echo.Context) error { return c.JSON(http.StatusOK, map[string]string{"a": "</head>"}) })

	site := httptest.NewServer(e)
	defer site.Close()

	get := func(path, accept string) (int, string, string) {
		req, _ := http.NewRequest(http.MethodGet, site.URL+path, nil)
		req.Header.Set("Accept", accept)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, res.Header.Get("Content-Type"), string(b)
	}

	status, _, page := get("/", "text/html")
	if status != 200 || strings.Count(page, "data-guard-sensor") != 1 || !strings.Contains(page, "echo") {
		t.Fatalf("page: %d %s", status, page)
	}

	start := strings.Index(page, `src="`) + 5
	src := page[start : start+strings.Index(page[start:], `"`)]
	status, kind, script := get(strings.ReplaceAll(src, "&amp;", "&"), "*/*")
	if status != 200 || !strings.Contains(kind, "javascript") || strings.Contains(strings.ToLower(script), "moonito") {
		t.Fatalf("script: %d %s", status, kind)
	}

	if status, _, body := get("/api", "application/json"); status != 200 || strings.Contains(body, "data-guard") {
		t.Fatalf("api changed: %d %s", status, body)
	}
}
