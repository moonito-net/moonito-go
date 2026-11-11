package moonitogo

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

const testPage = `<!DOCTYPE html><html><head><title>Shop</title></head><body>Halo ñ 😀</body></html>`

func fakeAPI(t *testing.T, block bool) *httptest.Server {
	t.Helper()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if block {
			_, _ = io.WriteString(w, `{"data":{"status":{"need_to_block":true}}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"status":{"need_to_block":false},"decision_id":"d1","nonce":"n1"}}`)
	}))
	t.Cleanup(api.Close)
	return api
}

func serve(t *testing.T, cfg Config, handler http.HandlerFunc, headers map[string]string) *http.Response {
	t.Helper()
	site := httptest.NewServer(New(cfg).Middleware(handler))
	t.Cleanup(site.Close)

	req, _ := http.NewRequest("GET", site.URL+"/", nil)
	req.Header.Set("Accept", "text/html")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

func body(t *testing.T, res *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func htmlHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(testPage)))
	_, _ = io.WriteString(w, testPage)
}

func TestSensorIsAddedOnceWithCorrectLength(t *testing.T) {
	api := fakeAPI(t, false)
	res := serve(t, Config{IsProtected: true, APIPublicKey: "pub_123", APISecretKey: "s", Endpoint: api.URL}, htmlHandler, nil)
	got := body(t, res)

	if strings.Count(got, sensorMarker) != 1 {
		t.Fatalf("sensor not added exactly once: %s", got)
	}
	if !strings.Contains(got, "sensor@1.1.1/t.js") || !strings.Contains(got, `data-key="pub_123"`) || !strings.Contains(got, "integrity=") {
		t.Fatalf("tag incomplete: %s", got)
	}
	if strings.Index(got, sensorMarker) > strings.Index(got, "</head>") {
		t.Fatal("tag not before </head>")
	}
	if res.ContentLength != int64(len(got)) {
		t.Fatalf("Content-Length %d, body %d", res.ContentLength, len(got))
	}
	if !strings.Contains(got, "Halo ñ 😀") {
		t.Fatal("page text changed")
	}
}

func TestSensorWithoutContentTypeAndInChunks(t *testing.T) {
	api := fakeAPI(t, false)
	res := serve(t, Config{IsProtected: true, APIPublicKey: "pub_123", APISecretKey: "s", Endpoint: api.URL}, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, testPage[:25])
		_, _ = io.WriteString(w, testPage[25:])
	}, nil)
	if got := body(t, res); strings.Count(got, sensorMarker) != 1 || !strings.HasSuffix(got, "</body></html>") {
		t.Fatalf("sniffed chunked page not injected: %s", got)
	}
}

func TestSensorLeavesOtherResponsesAlone(t *testing.T) {
	api := fakeAPI(t, false)
	cfg := Config{IsProtected: true, APIPublicKey: "pub_123", APISecretKey: "s", Endpoint: api.URL}

	cases := map[string]http.HandlerFunc{
		"json": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"a":"</head>"}`)
		},
		"gzip": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = io.WriteString(w, testPage)
		},
		"csp": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Security-Policy", "script-src 'self'")
			_, _ = io.WriteString(w, testPage)
		},
		"error": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(500)
			_, _ = io.WriteString(w, testPage)
		},
		"tagged": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, strings.Replace(testPage, "</head>", `<script src="https://cdn.jsdelivr.net/gh/moonito-net/sensor@1.0.0/t.js"></script></head>`, 1))
		},
		"flushed": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, testPage)
			w.(http.Flusher).Flush()
		},
	}

	for name, handler := range cases {
		// Asking for gzip ourselves stops the client unpacking the fake body.
		res := serve(t, cfg, handler, map[string]string{"Accept-Encoding": "gzip"})
		if got := body(t, res); strings.Contains(got, sensorMarker) {
			t.Errorf("%s: sensor added: %s", name, got)
		}
	}

	if got := body(t, serve(t, cfg, htmlHandler, map[string]string{"Accept": "application/json"})); strings.Contains(got, sensorMarker) {
		t.Error("API request got the sensor")
	}
	if got := body(t, serve(t, cfg, htmlHandler, map[string]string{"Sec-Fetch-Dest": "image"})); strings.Contains(got, sensorMarker) {
		t.Error("asset request got the sensor")
	}

	off := cfg
	off.DisableSensor = true
	if got := body(t, serve(t, off, htmlHandler, nil)); strings.Contains(got, sensorMarker) {
		t.Error("DisableSensor ignored")
	}
}

func TestBlockedVisitorGetsNoSensor(t *testing.T) {
	api := fakeAPI(t, true)
	res := serve(t, Config{IsProtected: true, APIPublicKey: "pub_123", APISecretKey: "s", Endpoint: api.URL}, htmlHandler, nil)
	if got := body(t, res); res.StatusCode != 403 || strings.Contains(got, sensorMarker) {
		t.Fatalf("blocked visitor: status %d body %s", res.StatusCode, got)
	}
}

func TestApiDownStillAddsSensor(t *testing.T) {
	res := serve(t, Config{IsProtected: true, APIPublicKey: "pub_123", APISecretKey: "s", Endpoint: "http://127.0.0.1:1"}, htmlHandler, nil)
	if got := body(t, res); res.StatusCode != 200 || strings.Count(got, sensorMarker) != 1 {
		t.Fatalf("fail-open visitor: status %d body %s", res.StatusCode, got)
	}
}
