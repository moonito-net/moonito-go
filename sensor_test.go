package moonitogo

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
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
	param := New(Config{APIPublicKey: "pub_123"}).relayParam()
	if !strings.Contains(got, `src="/?`+param+`=s&amp;v=`+sensorScriptVersion+`" data-endpoint="/"`) || !strings.Contains(got, `data-key="pub_123"`) || !strings.Contains(got, `data-p="`+param+`"`) {
		t.Fatalf("tag incomplete: %s", got)
	}
	if strings.Contains(strings.ToLower(got), "moonito") || strings.Contains(got, "jsdelivr") {
		t.Fatalf("the page names an outside host or the service: %s", got)
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
			w.Header().Set("Content-Security-Policy", "script-src https://cdn.example")
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

func TestRelayAnswersTheSensorWithoutADecision(t *testing.T) {
	decisions := 0
	relayed := make(chan string, 1)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/telemetry/relay" {
			b, _ := io.ReadAll(r.Body)
			relayed <- r.Header.Get("X-Secret-Key") + " " + string(b)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		decisions++
		_, _ = io.WriteString(w, `{"data":{"status":{"need_to_block":false}}}`)
	}))
	t.Cleanup(api.Close)

	cfg := Config{IsProtected: true, APIPublicKey: "pub_123", APISecretKey: "s", Endpoint: api.URL}
	param := New(cfg).relayParam()

	script := serve(t, cfg, htmlHandler, nil)
	_ = body(t, script)
	decisions = 0

	site := httptest.NewServer(New(cfg).Middleware(http.HandlerFunc(htmlHandler)))
	t.Cleanup(site.Close)

	res, err := http.Get(site.URL + "/shop?" + param + "=s&v=1.2.0")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(res.Header.Get("Content-Type"), "javascript") || string(got) != sensorScript {
		t.Fatalf("script not served: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	if strings.Contains(strings.ToLower(string(got)), "moonito") {
		t.Fatal("the served script names the service")
	}

	res, _ = http.Get(site.URL + "/shop?" + param + "=p")
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("ping answered %d", res.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodPost, site.URL+"/shop?"+param+"=t", strings.NewReader(`{"k":"pub_123"}`))
	req.Header.Set("X-Forwarded-For", "185.137.164.30")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("beacon answered %d", res.StatusCode)
	}

	select {
	case got := <-relayed:
		if got != `s {"ip":"185.137.164.30","p":"{\"k\":\"pub_123\"}"}` {
			t.Fatalf("relay carried %s", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("beacon was not relayed")
	}

	if decisions != 0 {
		t.Fatalf("sensor requests cost %d decisions", decisions)
	}

	// A generic parameter is just a page.
	res, _ = http.Get(site.URL + "/shop?__vt=s")
	page, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(page), "Shop") || decisions != 1 {
		t.Fatalf("a generic parameter was treated as the sensor's")
	}

	if New(Config{APIPublicKey: "pub_456"}).relayParam() == param {
		t.Fatal("two sites share a parameter")
	}
}

func TestSelfCSPStillGetsTheSensorWithThePagePath(t *testing.T) {
	api := fakeAPI(t, false)
	cfg := Config{IsProtected: true, APIPublicKey: "pub_123", APISecretKey: "s", Endpoint: api.URL}
	site := httptest.NewServer(New(cfg).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; object-src 'none'")
		_, _ = io.WriteString(w, testPage)
	})))
	t.Cleanup(site.Close)
	req, _ := http.NewRequest("GET", site.URL+"/shop/item?id=5", nil)
	req.Header.Set("Accept", "text/html")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(got), `src="/shop/item?`) || !strings.Contains(string(got), `data-endpoint="/shop/item"`) {
		t.Fatalf("self policy or page path not honoured: %s", got)
	}
}

// A broken or missing API must never break the customer's page or the relay.
func TestApiFaultsNeverBreakThePage(t *testing.T) {
	modes := map[string]http.HandlerFunc{
		"http500": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(500)
			_, _ = io.WriteString(w, "<html>err</html>")
		},
		"garbage":    func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "\x00 not json {") },
		"wrongshape": func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{"data":"x"}`) },
		"empty":      func(w http.ResponseWriter, r *http.Request) {},
	}
	for name, handler := range modes {
		api := httptest.NewServer(handler)
		cfg := Config{IsProtected: true, APIPublicKey: "pub_123", APISecretKey: "s", Endpoint: api.URL}
		site := httptest.NewServer(New(cfg).Middleware(http.HandlerFunc(htmlHandler)))
		param := New(cfg).relayParam()

		res, err := http.Get(site.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 200 || !strings.Contains(string(got), "Halo") {
			t.Errorf("%s: page broke: %d", name, res.StatusCode)
		}

		for _, body := range []string{`{"k":"pub_123"}`, "not json <<<", strings.Repeat("x", 20000), ""} {
			res, err = http.Post(site.URL+"/?"+param+"=t", "text/plain", strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			if res.StatusCode != http.StatusNoContent {
				t.Errorf("%s: beacon answered %d", name, res.StatusCode)
			}
		}

		site.Close()
		api.Close()
	}
}
