package moonitogo

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestDecisionInputLimitsStillBlock(t *testing.T) {
	for _, scenario := range []string{"headers", "path", "ua", "method", "combined"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				valid := true
				for field, limit := range map[string]int{"ua": 2048, "events": 4096, "method": 16, "path": 512} {
					value, _ := body[field].(string)
					valid = valid && utf8.RuneCountInString(value) <= limit && utf8.ValidString(value)
				}
				headers, _ := body["headers"].(map[string]any)
				valid = valid && len(headers) <= 64
				for name, value := range headers {
					if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Proxy-Authorization") || strings.EqualFold(name, "Cookie") {
						t.Error("visitor credential forwarded")
					}
					valid = valid && utf8.RuneCountInString(value.(string)) <= 2048
				}
				if !valid {
					w.WriteHeader(422)
					fmt.Fprint(w, `{"error":{"message":"validation"}}`)
					return
				}
				fmt.Fprint(w, `{"data":{"status":{"need_to_block":true}}}`)
			}))
			defer api.Close()
			sdk := New(Config{IsProtected: true, APIPublicKey: "dummy", APISecretKey: "dummy", Endpoint: api.URL})
			req := httptest.NewRequest("GET", "https://example.com/private", nil)
			req.RemoteAddr = "185.137.164.30:443"
			if scenario == "headers" || scenario == "combined" {
				for i := 0; i < 100; i++ {
					req.Header.Set(fmt.Sprintf("X-Test-%d", i), strings.Repeat("😀", 3000))
				}
				req.Header.Set("Authorization", "secret")
				req.Header.Set("Proxy-Authorization", "secret")
				req.Header.Set("Cookie", "session=secret")
			}
			if scenario == "path" || scenario == "combined" {
				req.URL.Path = "/" + strings.Repeat("😀", 5000)
			}
			if scenario == "ua" || scenario == "combined" {
				req.Header.Set("User-Agent", strings.Repeat("😀", 3000))
			}
			if scenario == "method" || scenario == "combined" {
				req.Method = strings.Repeat("A", 30)
			}
			rec := httptest.NewRecorder()
			protectedPage(sdk).ServeHTTP(rec, req)
			if calls != 1 || rec.Code != 403 || strings.Contains(rec.Body.String(), "SECRET PAGE") {
				t.Fatalf("check bypassed: calls=%d status=%d", calls, rec.Code)
			}
		})
	}
}

func TestSensorContextAndApplicationCookies(t *testing.T) {
	for _, identity := range []bool{false, true} {
		t.Run(fmt.Sprint(identity), func(t *testing.T) {
			extra := ""
			if identity {
				extra = `,"set_client_token":{"value":"identity"}`
			}
			api := apiReturning(200, `{"data":{"status":{"need_to_block":false},"decision_id":"did","nonce":"proof"`+extra+`}}`)
			defer api.Close()
			sdk := New(Config{IsProtected: true, APIPublicKey: "dummy", APISecretKey: "dummy", Endpoint: api.URL})
			rec := httptest.NewRecorder()
			rec.Header().Add("Set-Cookie", "session=existing; Path=/")
			protectedPage(sdk).ServeHTTP(rec, httptest.NewRequest("GET", "https://example.com/private", nil))
			cookies := map[string]*http.Cookie{}
			for _, cookie := range rec.Result().Cookies() {
				cookies[cookie.Name] = cookie
			}
			if cookies["session"] == nil {
				t.Fatal("session lost")
			}
			context := cookies["__mo_cx"]
			if context == nil {
				t.Fatal("context missing")
			}
			value, _ := url.QueryUnescape(context.Value)
			if value != "did:proof" || context.MaxAge != 120 || !context.Secure || context.HttpOnly {
				t.Fatalf("invalid context: %+v", context)
			}
			if (cookies["__mo_ct"] != nil) != identity {
				t.Fatal("unexpected identity cookie")
			}
			if rec.Body.String() != "SECRET PAGE" {
				t.Fatal("allow failed")
			}
		})
	}
}

func TestChallengeActionsStillWork(t *testing.T) {
	for _, action := range []string{"allow", "block", "challenge"} {
		t.Run(action, func(t *testing.T) {
			api := apiReturning(200, `{"data":{"status":{"need_to_block":false},"challenge_url":"https://challenge.example/check"}}`)
			defer api.Close()
			sdk := New(Config{IsProtected: true, APIPublicKey: "dummy", APISecretKey: "dummy", Endpoint: api.URL, ChallengeAction: action})
			rec := httptest.NewRecorder()
			protectedPage(sdk).ServeHTTP(rec, httptest.NewRequest("GET", "https://example.com/private", nil))
			if action == "allow" && rec.Body.String() != "SECRET PAGE" {
				t.Fatal("allow failed")
			}
			if action == "block" && rec.Code != 403 {
				t.Fatal("block failed")
			}
			if action == "challenge" && !strings.Contains(rec.Body.String(), "sessionStorage") {
				t.Fatal("challenge failed")
			}
		})
	}
}
