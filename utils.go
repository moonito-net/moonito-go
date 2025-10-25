package moonitogo

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// generateSecureTokenHex returns n random bytes hex-encoded
func generateSecureTokenHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (c *Client) isValidBypassToken(token string) bool {
	if token == "" {
		return false
	}
	a := []byte(token)
	b := []byte(c.bypassToken)
	if len(a) != len(b) {
		// constant-time compare requires equal lengths -> return false but in constant time
		// do a compare with zeroed slice of same len to consume time
		tmp := make([]byte, len(b))
		_ = subtle.ConstantTimeCompare(tmp, b)
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

func isValidIP(ip string) bool {
	if ip == "" {
		return false
	}
	// if x-forwarded-for may contain comma-separated list, take first
	if strings.Contains(ip, ",") {
		parts := strings.Split(ip, ",")
		ip = strings.TrimSpace(parts[0])
	}
	return net.ParseIP(ip) != nil
}

func getClientIP(r *http.Request) string {
	// Try Cloudflare header then X-Forwarded-For then RemoteAddr
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		return cf
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	// if RemoteAddr includes port, strip it
	if r.RemoteAddr != "" {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			return host
		}
		return r.RemoteAddr
	}
	return ""
}

func getCurrentURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	host := r.Host
	if host == "" {
		host = r.Header.Get("Host")
	}
	uri := r.URL.RequestURI()
	u := &url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   uri,
	}
	return u.String()
}

// urlsMatch compares currentUrl and targetUrl (full URL or relative path)
func urlsMatch(currentUrl, targetUrl string) bool {
	if currentUrl == "" || targetUrl == "" {
		return false
	}
	// if target is absolute URL
	if strings.HasPrefix(targetUrl, "http://") || strings.HasPrefix(targetUrl, "https://") {
		cur, err1 := url.Parse(currentUrl)
		tgt, err2 := url.Parse(targetUrl)
		if err1 != nil || err2 != nil {
			return false
		}
		return cur.Host == tgt.Host && cur.Path == tgt.Path && cur.RawQuery == tgt.RawQuery
	}

	// relative path: compare path+query or path alone
	cur, err := url.Parse(currentUrl)
	if err != nil {
		return false
	}
	curPath := cur.Path
	if cur.RawQuery != "" {
		curPath = cur.Path + "?" + cur.RawQuery
	}
	return curPath == targetUrl || cur.Path == targetUrl || strings.Contains(currentUrl, targetUrl)
}
