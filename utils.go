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

// cloudflareRanges are Cloudflare's published edge ranges. CF-Connecting-IP is
// only read from a connection that comes from one of them.
var cloudflareRanges = parseRanges([]string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
})

func parseRanges(entries []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if !strings.Contains(entry, "/") {
			if ip := net.ParseIP(entry); ip != nil {
				bits := 128
				if ip.To4() != nil {
					bits = 32
				}
				out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			}
			continue
		}
		if _, n, err := net.ParseCIDR(entry); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func inRanges(ip net.IP, ranges []*net.IPNet) bool {
	for _, n := range ranges {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func isPrivateIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		(ip.To4() != nil && ip.To4()[0] == 100 && ip.To4()[1]&0xC0 == 64)
}

// clientIP returns the visitor's address.
//
// Forwarded headers are set by whoever makes the request, so they are only
// believed when the connection came from a proxy: a private address, one
// listed in TrustedProxies, or Cloudflare for CF-Connecting-IP. Reading them
// unconditionally let a bot claim any clean address it liked.
func (c *Client) clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}

	remote := net.ParseIP(host)
	if remote == nil {
		return ""
	}

	trusted := parseRanges(c.cfg.TrustedProxies)
	fromCloudflare := inRanges(remote, cloudflareRanges)

	if !fromCloudflare && !isPrivateIP(remote) && !inRanges(remote, trusted) {
		return remote.String()
	}

	if fromCloudflare {
		if cf := net.ParseIP(strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))); cf != nil {
			return cf.String()
		}
	}

	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := net.ParseIP(strings.Trim(strings.TrimSpace(parts[i]), "[]"))
		if candidate == nil {
			continue
		}
		if isPrivateIP(candidate) || inRanges(candidate, trusted) || inRanges(candidate, cloudflareRanges) {
			continue
		}
		return candidate.String()
	}

	return remote.String()
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
