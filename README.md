# Moonito Go SDK (`moonito-go`)

> Official Go SDK for [Moonito](https://moonito.net) — a smart analytics and visitor filtering platform designed to protect your website from unwanted traffic, bots, and malicious activity while providing deep visitor insights.

[![Go Reference](https://pkg.go.dev/badge/github.com/moonito-net/moonito-go.svg)](https://pkg.go.dev/github.com/moonito-net/moonito-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/moonito-net/moonito-go)](https://goreportcard.com/report/github.com/moonito-net/moonito-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Overview

`moonito-go` is a lightweight Go SDK for integrating your web application with the **Moonito Visitor Analytics API**.  
It allows you to:

- Analyze and monitor web traffic intelligently
- Filter out bots, crawlers, and unwanted visitors
- Get real-time visitor behavior insights
- Protect APIs, landing pages, and web apps automatically

Compatible with **Echo**, **Gin**, **Fiber**, and other Go web frameworks.

---

## Installation

Initialize your Go module (if you haven’t yet):

```bash
go mod init github.com/yourusername/yourproject
```

Then install the SDK:

```bash
go get github.com/moonito-net/moonito-go@v1.3.1
```

---

## Quick Start (net/http)

Version v1.3.1 bounds visitor input to the decision API limits and forwards
sensor correlation through a short-lived response cookie. Existing API keys
and settings remain compatible. Upgrade the module, rebuild, and redeploy the
application to load the fix.

```go
package main

import (
	"log"
	"net/http"

	moonito "github.com/moonito-net/moonito-go"
)

func main() {
	client := moonito.New(moonito.Config{
		IsProtected:           true,
		APIPublicKey:          "YOUR_PUBLIC_KEY",
		APISecretKey:          "YOUR_SECRET_KEY",
		UnwantedVisitorTo:     "https://example.com/blocked", // URL or HTTP status code
		UnwantedVisitorAction: 1,                             // 1 = Redirect, 2 = Iframe, 3 = Load content
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})

	// Unwanted visitors are answered by Moonito and never reach your routes.
	log.Fatal(http.ListenAndServe(":8080", client.Middleware(mux)))
}
```

## Quick Start (Echo)

```go
import "github.com/moonito-net/moonito-go/middleware"

e := echo.New()
e.Use(middleware.EchoTrafficFilter(client))
```

If the check cannot run (the API is unreachable, or refuses because a plan expired) the visitor is let through and the reason is logged. Moonito never turns into an error page on your site.

---

## Configuration Options

| Field | Type | Description |
|--------|------|-------------|
| `IsProtected` | `bool` | Enable (`true`) or disable (`false`) protection |
| `APIPublicKey` | `string` | Your Moonito API public key (required) |
| `APISecretKey` | `string` | Your Moonito API secret key (required) |
| `UnwantedVisitorTo` | `string` | URL to redirect unwanted visitors or HTTP error code |
| `UnwantedVisitorAction` | `int` | Action for unwanted visitors: `1` = Redirect, `2` = Iframe, `3` = Load content |
| `TrustedProxies` | `[]string` | Optional. Public proxy or load balancer IPs/CIDRs whose `X-Forwarded-For` is trusted. Private proxies and Cloudflare are recognised automatically |

---

## Manual Evaluation (No Framework)

```go
result, err := client.EvaluateVisitorManually("8.8.8.8", "Mozilla/5.0", "/home", "example.com")
if err != nil {
    fmt.Println("Error:", err)
}

if result.NeedToBlock {
    fmt.Println("Blocked visitor detected.")
}
```

---

## Example Use Cases

- Prevent fake signups and bot traffic
- Protect landing pages from ad click fraud
- Collect accurate visitor analytics
- Detect suspicious activity in real time

---

## Requirements

- Go 1.19 or higher
- Moonito API keys from [https://moonito.net](https://moonito.net)

---

## Development Setup

```bash
git clone https://github.com/moonito-net/moonito-go.git
cd moonito-go
go mod tidy
go run examples/main.go
```

---

## Testing

```bash
go test ./...
```

---

## License

MIT License © 2025 [Moonito](https://moonito.net)

---

## Keywords

go analytics sdk, moonito sdk, visitor filtering go, go bot protection, go traffic analytics, moonito go sdk, moonito api, website protection sdk go, moonito visitor analytics, go security sdk

---

## Learn More

Visit [https://moonito.net](https://moonito.net) to learn more about:

- Visitor analytics
- Website traffic protection
- API-based bot and fraud filtering

---

**Moonito — Stop Bad Bots. Start Accurate Web Analytics.**
