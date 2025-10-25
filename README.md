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
go get github.com/moonito-net/moonito-go
```

---

## Quick Start (with Echo)

```go
package main

import (
	"net/http"
	"github.com/labstack/echo/v4"
	"github.com/moonito-net/moonito-go"
)

func main() {
	e := echo.New()

	// Initialize Moonito
	client := moonito.New(moonito.Config{
		IsProtected:           true,
		APIPublicKey:          "YOUR_PUBLIC_KEY",
		APISecretKey:          "YOUR_SECRET_KEY",
		UnwantedVisitorTo:     "https://example.com/blocked", // URL or HTTP status code
		UnwantedVisitorAction: 1, // 1 = Redirect, 2 = Iframe, 3 = Load content
	})

	// Global middleware
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			blocked, err := client.EvaluateRequest(c.Request())
			if err != nil {
				return c.String(http.StatusInternalServerError, err.Error())
			}
			if blocked {
				return c.String(http.StatusForbidden, "Access Denied")
			}
			return next(c)
		}
	})

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})

	e.Start(":8080")
}
```

---

## Configuration Options

| Field | Type | Description |
|--------|------|-------------|
| `IsProtected` | `bool` | Enable (`true`) or disable (`false`) protection |
| `APIPublicKey` | `string` | Your Moonito API public key (required) |
| `APISecretKey` | `string` | Your Moonito API secret key (required) |
| `UnwantedVisitorTo` | `string` | URL to redirect unwanted visitors or HTTP error code |
| `UnwantedVisitorAction` | `int` | Action for unwanted visitors: `1` = Redirect, `2` = Iframe, `3` = Load content |

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
