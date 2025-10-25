package middleware

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/moonito-net/moonito-go"
)

// EchoTrafficFilter adapts moonito-go client into an Echo middleware
func EchoTrafficFilter(client *moonitogo.Client) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Quick skip for health or static endpoints if needed:
			// if strings.HasPrefix(c.Request().URL.Path, "/health") { return next(c) }

			// run the visitor evaluation
			if err := client.EvaluateVisitor(c.Response(), c.Request()); err != nil {
				// on internal error, return 500
				return c.String(http.StatusInternalServerError, "Internal Server Error")
			}
			// if client already wrote a response (blocked visitor) do not continue
			if c.Response().Committed {
				return nil
			}
			return next(c)
		}
	}
}

// Simple helper to extract client IP if you need in Echo side
func GetClientIP(c echo.Context) string {
	req := c.Request()
	if cf := req.Header.Get("CF-Connecting-IP"); cf != "" {
		return cf
	}
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	return c.RealIP()
}
