package middleware

import (
	"github.com/labstack/echo/v4"
	"github.com/moonito-net/moonito-go"
)

// EchoTrafficFilter adapts moonito-go client into an Echo middleware
func EchoTrafficFilter(client *moonitogo.Client) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Quick skip for health or static endpoints if needed:
			// if strings.HasPrefix(c.Request().URL.Path, "/health") { return next(c) }

			// EvaluateVisitor fails open: when the check cannot run it logs
			// the reason and the visitor continues. A protection problem must
			// never become a 500 on the customer's site.
			_ = client.EvaluateVisitor(c.Response(), c.Request())
			// if client already wrote a response (blocked visitor) do not continue
			if c.Response().Committed {
				return nil
			}
			return next(c)
		}
	}
}

// GetClientIP is kept for compatibility. It returns Echo's RealIP, which
// follows Echo's own IPExtractor configuration. The SDK itself resolves the
// visitor address separately and never trusts a forwarded header from a
// connection that is not a proxy.
func GetClientIP(c echo.Context) string {
	return c.RealIP()
}
