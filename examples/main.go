package main

import (
	"log"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/moonito-net/moonito-go"
	"github.com/moonito-net/moonito-go/middleware"
)

func main() {
	e := echo.New()

	// Build client
	client := moonitogo.New(moonitogo.Config{
		IsProtected:           true,
		APIPublicKey:          "YOUR_PUBLIC_KEY",
		APISecretKey:          "YOUR_SECRET_KEY",
		UnwantedVisitorTo:     "403", // Can be an HTTP status code (e.g., "403") or a redirect URL (e.g., "https://example.com/blocked")
		UnwantedVisitorAction: 1,
	})

	// Global middleware
	e.Use(middleware.EchoTrafficFilter(client))

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, legit visitor!")
	})

	log.Fatal(e.Start(":8080"))
}
