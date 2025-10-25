package moonitogo

// Config contains SDK configuration.
type Config struct {
	IsProtected           bool
	APIPublicKey          string
	APISecretKey          string
	UnwantedVisitorTo     string
	UnwantedVisitorAction int
	// Optionally you can add HTTP client config, timeouts, logger, etc.
}

// Client is the main SDK client.
type Client struct {
	cfg         Config
	bypassToken string
}

// New returns a new Client instance.
func New(cfg Config) *Client {
	return &Client{
		cfg:         cfg,
		bypassToken: generateSecureTokenHex(32),
	}
}

func (c *Client) Config() Config {
	return c.cfg
}
