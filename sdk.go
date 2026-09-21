package moonitogo

// Config contains SDK configuration.
type Config struct {
	IsProtected           bool
	APIPublicKey          string
	APISecretKey          string
	UnwantedVisitorTo     string
	UnwantedVisitorAction int
	// Endpoint overrides the API base. Empty means https://moonito.net.
	Endpoint string

	// ChallengeAction decides what happens when the engine asks for a
	// challenge:
	//
	//   "allow"      treat it as an allow and log it. The default.
	//   "block"      treat it as a block.
	//   "challenge"  actually show the interstitial.
	//
	// Empty means "allow", on purpose and matching the PHP SDK. Turning a
	// scored challenge into a real page interruption changes what a visitor
	// sees, and that is the site owner's decision, not a side effect of taking
	// an upgrade.
	ChallengeAction string
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
