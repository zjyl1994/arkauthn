package vars

var (
	Config          ConfigFile
	SecretKey       []byte
	AuthRateLimiter SlidingWindowLimiterIFace
)

const (
	APP_NAME = "ARKAUTHN"
)
