package vars

import "github.com/zjyl1994/cap-go"

var (
	Config          ConfigFile
	AuthRateLimiter SlidingWindowLimiterIFace
	CapInstance     cap.ICap
)

const (
	APP_NAME = "ARKAUTHN"
)
