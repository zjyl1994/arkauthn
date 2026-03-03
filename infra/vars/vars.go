package vars

import (
	"crypto/ed25519"

	"github.com/zjyl1994/cap-go"
)

var (
	Config            ConfigFile
	Users             []UserItem
	AuthRateLimiter   SlidingWindowLimiterIFace
	CapInstance       cap.ICap
	Ed25519PublicKey  ed25519.PublicKey
	Ed25519PrivateKey ed25519.PrivateKey
	NodeRole          = NodeRoleMaster
)

const (
	APP_NAME        = "ARKAUTHN"
	NodeRoleMaster  = "master"
	NodeRoleReplica = "replica"
)
