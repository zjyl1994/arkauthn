package vars

type ConfigFile struct {
	Listen         string     `json:"listen"`
	Redirect       string     `json:"redirect"`
	LogFile        string     `json:"log_file,omitempty"`
	LogLevel       string     `json:"log_level"`
	Jail           JailConfig `json:"jail,omitempty"`
	TrustedDomain  string     `json:"trusted_domain,omitempty"`
	TrustedProxies []string   `json:"trusted_proxies,omitempty"`
}

type UserItem struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type UsersFile struct {
	Users []UserItem `json:"users"`
}

type KeysFile struct {
	Ed25519PublicKey  string `json:"ed25519_public_key"`
	Ed25519PrivateKey string `json:"ed25519_private_key"`
}

type PublicConfig struct {
	Redirect         string `json:"redirect"`
	Ed25519PublicKey string `json:"ed25519_public_key"`
}

type JailConfig struct {
	Enabled     bool `json:"enabled"`
	MaxAttempts int  `json:"max_attempts"`
	BanDuration int  `json:"ban_duration"`
}
