package vars

type ConfigFile struct {
	Listen         string     `json:"listen"`
	Redirect       string     `json:"redirect"`
	LogFile        string     `json:"log_file,omitempty"`
	LogLevel       string     `json:"log_level"`
	Secret         string     `json:"secret"`
	Users          []UserItem `json:"users"`
	Jail           JailConfig `json:"jail,omitempty"`
	TrustedDomains []string   `json:"trusted_domains,omitempty"`
	TrustedProxies []string   `json:"trusted_proxies,omitempty"`
}

type UserItem struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Nonce    string `json:"nonce,omitempty"`
}

type JailConfig struct {
	Enabled     bool `json:"enabled"`
	MaxAttempts int  `json:"max_attempts"`
	BanDuration int  `json:"ban_duration"`
}
