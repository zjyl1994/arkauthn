package vars

type ConfigFile struct {
	Listen      string     `json:"listen"`
	Redirect    string     `json:"redirect"`
	LogFile     string     `json:"log_file"`
	LogLevel    string     `json:"log_level"`
	Users       []UserItem `json:"users"`
	Jail        JailConfig `json:"jail"`
	TokenExpire int        `json:"token_expire"`
}

type UserItem struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type JailConfig struct {
	Enabled     bool `json:"enabled"`
	MaxAttempts int  `json:"max_attempts"`
	BanDuration int  `json:"ban_duration"`
}
