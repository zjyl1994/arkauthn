package vars

type ConfigFile struct {
	Listen   string     `json:"listen"`
	Redirect string     `json:"redirect"`
	Secret   string     `json:"secret"`
	LogFile  string     `json:"logfile"`
	LogLevel string     `json:"loglevel"`
	Users    []UserItem `json:"users"`
}

type UserItem struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
