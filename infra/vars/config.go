package vars

type ConfigFile struct {
	Listen   string     `json:"listen"`
	Host     string     `json:"host"`
	Secret   string     `json:"secret"`
	LogFile  string     `json:"logfile"`
	LogLevel string     `json:"loglevel"`
	Users    []UserItem `json:"users"`
}

type UserItem struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
