package startup

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"github.com/zjyl1994/arkauthn/infra/utils"
	"github.com/zjyl1994/arkauthn/infra/vars"
	"github.com/zjyl1994/arkauthn/server"
	"github.com/zjyl1994/cap-go"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/natefinch/lumberjack.v2"
)

func Start() error {
	var masterURL string
	flag.StringVar(&masterURL, "master_url", "", "Master URL")
	flag.Parse()

	workingDir, err := os.Getwd()
	if err != nil || workingDir == "" {
		workingDir = "."
	}
	stateDir := getStateDir()
	if err := ensureDir(stateDir); err != nil {
		return err
	}
	_ = godotenv.Load(filepath.Join(stateDir, ".env"), filepath.Join(workingDir, ".env"))

	vars.Config.Listen = getEnv("ARKAUTHN_LISTEN", "127.0.0.1:9008")
	vars.Config.LogLevel = getEnv("ARKAUTHN_LOG_LEVEL", "info")
	vars.Config.LogFile = getEnv("ARKAUTHN_LOG_FILE", filepath.Join(stateDir, "arkauthn.log"))
	vars.Config.Redirect = getEnv("ARKAUTHN_REDIRECT", "http://127.0.0.1:9008")
	trustedDomain := getEnv("ARKAUTHN_TRUSTED_DOMAIN", "")
	if trustedDomain == "" {
		if domain, err := utils.ExtractRootDomain(vars.Config.Redirect); err == nil {
			trustedDomain = domain
		}
	}
	vars.Config.TrustedDomain = trustedDomain
	envTrustedProxies := getEnv("ARKAUTHN_TRUSTED_PROXIES", "")
	if envTrustedProxies != "" {
		vars.Config.TrustedProxies = splitEnvList(envTrustedProxies)
	}
	defaultJail := normalizeJailConfig(vars.JailConfig{Enabled: true})
	vars.Config.Jail.Enabled = getEnvBool("ARKAUTHN_JAIL_ENABLED", defaultJail.Enabled)
	vars.Config.Jail.MaxAttempts = getEnvInt("ARKAUTHN_JAIL_MAX_ATTEMPTS", defaultJail.MaxAttempts)
	vars.Config.Jail.BanDuration = getEnvInt("ARKAUTHN_JAIL_BAN_DURATION", defaultJail.BanDuration)
	vars.Config.Jail = normalizeJailConfig(vars.Config.Jail)

	if masterURL != "" {
		vars.NodeRole = vars.NodeRoleReplica
		vars.Config.Redirect = masterURL
		publicConfig, err := fetchPublicConfig(masterURL)
		if err != nil {
			return err
		}
		if err := loadEd25519PublicKey(publicConfig.Ed25519PublicKey); err != nil {
			return err
		}
	} else {
		vars.NodeRole = vars.NodeRoleMaster
		keysFile := getEnv("ARKAUTHN_KEYS_FILE", filepath.Join(stateDir, "arkauthn.keys.json"))
		usersFile := getEnv("ARKAUTHN_USERS_FILE", filepath.Join(stateDir, "arkauthn.users.json"))
		if err := loadOrCreateKeys(keysFile); err != nil {
			return err
		}
		if err := loadOrCreateUsers(usersFile); err != nil {
			return err
		}
	}
	if vars.Config.Jail.Enabled {
		vars.AuthRateLimiter = utils.NewErrorSlidingWindowLimiter(vars.Config.Jail.MaxAttempts, time.Duration(vars.Config.Jail.BanDuration)*time.Second)
	}
	// init log
	logLevel, err := logrus.ParseLevel(vars.Config.LogLevel)
	if err != nil {
		return err
	}
	logrus.SetLevel(logLevel)
	if len(vars.Config.LogFile) > 0 {
		fileLogger := &lumberjack.Logger{
			Filename:   vars.Config.LogFile,
			MaxSize:    10,
			MaxBackups: 3,
			MaxAge:     7,
			Compress:   true,
		}
		logrus.AddHook(utils.NewFileHook(fileLogger))
	}
	vars.CapInstance = cap.NewCap(utils.NewFreeCacheStorage(50 * 1024))
	// start server
	logrus.Infoln("ArkAuthn running in", vars.Config.Listen)
	shutdownContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return server.Run(shutdownContext)
}

func parseEd25519Keys(publicKey string, privateKey string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if publicKey == "" || privateKey == "" {
		return nil, nil, errors.New("ed25519 key missing")
	}
	pubBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, nil, err
	}
	privBytes, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, nil, err
	}
	if len(pubBytes) != ed25519.PublicKeySize || len(privBytes) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("ed25519 key invalid")
	}
	return ed25519.PublicKey(pubBytes), ed25519.PrivateKey(privBytes), nil
}

func generateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func loadEd25519PublicKey(publicKey string) error {
	if publicKey == "" {
		return errors.New("ed25519 public key missing")
	}
	pubBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return err
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return errors.New("ed25519 public key invalid")
	}
	vars.Ed25519PublicKey = ed25519.PublicKey(pubBytes)
	return nil
}

func loadOrCreateKeys(keysFile string) error {
	if _, err := os.Stat(keysFile); os.IsNotExist(err) {
		pubKey, privKey, err := generateEd25519KeyPair()
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(vars.KeysFile{
			Ed25519PublicKey:  base64.StdEncoding.EncodeToString(pubKey),
			Ed25519PrivateKey: base64.StdEncoding.EncodeToString(privKey),
		}, "", "    ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(keysFile, data, 0600); err != nil {
			return err
		}
	}
	bConf, err := os.ReadFile(keysFile)
	if err != nil {
		return err
	}
	var keys vars.KeysFile
	if err := json.Unmarshal(bConf, &keys); err != nil {
		return err
	}
	pubKey, privKey, err := parseEd25519Keys(keys.Ed25519PublicKey, keys.Ed25519PrivateKey)
	if err != nil {
		return err
	}
	vars.Ed25519PublicKey = pubKey
	vars.Ed25519PrivateKey = privKey
	return nil
}

func loadOrCreateUsers(usersFile string) error {
	if _, err := os.Stat(usersFile); os.IsNotExist(err) {
		initUser := getEnv("ARKAUTHN_INIT_USERNAME", "")
		initPassword := getEnv("ARKAUTHN_INIT_PASSWORD", "")
		if initUser == "" || initPassword == "" {
			return errors.New("users file missing; set ARKAUTHN_INIT_USERNAME and ARKAUTHN_INIT_PASSWORD to initialize")
		}
		if len(initPassword) < 8 {
			return errors.New("initial password too short; must be at least 8 characters")
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(initPassword), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		defaultUsers := vars.UsersFile{
			Users: []vars.UserItem{
				{
					Username: initUser,
					Password: string(hash),
				},
			},
		}
		data, err := json.MarshalIndent(defaultUsers, "", "    ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(usersFile, data, 0600); err != nil {
			return err
		}
	}
	bConf, err := os.ReadFile(usersFile)
	if err != nil {
		return err
	}
	var users vars.UsersFile
	if err := json.Unmarshal(bConf, &users); err != nil {
		return err
	}
	vars.Users = users.Users
	return nil
}

func normalizeJailConfig(cfg vars.JailConfig) vars.JailConfig {
	if cfg.MaxAttempts == 0 {
		cfg.MaxAttempts = 5
	}
	if cfg.BanDuration == 0 {
		cfg.BanDuration = 300
	}
	return cfg
}

func fetchPublicConfig(masterURL string) (vars.PublicConfig, error) {
	u, err := url.Parse(masterURL)
	if err != nil {
		return vars.PublicConfig{}, err
	}
	if u.Scheme == "" || u.Host == "" {
		return vars.PublicConfig{}, errors.New("redirect_url invalid")
	}
	u.Path = "/.well-known/arkauthn.json"
	u.RawQuery = ""
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get(u.String())
	if err != nil {
		return vars.PublicConfig{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return vars.PublicConfig{}, errors.New("remote config not available")
	}
	var config vars.PublicConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return vars.PublicConfig{}, err
	}
	return config, nil
}

func getEnv(key string, fallback string) string {
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		return fallback
	}
	return value
}

func getEnvInt(key string, fallback int) int {
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		return fallback
	}
	num, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return num
}

func getEnvBool(key string, fallback bool) bool {
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		return fallback
	}
	val, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return val
}

func splitEnvList(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

func getStateDir() string {
	stateDir := os.Getenv("STATE_DIRECTORY")
	if stateDir != "" {
		parts := strings.Split(stateDir, ":")
		for _, part := range parts {
			item := strings.TrimSpace(part)
			if item != "" {
				return item
			}
		}
	}
	workingDir, err := os.Getwd()
	if err == nil && workingDir != "" {
		return workingDir
	}
	return "."
}

func ensureDir(path string) error {
	if path == "" {
		return errors.New("state directory missing")
	}
	return os.MkdirAll(path, 0755)
}
