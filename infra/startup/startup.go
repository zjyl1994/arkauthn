package startup

import (
	"encoding/json"
	"flag"
	"io"
	"os"

	_ "github.com/joho/godotenv/autoload"
	"github.com/sirupsen/logrus"
	"github.com/zjyl1994/arkauthn/infra/utils"
	"github.com/zjyl1994/arkauthn/infra/vars"
	"github.com/zjyl1994/arkauthn/server"
	"gopkg.in/natefinch/lumberjack.v2"
)

func Start() error {
	// init config
	var configFile string
	flag.StringVar(&configFile, "config", "config.json", "Config JSON path")
	flag.Parse()
	if configFile != "" {
		bConf, err := os.ReadFile(configFile)
		if err != nil {
			return err
		}
		err = json.Unmarshal(bConf, &vars.Config)
		if err != nil {
			return err
		}
		if vars.Config.Listen == "" {
			vars.Config.Listen = ":9008"
		}
		if vars.Config.Host == "" {
			vars.Config.Host = "http://127.0.0.1:9008"
		}
		if vars.Config.LogLevel == "" {
			vars.Config.LogLevel = "info"
		}
		vars.SecretKey = utils.SHA256([]byte(vars.Config.Secret))
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
		logrus.SetOutput(io.MultiWriter(os.Stdout, fileLogger))
	}
	// start server
	logrus.Infoln("ArkAuthn running in", vars.Config.Listen)
	return server.Run(vars.Config.Listen)
}
