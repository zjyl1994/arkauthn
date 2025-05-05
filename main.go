package main

import (
	"github.com/sirupsen/logrus"
	"github.com/zjyl1994/arkauthn/infra/startup"
)

func main() {
	err := startup.Start()
	if err != nil {
		logrus.Fatalln(err.Error())
	}
}
