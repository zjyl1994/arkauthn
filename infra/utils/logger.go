package utils

import (
	"io"

	"github.com/sirupsen/logrus"
)

type FileHook struct {
	writer    io.Writer
	formatter logrus.Formatter
}

func NewFileHook(writer io.Writer) *FileHook {
	return &FileHook{
		writer: writer,
		formatter: &logrus.TextFormatter{
			DisableColors: true,
		},
	}
}

func (h *FileHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *FileHook) Fire(entry *logrus.Entry) error {
	line, err := h.formatter.Format(entry)
	if err != nil {
		return err
	}
	_, err = h.writer.Write(line)
	return err
}
