package web

import (
	"embed"
	"io/fs"
)

//go:embed public
var publicFiles embed.FS

func GetHttpAssets() (fs.FS, error) {
	f, err := fs.Sub(publicFiles, "public")
	if err != nil {
		return nil, err
	}
	return f, nil
}
