package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed public
var publicFiles embed.FS

func GetHttpAssets() (http.FileSystem, error) {
	f, err := fs.Sub(publicFiles, "public")
	if err != nil {
		return nil, err
	}
	return http.FS(f), nil
}
