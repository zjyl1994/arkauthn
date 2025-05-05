package web

import "embed"

//go:embed public
var PublicFiles embed.FS

//go:embed template
var TemplateFiles embed.FS
