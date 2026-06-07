//go:build embed

package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var embedded embed.FS

func init() {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		panic("webui: embed dist: " + err.Error())
	}
	FS = sub
}
