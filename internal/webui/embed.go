//go:build embed_ui

package webui

import (
	"embed"
	"io/fs"
)

// distFS holds the production build of the Access console. It is populated only
// under the embed_ui build tag, so a default build does not require the SPA to
// have been built first.
//
//go:embed all:dist
var distFS embed.FS

func init() {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		// A build that sets embed_ui but produced no dist/ is a build-pipeline
		// bug; fail loudly at startup rather than silently serving nothing.
		panic("webui: embed_ui build is missing internal/webui/dist: " + err.Error())
	}
	Assets = sub
}
