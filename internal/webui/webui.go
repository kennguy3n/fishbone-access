// Package webui optionally serves the embedded Access console (the ui/ SPA)
// from the same binary as the API, so ShieldNet Access ships as a single
// deployable.
//
// The embedded assets are wired in only when the binary is built with the
// `embed_ui` build tag (see embed.go); the default build leaves Assets nil and
// Register is a no-op, so a plain `go build` / `go test` needs no prebuilt UI.
// Production images run `npm run build` (which emits to internal/webui/dist)
// and then `go build -tags embed_ui ./cmd/ztna-api`.
//
// Runtime config: the SPA reads window.__SNG_CONFIG__ from /config.js, which is
// embedded with safe same-origin defaults (apiBaseUrl "/api/v1", authMode
// "jwt"). To enable OIDC (or point at a non-same-origin API) without rebuilding
// the bundle, a deploy overwrites that single asset at start time — the same
// pattern the static nginx image uses (ui/public/config.js is the template).
package webui

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
)

// Assets holds the built SPA rooted at its top directory (index.html at the
// root). It is nil unless the binary was built with the embed_ui tag.
var Assets fs.FS

// Enabled reports whether an embedded UI is available to serve.
func Enabled() bool { return Assets != nil }

// reserved paths are owned by the API/operational surface and must never be
// shadowed by the SPA fallback.
func reserved(p string) bool {
	return p == "/health" ||
		p == "/readyz" ||
		p == "/api" ||
		strings.HasPrefix(p, "/api/")
}

// Register mounts the embedded console on r via a NoRoute handler: real asset
// files are served with correct content types and long-lived caching, and any
// other (non-API) GET falls back to index.html so client-side routes deep-link
// correctly. It is a no-op when no UI is embedded.
func Register(r *gin.Engine) {
	if Assets == nil {
		return
	}
	fileServer := http.FileServer(http.FS(Assets))

	r.NoRoute(func(c *gin.Context) {
		req := c.Request
		// Only GET/HEAD can resolve to a page; everything else on an unknown
		// route is a genuine 404 (don't answer POST /api typos with HTML).
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		clean := path.Clean(req.URL.Path)
		if reserved(clean) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}

		// Serve a real asset (JS/CSS/img) when the path maps to one; otherwise
		// hand back index.html for the SPA router to resolve.
		if name := strings.TrimPrefix(clean, "/"); name != "" {
			if f, err := Assets.Open(name); err == nil {
				info, statErr := f.Stat()
				_ = f.Close()
				if statErr == nil && !info.IsDir() {
					// index.html (even when requested directly) must go through
					// serveIndex so it carries Cache-Control: no-cache; the
					// file server would serve it cacheable (embed.FS has no
					// modtime), risking a stale shell pointing at 404'd bundles.
					if name == "index.html" {
						serveIndex(c)
						return
					}
					fileServer.ServeHTTP(c.Writer, req)
					return
				}
			}
		}
		serveIndex(c)
	})
}

func serveIndex(c *gin.Context) {
	data, err := fs.ReadFile(Assets, "index.html")
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "ui assets missing index.html",
		})
		return
	}
	// index.html must never be cached: it references content-hashed asset URLs
	// that change on every deploy, so a stale index would point at 404'd bundles.
	c.Header("Cache-Control", "no-cache")
	c.Data(http.StatusOK, "text/html; charset=utf-8", data)
}
