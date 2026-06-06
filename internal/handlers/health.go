package handlers

import (
	"net/http"
	"sync/atomic"

	"github.com/gin-gonic/gin"
)

// liveness reports the process is up. It must never depend on downstream
// systems (DB, Redis, iam-core) so a liveness probe failure means "restart me",
// not "a dependency is slow".
func liveness(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// readiness reports whether the process is ready to serve traffic. It flips to
// true once boot wiring (migrations, dependency dials) completes. A nil flag is
// treated as ready (used by tests that don't model boot).
func readiness(ready *atomic.Bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if ready == nil || ready.Load() {
			c.JSON(http.StatusOK, gin.H{"status": "ready"})
			return
		}
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not ready"})
	}
}
