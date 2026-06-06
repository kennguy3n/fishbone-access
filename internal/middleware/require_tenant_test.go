package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
)

func requireTenantTestDB(t *testing.T) (*gorm.DB, uuid.UUID) {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ws := &models.Workspace{Name: "acme", IAMCoreTenantID: "claim-tenant"}
	if err := db.Create(ws).Error; err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	return db, ws.ID
}

// scopedRouter mounts Auth + ResolveTenant + RequireTenant in front of a
// handler that can ONLY answer with the workspace id it reads from context.
// This is the structural proof that a handler cannot run an unscoped query: it
// has no other source for a workspace id.
func scopedRouter(v TokenValidator, db *gorm.DB) *gin.Engine {
	r := gin.New()
	r.Use(Auth(v), ResolveTenant(), RequireTenant(db))
	r.GET("/scoped", func(c *gin.Context) {
		ws, ok := WorkspaceFromContext(c)
		if !ok {
			// Defense in depth: RequireTenant guarantees this never happens,
			// but if the guard were ever removed the handler still refuses to
			// query without a workspace.
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "no workspace"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"workspace_id": ws.String()})
	})
	return r
}

func TestRequireTenantResolvesWorkspace(t *testing.T) {
	db, wsID := requireTenantTestDB(t)
	v := fakeValidator{claims: &iamcore.Claims{Subject: "u", TenantID: "claim-tenant"}}
	r := scopedRouter(v, db)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/scoped", nil)
	req.Header.Set("Authorization", "Bearer good")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if want := wsID.String(); !strings.Contains(w.Body.String(), want) {
		t.Fatalf("body %q does not contain workspace id %q", w.Body.String(), want)
	}
}

// TestRequireTenantNoWorkspace403 proves that an authenticated principal whose
// tenant has no provisioned workspace gets 403 — never a fall-through to an
// unscoped query.
func TestRequireTenantNoWorkspace403(t *testing.T) {
	db, _ := requireTenantTestDB(t)
	v := fakeValidator{claims: &iamcore.Claims{Subject: "u", TenantID: "unprovisioned-tenant"}}
	r := scopedRouter(v, db)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/scoped", nil)
	req.Header.Set("Authorization", "Bearer good")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for tenant with no workspace", w.Code)
	}
}

// TestRequireTenantNoClaim403 proves the fail-closed chain end to end: a token
// with no tenant_id claim is rejected by ResolveTenant before RequireTenant
// ever runs, so no workspace is ever set and the handler cannot query.
func TestRequireTenantNoClaim403(t *testing.T) {
	db, _ := requireTenantTestDB(t)
	v := fakeValidator{claims: &iamcore.Claims{Subject: "u"}} // no tenant claim
	r := scopedRouter(v, db)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/scoped", nil)
	req.Header.Set("Authorization", "Bearer good")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 when token has no tenant claim", w.Code)
	}
}

// TestRequireTenantNilDB503 proves a misconfigured deployment (no tenant store)
// fails closed with 503 rather than serving an unscoped request.
func TestRequireTenantNilDB503(t *testing.T) {
	v := fakeValidator{claims: &iamcore.Claims{Subject: "u", TenantID: "claim-tenant"}}
	r := scopedRouter(v, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/scoped", nil)
	req.Header.Set("Authorization", "Bearer good")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when tenant store is unavailable", w.Code)
	}
}
