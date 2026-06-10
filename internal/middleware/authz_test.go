package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
	"github.com/kennguy3n/fishbone-access/internal/services/authz"
)

// fakeResolver is a stand-in for *authz.RBACService in middleware unit tests.
type fakeResolver struct {
	membership *authz.Membership
	err        error
	gotWS      uuid.UUID
	gotUser    string
}

func (f *fakeResolver) GetMembership(_ context.Context, ws uuid.UUID, user string) (*authz.Membership, error) {
	f.gotWS, f.gotUser = ws, user
	if f.err != nil {
		return nil, f.err
	}
	return f.membership, nil
}

// inject sets the claims + workspace the AuthzMiddleware depends on, simulating
// a successful Auth → ResolveTenant → RequireTenant chain.
func inject(subject string, ws uuid.UUID) gin.HandlerFunc {
	return func(c *gin.Context) {
		if subject != "" {
			c.Set(ctxKeyClaims, &iamcore.Claims{Subject: subject})
		}
		if ws != uuid.Nil {
			c.Set(ctxKeyWorkspaceID, ws)
		}
		c.Next()
	}
}

func okHandler(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) }

func do(r *gin.Engine) int {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	return w.Code
}

func memberWith(role authz.WorkspaceRole) *authz.Membership {
	return &authz.Membership{Role: role}
}

func TestAuthzMiddlewareAllowsPermissionHolder(t *testing.T) {
	ws := uuid.New()
	res := &fakeResolver{membership: memberWith(authz.RoleAdmin)}
	r := gin.New()
	r.Use(inject("user-1", ws), AuthzMiddleware(res))
	r.GET("/x", RequirePermission(authz.PermRBACManage), okHandler)
	if code := do(r); code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if res.gotWS != ws || res.gotUser != "user-1" {
		t.Fatalf("resolver got (%s,%s), want (%s,user-1)", res.gotWS, res.gotUser, ws)
	}
}

func TestAuthzMiddlewareDeniesNonHolder(t *testing.T) {
	r := gin.New()
	r.Use(inject("user-1", uuid.New()), AuthzMiddleware(&fakeResolver{membership: memberWith(authz.RoleAuditor)}))
	r.GET("/x", RequirePermission(authz.PermPolicyPromote), okHandler)
	if code := do(r); code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", code)
	}
}

func TestAuthzMiddlewareDeniesNonMember(t *testing.T) {
	r := gin.New()
	r.Use(inject("user-1", uuid.New()), AuthzMiddleware(&fakeResolver{err: authz.ErrMembershipNotFound}))
	r.GET("/x", RequirePermission(authz.PermPolicyRead), okHandler)
	if code := do(r); code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (fail-closed non-member)", code)
	}
}

func TestAuthzMiddlewareResolverErrorIs503(t *testing.T) {
	r := gin.New()
	r.Use(inject("user-1", uuid.New()), AuthzMiddleware(&fakeResolver{err: context.DeadlineExceeded}))
	r.GET("/x", RequirePermission(authz.PermPolicyRead), okHandler)
	if code := do(r); code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (infra error denies but signals retryable)", code)
	}
}

func TestAuthzMiddlewareNoClaimsIs401(t *testing.T) {
	r := gin.New()
	r.Use(inject("", uuid.New()), AuthzMiddleware(&fakeResolver{membership: memberWith(authz.RoleOwner)}))
	r.GET("/x", RequirePermission(authz.PermPolicyRead), okHandler)
	if code := do(r); code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
}

func TestAuthzMiddlewareNoWorkspaceIs403(t *testing.T) {
	r := gin.New()
	r.Use(inject("user-1", uuid.Nil), AuthzMiddleware(&fakeResolver{membership: memberWith(authz.RoleOwner)}))
	r.GET("/x", RequirePermission(authz.PermPolicyRead), okHandler)
	if code := do(r); code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", code)
	}
}

// TestRequirePermissionNoOpWithoutAuthzMiddleware proves the gate is additive:
// when AuthzMiddleware did not run (no sentinel), RequirePermission passes
// through so a route can carry the gate before RBAC is wired everywhere.
func TestRequirePermissionNoOpWithoutAuthzMiddleware(t *testing.T) {
	r := gin.New()
	r.Use(inject("user-1", uuid.New())) // no AuthzMiddleware
	r.GET("/x", RequirePermission(authz.PermPolicyPromote), okHandler)
	if code := do(r); code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (gate no-ops without RBAC installed)", code)
	}
}

func TestRequireAnyPermissionMatchesAny(t *testing.T) {
	r := gin.New()
	// Auditor holds audit.read but not policy.promote; OR must allow.
	r.Use(inject("user-1", uuid.New()), AuthzMiddleware(&fakeResolver{membership: memberWith(authz.RoleAuditor)}))
	r.GET("/x", RequireAnyPermission(authz.PermPolicyPromote, authz.PermAuditRead), okHandler)
	if code := do(r); code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
}

func TestRequireAnyPermissionDeniesWhenNoneHeld(t *testing.T) {
	r := gin.New()
	r.Use(inject("user-1", uuid.New()), AuthzMiddleware(&fakeResolver{membership: memberWith(authz.RoleAuditor)}))
	r.GET("/x", RequireAnyPermission(authz.PermPolicyPromote, authz.PermPAMTakeover), okHandler)
	if code := do(r); code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", code)
	}
}

// TestRequireAnyPermissionEmptyDenies proves an empty disjunction denies (an
// empty OR is false) rather than accidentally allowing every caller.
func TestRequireAnyPermissionEmptyDenies(t *testing.T) {
	r := gin.New()
	r.Use(inject("user-1", uuid.New()), AuthzMiddleware(&fakeResolver{membership: memberWith(authz.RoleOwner)}))
	r.GET("/x", RequireAnyPermission(), okHandler)
	if code := do(r); code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (empty disjunction denies)", code)
	}
}

func TestRoleAndPermissionsFromContext(t *testing.T) {
	ws := uuid.New()
	r := gin.New()
	r.Use(inject("user-1", ws), AuthzMiddleware(&fakeResolver{membership: memberWith(authz.RoleSecurityAdmin)}))
	r.GET("/x", func(c *gin.Context) {
		role, ok := RoleFromContext(c)
		if !ok || role != authz.RoleSecurityAdmin {
			t.Errorf("RoleFromContext = (%q,%v), want security_admin,true", role, ok)
		}
		perms, ok := PermissionsFromContext(c)
		if !ok || !perms.Has(authz.PermPolicyPromote) {
			t.Errorf("PermissionsFromContext missing expected permission")
		}
		c.Status(http.StatusOK)
	})
	if code := do(r); code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
}

// TestContextAccessorsWithoutMiddleware confirms the accessors report "not set"
// rather than panicking when AuthzMiddleware never ran.
func TestContextAccessorsWithoutMiddleware(t *testing.T) {
	r := gin.New()
	r.GET("/x", func(c *gin.Context) {
		if _, ok := RoleFromContext(c); ok {
			t.Error("RoleFromContext ok=true without middleware")
		}
		if _, ok := PermissionsFromContext(c); ok {
			t.Error("PermissionsFromContext ok=true without middleware")
		}
		c.Status(http.StatusOK)
	})
	_ = do(r)
}
