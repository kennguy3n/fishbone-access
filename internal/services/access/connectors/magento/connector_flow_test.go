package magento

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func magentoFlowConfig() map[string]interface{} {
	return map[string]interface{}{"endpoint": "https://magento.example.com"}
}
func magentoFlowSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "tok_AAAA1234bbbbCCCC"}
}

func TestMagentoConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "555"
	const userEmail = "alice@example.com"
	const groupID = "3"

	var mu sync.Mutex
	state := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Errorf("authorization header missing")
		}
		customers := "/rest/V1/customers"
		userPath := customers + "/" + userID
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == customers:
			if state != "" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"message":"A customer with the same email already exists"}`))
				return
			}
			// Validate the create body the way the real Magento API would:
			// the group must arrive as snake_case "group_id" and email /
			// firstname / lastname are mandatory.
			var reqBody struct {
				Customer struct {
					Email     string      `json:"email"`
					Firstname string      `json:"firstname"`
					Lastname  string      `json:"lastname"`
					GroupID   json.Number `json:"group_id"`
				} `json:"customer"`
			}
			raw, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(raw, &reqBody); err != nil {
				t.Errorf("decode provision body: %v (%s)", err, raw)
			}
			if strings.Contains(string(raw), "groupId") {
				t.Errorf("provision body uses camelCase groupId, want snake_case group_id: %s", raw)
			}
			if reqBody.Customer.GroupID.String() != groupID {
				t.Errorf("group_id = %q, want %q (body=%s)", reqBody.Customer.GroupID.String(), groupID, raw)
			}
			if reqBody.Customer.Email == "" || reqBody.Customer.Firstname == "" || reqBody.Customer.Lastname == "" {
				t.Errorf("missing required customer fields: %s", raw)
			}
			state = groupID
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":` + userID + `,"email":"` + userEmail + `","group_id":` + groupID + `}`))
		case r.Method == http.MethodDelete && r.URL.Path == userPath:
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			state = ""
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`true`))
		case r.Method == http.MethodGet && r.URL.Path == userPath:
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"id":` + userID + `,"email":"` + userEmail + `","group_id":` + state + `}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := magentoFlowConfig()
	secrets := magentoFlowSecrets()
	grant := access.AccessGrant{
		UserExternalID:     userID,
		ResourceExternalID: groupID,
		Scope: map[string]interface{}{
			"email":     userEmail,
			"firstname": "Alice",
			"lastname":  "Smith",
		},
	}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, userID)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != groupID || ents[0].Source != "direct" {
		t.Fatalf("ents = %#v, want 1 with group=%s source=direct", ents, groupID)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, userID)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
	}
}

func TestMagentoConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		magentoFlowConfig(), magentoFlowSecrets(),
		access.AccessGrant{
			UserExternalID:     "alice@example.com",
			ResourceExternalID: "1",
			Scope: map[string]interface{}{
				"firstname": "Alice",
				"lastname":  "Smith",
			},
		})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}

// TestMagentoProvision_RequiresCustomerFields verifies the connector fails
// loud (before issuing any HTTP request) when the data Magento requires to
// create a customer — a valid email plus firstname/lastname — is missing,
// rather than POSTing an incomplete body the real API would reject with a 400.
func TestMagentoProvision_RequiresCustomerFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s; provision should fail before calling the API", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	cases := []struct {
		name  string
		grant access.AccessGrant
		want  string
	}{
		{
			name:  "non-email id without scope email",
			grant: access.AccessGrant{UserExternalID: "555", ResourceExternalID: "3", Scope: map[string]interface{}{"firstname": "Alice", "lastname": "Smith"}},
			want:  "email is required",
		},
		{
			name:  "email but missing names",
			grant: access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "3"},
			want:  "firstname and lastname are required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := c.ProvisionAccess(context.Background(), magentoFlowConfig(), magentoFlowSecrets(), tc.grant)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}
