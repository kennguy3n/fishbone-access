package docusign

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// Regression: DocuSign's eSignature REST API reports a user's account state
// in the string field `userStatus` ("Active", "Closed", "ActivationSent",
// ...), not a boolean `active`. The previous `Status bool json:"active"`
// decoded the absent boolean to false and reported every user inactive.
// SyncIdentities must derive the status from `userStatus`.
func TestSyncIdentities_DerivesStatusFromUserStatusString(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"users":[
			{"userId":"u-active","email":"a@x.com","userStatus":"Active"},
			{"userId":"u-closed","email":"c@x.com","userStatus":"Closed"}
		]}`))
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	got := map[string]string{}
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "",
		func(batch []*access.Identity, _ string) error {
			for _, id := range batch {
				got[id.ExternalID] = id.Status
			}
			return nil
		})
	if err != nil {
		t.Fatalf("SyncIdentities: %v", err)
	}
	if got["u-active"] != "active" {
		t.Fatalf(`userStatus "Active" -> status %q; want "active"`, got["u-active"])
	}
	if got["u-closed"] != "inactive" {
		t.Fatalf(`userStatus "Closed" -> status %q; want "inactive"`, got["u-closed"])
	}
}
