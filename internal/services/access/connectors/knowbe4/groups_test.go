package knowbe4

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func knowbe4GroupsConfig() map[string]interface{} { return map[string]interface{}{"region": "us"} }
func knowbe4GroupsSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "kb4-token"}
}

func TestKnowBe4_SyncGroups_HappyPath_TwoPages(t *testing.T) {
	pageOne := strings.Repeat(`{"id":1,"name":"All","status":"active"},`, pageSize)
	pageOne = "[" + strings.TrimRight(pageOne, ",") + "]"
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/groups") {
			t.Errorf("path=%q; want /v1/groups prefix", r.URL.Path)
		}
		hits++
		switch hits {
		case 1:
			_, _ = w.Write([]byte(pageOne))
		case 2:
			_, _ = w.Write([]byte(`[{"id":2,"name":"Engineering","status":"active"}]`))
		default:
			t.Errorf("unexpected page %d", hits)
		}
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	var got []*access.Identity
	if err := c.SyncGroups(context.Background(), knowbe4GroupsConfig(), knowbe4GroupsSecrets(), "",
		func(batch []*access.Identity, _ string) error {
			got = append(got, batch...)
			return nil
		}); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if len(got) != pageSize+1 {
		t.Errorf("got %d groups; want %d", len(got), pageSize+1)
	}
	if got[0].Type != access.IdentityTypeGroup {
		t.Errorf("type = %s; want group", got[0].Type)
	}
	if got[pageSize].ExternalID != "2" {
		t.Errorf("last id = %q; want 2", got[pageSize].ExternalID)
	}
}

func TestKnowBe4_SyncGroupMembers_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/groups/42/members") {
			t.Errorf("path=%q; want /v1/groups/42/members prefix", r.URL.Path)
		}
		_, _ = w.Write([]byte(`[{"id":100,"email":"a@x"},{"id":200,"email":"b@x"}]`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	var ids []string
	if err := c.SyncGroupMembers(context.Background(), knowbe4GroupsConfig(), knowbe4GroupsSecrets(), "42", "",
		func(batch []string, _ string) error {
			ids = append(ids, batch...)
			return nil
		}); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	if fmt.Sprintf("%v", ids) != "[100 200]" {
		t.Errorf("ids = %v; want [100 200]", ids)
	}
}

func TestKnowBe4_CountGroups_WalksPages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":1,"name":"G","status":"active"}]`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	n, err := c.CountGroups(context.Background(), knowbe4GroupsConfig(), knowbe4GroupsSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if n != 1 {
		t.Errorf("count = %d; want 1", n)
	}
}

func TestKnowBe4_SyncGroups_ServerErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	err := c.SyncGroups(context.Background(), knowbe4GroupsConfig(), knowbe4GroupsSecrets(), "",
		func(_ []*access.Identity, _ string) error { return nil })
	if err == nil {
		t.Error("err = nil; want non-nil for 500")
	}
}

func TestKnowBe4_SyncGroupMembers_MissingGroupID(t *testing.T) {
	c := New()
	err := c.SyncGroupMembers(context.Background(), knowbe4GroupsConfig(), knowbe4GroupsSecrets(), "", "",
		func(_ []string, _ string) error { return nil })
	if err == nil {
		t.Error("err = nil; want non-nil for empty group id")
	}
}

func TestKnowBe4_SatisfiesGroupSyncerInterface(_ *testing.T) {
	var _ access.GroupSyncer = New()
}
