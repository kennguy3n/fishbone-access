package qualys

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted")
}

func validConfig() map[string]interface{} { return map[string]interface{}{"platform": "us1"} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"username": "userAAAA1234bbbbCCCC", "password": "passDDDD5678eeeeFFFF"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing creds")
	}
	if err := c.Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing platform/base_url")
	}
	if err := c.Validate(context.Background(), map[string]interface{}{"platform": "xx9"}, validSecrets()); err == nil {
		t.Error("expected error for unknown platform")
	}
	if err := c.Validate(context.Background(), map[string]interface{}{"platform": "us1", "base_url": "https://qualys.example.com"}, validSecrets()); err == nil {
		t.Error("expected error for both platform and base_url")
	}
}

func TestValidate_PureLocal(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prev })
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestRegistryIntegration(t *testing.T) {
	if got, _ := access.GetAccessConnector(ProviderName); got == nil {
		t.Fatal("not registered")
	}
}

func TestSync_PaginatesUsers(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.Header.Get("X-Requested-With"); got == "" {
			t.Errorf("expected X-Requested-With header")
		}
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Basic ") {
			t.Errorf("expected Basic auth; got %q", got)
		}
		idMin := r.URL.Query().Get("id_min")
		w.Header().Set("Content-Type", "application/xml")
		if calls == 1 {
			if idMin != "" {
				t.Errorf("first call id_min = %q; want empty", idMin)
			}
			var sb strings.Builder
			sb.WriteString(`<USER_LIST_OUTPUT><RESPONSE><USER_LIST>`)
			for i := 0; i < pageSize; i++ {
				sb.WriteString(fmt.Sprintf(`<USER><USER_ID>%d</USER_ID><USER_LOGIN>u%d</USER_LOGIN><EMAIL>u%d@x.com</EMAIL><FIRST_NAME>U</FIRST_NAME><LAST_NAME>%d</LAST_NAME><USER_STATUS>Active</USER_STATUS></USER>`, i+1, i, i, i))
			}
			sb.WriteString(`</USER_LIST></RESPONSE></USER_LIST_OUTPUT>`)
			_, _ = w.Write([]byte(sb.String()))
			return
		}
		if idMin == "" {
			t.Errorf("second call id_min = empty; want non-empty")
		}
		_, _ = w.Write([]byte(`<USER_LIST_OUTPUT><RESPONSE><USER_LIST><USER><USER_ID>999</USER_ID><USER_LOGIN>last</USER_LOGIN><EMAIL>last@x.com</EMAIL><FIRST_NAME>Last</FIRST_NAME><LAST_NAME></LAST_NAME><USER_STATUS>Disabled</USER_STATUS></USER></USER_LIST></RESPONSE></USER_LIST_OUTPUT>`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.Identity
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(got) != pageSize+1 || calls != 2 {
		t.Fatalf("got=%d calls=%d", len(got), calls)
	}
	if got[len(got)-1].Status != "disabled" {
		t.Errorf("last user status = %q; want disabled", got[len(got)-1].Status)
	}
}

func TestConnect_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("Connect err = %v; want 401", err)
	}
}

func TestGetCredentialsMetadata_RedactsToken(t *testing.T) {
	c := New()
	md, err := c.GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	u, _ := md["username_short"].(string)
	p, _ := md["password_short"].(string)
	if !strings.Contains(u, "...") || strings.Contains(u, "AAAA1234") {
		t.Errorf("username redaction failed: %q", u)
	}
	if !strings.Contains(p, "...") || strings.Contains(p, "DDDD5678") {
		t.Errorf("password redaction failed: %q", p)
	}
}

func TestValidate_RejectsBadBaseURL(t *testing.T) {
	c := New()
	bad := map[string]string{
		"http scheme":    "http://qualys.example.com",
		"ip literal":     "https://10.0.0.1",
		"v6 ip literal":  "https://[::1]",
		"with userinfo":  "https://attacker@qualys.example.com",
		"with path":      "https://qualys.example.com/internal",
		"with query":     "https://qualys.example.com?x=1",
		"with fragment":  "https://qualys.example.com#frag",
		"hyphen leading": "https://-qualys.example.com",
		"underscore":     "https://bad_label.example.com",
		"empty host":     "https://",
		"unparseable":    "https://%zz",
	}
	for name, ep := range bad {
		t.Run(name, func(t *testing.T) {
			err := c.Validate(context.Background(), map[string]interface{}{"base_url": ep}, validSecrets())
			if err == nil {
				t.Errorf("expected error for base_url %q", ep)
			}
		})
	}
}
