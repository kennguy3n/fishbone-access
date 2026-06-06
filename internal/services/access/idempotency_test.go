package access

import (
	"net/http"
	"testing"
)

func TestIsIdempotentProvisionStatus(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"409 conflict", http.StatusConflict, "", true},
		{"422 with already-exists", http.StatusUnprocessableEntity, `{"error":"user already in team"}`, true},
		{"400 with duplicate", http.StatusBadRequest, "duplicate share for sheet", true},
		{"400 with already-subscribed", http.StatusBadRequest, `{"message":"User is already subscribed"}`, true},
		{"400 without keyword", http.StatusBadRequest, "validation failure: bad email", false},
		{"500 server error", http.StatusInternalServerError, "", false},
		{"200 success", http.StatusOK, "", false},
		{"403 forbidden", http.StatusForbidden, "forbidden", false},
	}
	for _, tc := range cases {
		got := IsIdempotentProvisionStatus(tc.status, []byte(tc.body))
		if got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestIsIdempotentRevokeStatus(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"404 not found", http.StatusNotFound, "", true},
		{"410 gone with does-not-exist", http.StatusGone, `{"error":"resource does not exist"}`, true},
		{"422 with not-a-member", http.StatusUnprocessableEntity, `not a member of team`, true},
		{"400 with no-such-record", http.StatusBadRequest, "no such record", true},
		{"400 plain validation", http.StatusBadRequest, "invalid email", false},
		{"500 server error", http.StatusInternalServerError, "not found", false},
		{"200 success", http.StatusOK, "", false},
	}
	for _, tc := range cases {
		got := IsIdempotentRevokeStatus(tc.status, []byte(tc.body))
		if got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestIsTransientStatus(t *testing.T) {
	cases := []struct {
		status int
		want   bool
	}{
		{http.StatusOK, false},
		{http.StatusBadRequest, false},
		{http.StatusForbidden, false},
		{http.StatusNotFound, false},
		{http.StatusTooManyRequests, true},
		{http.StatusInternalServerError, true},
		{http.StatusBadGateway, true},
		{http.StatusServiceUnavailable, true},
		{http.StatusGatewayTimeout, true},
	}
	for _, tc := range cases {
		got := IsTransientStatus(tc.status)
		if got != tc.want {
			t.Errorf("status %d: got %v want %v", tc.status, got, tc.want)
		}
	}
}

func TestIsIdempotentMessage(t *testing.T) {
	cases := []struct {
		name    string
		message string
		phrases []string
		want    bool
	}{
		{"empty message", "", []string{"already"}, false},
		{"empty phrases", "already subscribed", nil, false},
		{"exact lowercase", "already subscribed", []string{"already"}, true},
		{"mixed case input", "ALREADY SUBSCRIBED", []string{"already"}, true},
		{"no match", "validation error", []string{"already", "duplicate"}, false},
		{"multi-phrase any match", "user is a member", []string{"already", "is a member"}, true},
	}
	for _, tc := range cases {
		got := IsIdempotentMessage(tc.message, tc.phrases)
		if got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}
