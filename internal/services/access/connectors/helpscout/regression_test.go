package helpscout

import (
	"encoding/json"
	"testing"
)

// Regression: mapHelpscoutActivity must return nil when the timestamp
// is empty or unparseable, preventing zero-time audit entries.

func TestMapHelpscoutActivity_ZeroTimeReturnsNil(t *testing.T) {
	for _, tc := range []struct {
		name      string
		timestamp string
		wantNil   bool
	}{
		{"empty", "", true},
		{"garbage", "not-a-date", true},
		{"valid_rfc3339", "2024-06-01T11:00:00Z", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := &helpscoutActivity{
				ID:        json.Number("42"),
				Type:      "user",
				Action:    "login",
				Timestamp: tc.timestamp,
			}
			got := mapHelpscoutActivity(entry)
			if tc.wantNil && got != nil {
				t.Errorf("expected nil for Timestamp=%q, got %+v", tc.timestamp, got)
			}
			if !tc.wantNil && got == nil {
				t.Errorf("expected non-nil for Timestamp=%q", tc.timestamp)
			}
		})
	}
}
