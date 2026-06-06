package docusign

import "testing"

// Regression: a request-log row whose CreatedDate is present but unparseable
// must be skipped rather than emitted with a zero Timestamp. A zero Timestamp
// becomes the watermark cursor and forces an infinite re-fetch of the same
// window on the next sync.
func TestMapDocuSignRequestLog_SkipsZeroTimestamp(t *testing.T) {
	if got := mapDocuSignRequestLog(&docusignRequestLog{RequestLogID: "log-x", CreatedDate: "not-a-date", Method: "POST"}); got != nil {
		t.Fatalf("mapDocuSignRequestLog(bad date) = %+v; want nil", got)
	}
	if got := mapDocuSignRequestLog(&docusignRequestLog{RequestLogID: "log-y", CreatedDate: "2024-04-01T08:00:00Z", Method: "POST"}); got == nil {
		t.Fatal("valid request log unexpectedly skipped")
	}
}
