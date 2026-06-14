// This test lives in package access (not access_test) so it can exercise the
// unexported advisory field-format patterns directly. The patterns are UI hints
// only — the connector Validate is authoritative — but they must not flag values
// the connector itself accepts (a false "wrong format" hint on a valid value is
// a real UX bug, e.g. AWS GovCloud regions like us-gov-east-1).
package access

import (
	"regexp"
	"testing"
)

func TestAWSRegionPatternAcceptsValidRegions(t *testing.T) {
	re := regexp.MustCompile(awsRegionPattern)
	valid := []string{
		"us-east-1", "us-west-2", "eu-west-1", "ap-southeast-2",
		"ca-central-1", "us-gov-east-1", "us-gov-west-1", "cn-north-1",
	}
	for _, r := range valid {
		if !re.MatchString(r) {
			t.Errorf("awsRegionPattern should accept valid region %q", r)
		}
	}
	invalid := []string{"useast1", "US-EAST-1", "us-east", "us_east_1", ""}
	for _, r := range invalid {
		if re.MatchString(r) {
			t.Errorf("awsRegionPattern should reject %q", r)
		}
	}
}

func TestUUIDPatternMatchesSampleIDs(t *testing.T) {
	re := regexp.MustCompile(uuidPattern)
	if !re.MatchString("11111111-1111-1111-1111-111111111111") {
		t.Error("uuidPattern should accept a canonical UUID")
	}
	if re.MatchString("not-a-uuid") {
		t.Error("uuidPattern should reject a non-UUID")
	}
}
