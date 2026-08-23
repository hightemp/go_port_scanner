package portscanner

import (
	"regexp"
	"testing"
)

func TestVersion(t *testing.T) {
	t.Parallel()

	validVersion := regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z]+)*$`)
	if version := Version(); !validVersion.MatchString(version) {
		t.Errorf("Version() = %q, want semantic version from VERSION", version)
	}
}
