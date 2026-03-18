package envutil

import "testing"

func TestResolveOptionalPrefersFlagValue(t *testing.T) {
	t.Setenv("TEST_OPTIONAL_SECRET", "from-env")

	got := ResolveOptional("  from-flag  ", "TEST_OPTIONAL_SECRET")
	if got != "from-flag" {
		t.Fatalf("ResolveOptional() = %q, want %q", got, "from-flag")
	}
}

func TestResolveOptionalFallsBackToEnv(t *testing.T) {
	t.Setenv("TEST_OPTIONAL_SECRET", "  from-env  ")

	got := ResolveOptional("", "TEST_OPTIONAL_SECRET")
	if got != "from-env" {
		t.Fatalf("ResolveOptional() = %q, want %q", got, "from-env")
	}
}

func TestResolveOptionalReturnsEmptyWhenUnset(t *testing.T) {
	got := ResolveOptional("", "MISSING_OPTIONAL_SECRET")
	if got != "" {
		t.Fatalf("ResolveOptional() = %q, want empty", got)
	}
}
