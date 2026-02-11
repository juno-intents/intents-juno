package main

import "testing"

func TestMultiValueFlag_SetRejectsBlank(t *testing.T) {
	t.Parallel()

	var f multiValueFlag
	if err := f.Set(" "); err == nil {
		t.Fatalf("expected blank value rejection")
	}
}

func TestMultiValueFlag_ValuesReturnsCopy(t *testing.T) {
	t.Parallel()

	var f multiValueFlag
	if err := f.Set("--foo"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := f.Set("bar"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	values := f.Values()
	if len(values) != 2 {
		t.Fatalf("values length: got %d want 2", len(values))
	}
	values[0] = "mutated"

	fresh := f.Values()
	if fresh[0] != "--foo" {
		t.Fatalf("Values must return copy, got %q", fresh[0])
	}
}
