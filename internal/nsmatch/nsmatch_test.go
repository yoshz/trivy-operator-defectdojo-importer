// SPDX-License-Identifier: GPL-3.0-or-later

package nsmatch

import "testing"

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern, namespace string
		want               bool
	}{
		{"production", "production", true},
		{"Production", "production", true}, // case-insensitive exact match
		{"production", "staging", false},
		{"review-*", "review-123", true},
		{"review-*", "review-", true},
		{"review-*", "reviewsomehow", false},
		{"review-*", "staging", false},
	}
	for _, c := range cases {
		if got := Match(c.pattern, c.namespace); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.namespace, got, c.want)
		}
	}
}

func TestMatchAny(t *testing.T) {
	patterns := []string{"production", "acceptance", "review-*"}
	cases := map[string]bool{
		"production": true,
		"acceptance": true,
		"review-123": true,
		"staging":    false,
		"default":    false,
	}
	for ns, want := range cases {
		if got := MatchAny(patterns, ns); got != want {
			t.Errorf("MatchAny(%v, %q) = %v, want %v", patterns, ns, got, want)
		}
	}

	if MatchAny(nil, "anything") {
		t.Error("MatchAny(nil, ...) should be false")
	}
}
