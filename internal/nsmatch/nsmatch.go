// SPDX-License-Identifier: GPL-3.0-or-later

// Package nsmatch matches Kubernetes namespace names against patterns -
// either an exact (case-insensitive) name or a path.Match glob, e.g.
// "testing-*". Shared by the product/environment namespace maps and the
// report watcher's include/exclude namespace filtering.
package nsmatch

import (
	"path"
	"strings"
)

// Match reports whether namespace matches pattern.
func Match(pattern, namespace string) bool {
	if strings.EqualFold(pattern, namespace) {
		return true
	}
	ok, _ := path.Match(pattern, namespace)
	return ok
}

// MatchAny reports whether namespace matches any entry in patterns.
func MatchAny(patterns []string, namespace string) bool {
	for _, p := range patterns {
		if Match(p, namespace) {
			return true
		}
	}
	return false
}
