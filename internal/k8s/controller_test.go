// SPDX-License-Identifier: GPL-3.0-or-later

package k8s

import (
	"testing"

	"github.com/yoshz/trivy-operator-defectdojo-importer/internal/config"
)

func TestNamespaceAllowed(t *testing.T) {
	cases := []struct {
		name      string
		include   []string
		exclude   []string
		namespace string
		want      bool
	}{
		{"no filters allows everything", nil, nil, "anything", true},
		{"include matches", []string{"production", "review-*"}, nil, "review-123", true},
		{"include excludes non-matching", []string{"production"}, nil, "staging", false},
		{"exclude blocks matching", nil, []string{"kube-system"}, "kube-system", false},
		{"exclude glob blocks matching", nil, []string{"kube-*"}, "kube-public", false},
		{"exclude doesn't affect others", nil, []string{"kube-system"}, "production", true},
		{"exclude wins over include", []string{"production", "review-*"}, []string{"review-*"}, "review-123", false},
		{"include and exclude both non-matching stays included", []string{"production"}, []string{"kube-system"}, "production", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctrl := &Controller{cfg: &config.Config{
				IncludeNamespaces: c.include,
				ExcludeNamespaces: c.exclude,
			}}
			if got := ctrl.namespaceAllowed(c.namespace); got != c.want {
				t.Errorf("namespaceAllowed(%q) = %v, want %v", c.namespace, got, c.want)
			}
		})
	}
}
