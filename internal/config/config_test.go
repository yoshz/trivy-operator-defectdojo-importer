// SPDX-License-Identifier: GPL-3.0-or-later

package config

import "testing"

func TestValidateNamespaceTemplate(t *testing.T) {
	cases := []struct {
		name    string
		tmpl    string
		wantErr bool
	}{
		{"namespace only", "{{.Namespace}}", false},
		{"namespace with static text", "k8s-{{.Namespace}}", false},
		{"static string", "Kubernetes", true},
		{"depends on product name", "{{.Namespace}}/{{.ProductName}}", true},
		{"depends on resource name only", "{{.ResourceName}}", true},
		{"invalid template", "{{.Namespace", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateNamespaceTemplate(c.tmpl)
			if (err != nil) != c.wantErr {
				t.Errorf("validateNamespaceTemplate(%q) error = %v, wantErr %v", c.tmpl, err, c.wantErr)
			}
		})
	}
}

func TestLoadRejectsDeleteRemovedNamespacesWithoutNamespaceTemplate(t *testing.T) {
	t.Setenv("DRY_RUN", "true")
	t.Setenv("DEFECT_DOJO_DELETE_REMOVED_NAMESPACES", "true")
	t.Setenv("DEFECT_DOJO_ENGAGEMENT_NAME", "Kubernetes")
	if _, err := Load(); err == nil {
		t.Fatal("Load() succeeded, want error for an engagement name not derived from the namespace")
	}

	t.Setenv("DEFECT_DOJO_ENGAGEMENT_NAME", "{{.Namespace}}")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.DeleteRemovedNamespaces {
		t.Error("DeleteRemovedNamespaces = false, want true")
	}
}
