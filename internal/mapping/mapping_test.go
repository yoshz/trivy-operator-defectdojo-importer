// SPDX-License-Identifier: GPL-3.0-or-later

package mapping

import (
	"testing"

	"github.com/yoshz/trivy-operator-defectdojo-importer/internal/config"
)

func testConfig() *config.Config {
	return &config.Config{
		ProductTypeDefault:  "Research and Development",
		ProductNameFallback: "{{.ResourceName}}",
		ProductNameLabels:   []string{"app.kubernetes.io/name", "app"},
		ProductTypeNamespaceMap: []config.NamespaceValueMapping{
			{Pattern: "production", Value: "App Stack"},
			{Pattern: "acceptance", Value: "App Stack"},
			{Pattern: "demo", Value: "App Stack"},
			{Pattern: "testing-*", Value: "App Stack"},
		},
		EnvNameNamespaceMap: []config.NamespaceValueMapping{
			{Pattern: "production", Value: "Production"},
			{Pattern: "acceptance", Value: "Acceptance"},
			{Pattern: "testing-*", Value: "Testing"},
		},
	}
}

func TestProductType(t *testing.T) {
	cfg := testConfig()
	matching := map[string]string{
		"production":  "App Stack",
		"acceptance":  "App Stack",
		"demo":        "App Stack",
		"testing-123": "App Stack",
		"testing-":    "App Stack",
	}
	for ns, want := range matching {
		got, ok := ProductType(cfg, ns)
		if !ok {
			t.Errorf("ProductType(%q) matched nothing, want %q", ns, want)
			continue
		}
		if got != want {
			t.Errorf("ProductType(%q) = %q, want %q", ns, got, want)
		}
	}

	nonMatching := []string{"staging", "default", "testingsomehow"}
	for _, ns := range nonMatching {
		if _, ok := ProductType(cfg, ns); ok {
			t.Errorf("ProductType(%q) matched, want no match (caller renders ProductTypeDefault)", ns)
		}
	}
}

func TestProductTypeEmptyMapReturnsNoMatch(t *testing.T) {
	cfg := &config.Config{
		ProductTypeDefault: "Research and Development",
	}
	if _, ok := ProductType(cfg, "production"); ok {
		t.Error("ProductType with empty map matched, want no match")
	}
}

func TestEnvironment(t *testing.T) {
	cfg := testConfig()
	cases := map[string]string{
		"production":  "Production",
		"acceptance":  "Acceptance",
		"testing-123": "Testing",
		"testing-":    "Testing",
	}
	for ns, want := range cases {
		got, ok := Environment(cfg, ns)
		if !ok {
			t.Errorf("Environment(%q) matched nothing, want %q", ns, want)
			continue
		}
		if got != want {
			t.Errorf("Environment(%q) = %q, want %q", ns, got, want)
		}
	}

	if _, ok := Environment(cfg, "demo"); ok {
		t.Errorf("Environment(demo) matched, want no match (falls back to template)")
	}
}

func TestProductName(t *testing.T) {
	cfg := testConfig()

	t.Run("checks label keys in priority order: name, app", func(t *testing.T) {
		labels := map[string]string{
			"app":                    "app-value",
			"app.kubernetes.io/name": "name-value",
		}
		got, ok := ProductName(cfg, labels)
		if !ok {
			t.Fatal("ProductName matched nothing, want name-value")
		}
		if got != "name-value" {
			t.Errorf("ProductName = %q, want name-value", got)
		}
	})

	t.Run("returns no match when nothing matches", func(t *testing.T) {
		if _, ok := ProductName(cfg, nil); ok {
			t.Error("ProductName matched, want no match (caller renders ProductNameFallback)")
		}
		unrelated := map[string]string{"unrelated": "x"}
		if _, ok := ProductName(cfg, unrelated); ok {
			t.Error("ProductName matched, want no match (caller renders ProductNameFallback)")
		}
	})
}
