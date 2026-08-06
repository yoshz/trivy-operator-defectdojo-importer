// SPDX-License-Identifier: GPL-3.0-or-later

package mapping

import (
	"testing"

	"github.com/yoshz/trivy-operator-defectdojo-importer/internal/config"
)

func testConfig() *config.Config {
	return &config.Config{
		ProductTypeDefault:  "Research and Development",
		ProductNameFallback: "product",
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
	cases := map[string]string{
		"production":     "App Stack",
		"acceptance":     "App Stack",
		"demo":           "App Stack",
		"testing-123":    "App Stack",
		"testing-":       "App Stack",
		"staging":        "Research and Development",
		"default":        "Research and Development",
		"testingsomehow": "Research and Development",
	}
	for ns, want := range cases {
		if got := ProductType(cfg, ns); got != want {
			t.Errorf("ProductType(%q) = %q, want %q", ns, got, want)
		}
	}
}

func TestProductTypeEmptyMapFallsBackToDefault(t *testing.T) {
	cfg := &config.Config{
		ProductTypeDefault: "Research and Development",
	}
	if got := ProductType(cfg, "production"); got != "Research and Development" {
		t.Errorf("ProductType(production) with empty map = %q, want Research and Development", got)
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

	t.Run("controller label takes priority over pod label", func(t *testing.T) {
		controllerLabels := map[string]string{"app.kubernetes.io/name": "controller-app"}
		podLabels := map[string]string{"app.kubernetes.io/name": "pod-app"}
		if got := ProductName(cfg, controllerLabels, podLabels); got != "controller-app" {
			t.Errorf("ProductName = %q, want controller-app", got)
		}
	})

	t.Run("falls back to pod label when controller has none of the keys", func(t *testing.T) {
		controllerLabels := map[string]string{"unrelated": "x"}
		podLabels := map[string]string{"app.kubernetes.io/name": "pod-app"}
		if got := ProductName(cfg, controllerLabels, podLabels); got != "pod-app" {
			t.Errorf("ProductName = %q, want pod-app", got)
		}
	})

	t.Run("checks label keys in priority order: name, app", func(t *testing.T) {
		controllerLabels := map[string]string{
			"app":                    "app-value",
			"app.kubernetes.io/name": "name-value",
		}
		if got := ProductName(cfg, controllerLabels, nil); got != "name-value" {
			t.Errorf("ProductName = %q, want name-value", got)
		}
	})

	t.Run("falls back to configured default when nothing matches", func(t *testing.T) {
		if got := ProductName(cfg, nil, nil); got != "product" {
			t.Errorf("ProductName = %q, want product", got)
		}
		if got := ProductName(cfg, map[string]string{"unrelated": "x"}, map[string]string{"unrelated": "y"}); got != "product" {
			t.Errorf("ProductName = %q, want product", got)
		}
	})
}
