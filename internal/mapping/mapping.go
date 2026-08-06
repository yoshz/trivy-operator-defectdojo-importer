// SPDX-License-Identifier: GPL-3.0-or-later

// Package mapping implements the product type / product name / environment
// business rules that differ from telekom-mms/trivy-dojo-report-operator:
//
//   - Product type is resolved from the report's namespace via
//     ProductTypeNamespaceMap, e.g. production -> App Stack, testing-* ->
//     App Stack. Namespaces matching nothing fall back to ProductTypeDefault.
//   - Product name is the first of ProductNameLabels found on the report's
//     immediate controller (e.g. its ReplicaSet), falling back to the Pod
//     itself if the controller doesn't carry any of them.
//   - Environment is resolved from the report's namespace via
//     EnvNameNamespaceMap, e.g. production -> Production, testing-* ->
//     Testing.
package mapping

import (
	"github.com/yoshz/trivy-operator-defectdojo-importer/internal/config"
	"github.com/yoshz/trivy-operator-defectdojo-importer/internal/nsmatch"
)

// ProductType returns the DefectDojo product type name for a report found in
// the given namespace, per cfg.ProductTypeNamespaceMap (checked in order,
// first match wins). Namespaces matching nothing get cfg.ProductTypeDefault.
func ProductType(cfg *config.Config, namespace string) string {
	if v, ok := matchNamespaceMap(cfg.ProductTypeNamespaceMap, namespace); ok {
		return v
	}
	return cfg.ProductTypeDefault
}

// Environment returns the DefectDojo environment name for a report found in
// the given namespace, per cfg.EnvNameNamespaceMap (checked in order, first
// match wins). The second return value is false when no entry matched, so
// the caller can fall back to its own default.
func Environment(cfg *config.Config, namespace string) (string, bool) {
	return matchNamespaceMap(cfg.EnvNameNamespaceMap, namespace)
}

// matchNamespaceMap returns the value of the first entry in m whose pattern
// matches namespace, and whether any entry matched.
func matchNamespaceMap(m []config.NamespaceValueMapping, namespace string) (string, bool) {
	for _, entry := range m {
		if nsmatch.Match(entry.Pattern, namespace) {
			return entry.Value, true
		}
	}
	return "", false
}

// ProductName returns the DefectDojo product name for a report. It checks
// cfg.ProductNameLabels, in order, against controllerLabels first (the
// report's immediate controller, e.g. a ReplicaSet - or the Pod itself when
// the report references a Pod directly); only if none of them are found
// there does it fall back to checking the same keys, in order, against
// podLabels. If nothing matches in either map, cfg.ProductNameFallback is
// used. Either map may be nil.
func ProductName(cfg *config.Config, controllerLabels, podLabels map[string]string) string {
	for _, key := range cfg.ProductNameLabels {
		if v := controllerLabels[key]; v != "" {
			return v
		}
	}
	for _, key := range cfg.ProductNameLabels {
		if v := podLabels[key]; v != "" {
			return v
		}
	}
	return cfg.ProductNameFallback
}
