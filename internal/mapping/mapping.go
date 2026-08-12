// SPDX-License-Identifier: GPL-3.0-or-later

// Package mapping implements the product type / product name / environment
// business rules that differ from telekom-mms/trivy-dojo-report-operator:
//
//   - Product type is resolved from the report's namespace via
//     ProductTypeNamespaceMap, e.g. production -> App Stack, testing-* ->
//     App Stack. Namespaces matching nothing fall back to ProductTypeDefault,
//     a naming template rendered by the caller.
//   - Product name is the first of ProductNameLabels found in the report's
//     resolved labels (see internal/labelresolve - the report's immediate
//     controller, e.g. its ReplicaSet, merged with its Pod's labels, with
//     the controller's values taking precedence on key conflicts). If
//     nothing is found, it falls back to ProductNameFallback, a naming
//     template rendered by the caller.
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
// first match wins). The second return value is false when no entry
// matched, in which case the caller should render cfg.ProductTypeDefault as
// a naming template.
func ProductType(cfg *config.Config, namespace string) (string, bool) {
	return matchNamespaceMap(cfg.ProductTypeNamespaceMap, namespace)
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

// ProductName returns the DefectDojo product name for a report: the value of
// the first of cfg.ProductNameLabels found in labels. labels may be nil. The
// second return value is false when none of them matched, in which case the
// caller should render cfg.ProductNameFallback as a naming template.
func ProductName(cfg *config.Config, labels map[string]string) (string, bool) {
	for _, key := range cfg.ProductNameLabels {
		if v := labels[key]; v != "" {
			return v, true
		}
	}
	return "", false
}
