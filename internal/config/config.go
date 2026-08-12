// SPDX-License-Identifier: GPL-3.0-or-later

// Package config loads operator configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"strings"
)

// Config holds all runtime configuration for the operator.
type Config struct {
	// DefectDojo connection
	DefectDojoURL    string
	DefectDojoAPIKey string

	// DefectDojo import-scan behavior flags
	Active                       bool
	Verified                     bool
	CloseOldFindings             bool
	CloseOldFindingsProductScope bool
	PushToJira                   bool
	MinimumSeverity              string
	AutoCreateContext            bool
	DeduplicationOnEngagement    bool
	DoNotReactivate              bool

	// Naming templates (Go text/template syntax, evaluated per-report).
	// Available fields: .Namespace .ReportName .ReportKind .ResourceKind
	// .ResourceName
	EngagementNameTemplate string
	ServiceNameTemplate    string
	EnvNameTemplate        string
	TestTitleTemplate      string
	TagsTemplate           string

	// ProductNameLabels are checked in order against the report's resolved
	// resource labels (see internal/labelresolve - the report's immediate
	// controller, e.g. a ReplicaSet, merged with its Pod's labels, with the
	// controller's values taking precedence on key conflicts). Not
	// templated: these are label keys, matched verbatim.
	ProductNameLabels []string

	// ProductNameFallback and ProductTypeDefault are naming templates (same
	// syntax/fields as above), rendered only when ProductNameLabels /
	// ProductTypeNamespaceMap didn't resolve a value for this report.
	ProductNameFallback string
	ProductTypeDefault  string

	// ProductTypeNamespaceMap resolves the DefectDojo product type from the
	// report's namespace, e.g. production -> App Stack, testing-* -> App
	// Stack. Checked in order; the first match wins. Namespaces that match
	// nothing fall back to ProductTypeDefault.
	ProductTypeNamespaceMap []NamespaceValueMapping

	// EnvNameNamespaceMap resolves the DefectDojo environment name from the
	// report's namespace, e.g. production -> Production, testing-* ->
	// Testing. Checked in order; the first match wins. Namespaces that match
	// nothing fall back to EnvNameTemplate.
	EnvNameNamespaceMap []NamespaceValueMapping

	// Resource selection
	Reports       []string // report CRD plural names to watch, e.g. vulnerabilityreports
	ReportGroup   string
	ReportVersion string
	Label         string
	LabelValue    string

	// IncludeNamespaces/ExcludeNamespaces filter which namespaces' reports
	// are processed (exact match or path.Match glob, e.g. "testing-*").
	// IncludeNamespaces empty means all namespaces are candidates.
	// ExcludeNamespaces always wins over IncludeNamespaces when both match.
	IncludeNamespaces []string
	ExcludeNamespaces []string

	// Networking
	HTTPProxy  string
	HTTPSProxy string

	// Misc
	LogLevel    string
	MetricsAddr string
	DryRun      bool // resolve and log product type/name/naming fields, skip calling DefectDojo
}

// NamespaceValueMapping pairs a namespace match (exact or path.Match glob,
// e.g. "testing-*") with a value to use when a report's namespace matches it.
type NamespaceValueMapping struct {
	Pattern string
	Value   string
}

var allowedReports = map[string]bool{
	"configauditreports":     true,
	"vulnerabilityreports":   true,
	"exposedsecretreports":   true,
	"infraassessmentreports": true,
	"rbacassessmentreports":  true,
}

// Load reads configuration from the environment, applying the same defaults
// (where sensible) as telekom-mms/trivy-dojo-report-operator's settings.py.
func Load() (*Config, error) {
	dryRun := getBool("DRY_RUN", false)

	apiKey := os.Getenv("DEFECT_DOJO_API_KEY")
	if apiKey == "" && !dryRun {
		return nil, fmt.Errorf("DEFECT_DOJO_API_KEY environment variable is required (unless DRY_RUN=true)")
	}
	url := os.Getenv("DEFECT_DOJO_URL")
	if url == "" && !dryRun {
		return nil, fmt.Errorf("DEFECT_DOJO_URL environment variable is required (unless DRY_RUN=true)")
	}

	productTypeMap, err := parseNamespaceValueMap(getString("DEFECT_DOJO_PRODUCT_TYPE_MAP", ""))
	if err != nil {
		return nil, fmt.Errorf("parsing DEFECT_DOJO_PRODUCT_TYPE_MAP: %w", err)
	}
	envNameMap, err := parseNamespaceValueMap(getString("DEFECT_DOJO_ENV_NAME_MAP", ""))
	if err != nil {
		return nil, fmt.Errorf("parsing DEFECT_DOJO_ENV_NAME_MAP: %w", err)
	}

	cfg := &Config{
		DefectDojoURL:    strings.TrimRight(url, "/"),
		DefectDojoAPIKey: apiKey,

		Active:                       getBool("DEFECT_DOJO_ACTIVE", false),
		Verified:                     getBool("DEFECT_DOJO_VERIFIED", false),
		CloseOldFindings:             getBool("DEFECT_DOJO_CLOSE_OLD_FINDINGS", false),
		CloseOldFindingsProductScope: getBool("DEFECT_DOJO_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE", false),
		PushToJira:                   getBool("DEFECT_DOJO_PUSH_TO_JIRA", false),
		MinimumSeverity:              getString("DEFECT_DOJO_MINIMUM_SEVERITY", "Info"),
		AutoCreateContext:            getBool("DEFECT_DOJO_AUTO_CREATE_CONTEXT", false),
		DeduplicationOnEngagement:    getBool("DEFECT_DOJO_DEDUPLICATION_ON_ENGAGEMENT", false),
		DoNotReactivate:              getBool("DEFECT_DOJO_DO_NOT_REACTIVATE", false),

		EngagementNameTemplate: getString("DEFECT_DOJO_ENGAGEMENT_NAME", "{{.Namespace}}"),
		ServiceNameTemplate:    getString("DEFECT_DOJO_SERVICE_NAME", ""),
		EnvNameTemplate:        getString("DEFECT_DOJO_ENV_NAME", "Development"),
		TestTitleTemplate:      getString("DEFECT_DOJO_TEST_TITLE", "Kubernetes"),
		TagsTemplate:           getString("DEFECT_DOJO_TAGS", ""),

		ProductNameLabels:   splitCSV(getString("DEFECT_DOJO_PRODUCT_NAME_LABELS", "app.kubernetes.io/part-of,app.kubernetes.io/name,app,k8s-app")),
		ProductNameFallback: getString("DEFECT_DOJO_PRODUCT_NAME", "{{.ResourceName}}"),
		ProductTypeDefault:  getString("DEFECT_DOJO_PRODUCT_TYPE_NAME", "Research and Development"),

		ProductTypeNamespaceMap: productTypeMap,
		EnvNameNamespaceMap:     envNameMap,

		Reports:       splitCSV(getString("REPORTS", "vulnerabilityreports")),
		ReportGroup:   getString("REPORT_API_GROUP", "aquasecurity.github.io"),
		ReportVersion: getString("REPORT_API_VERSION", "v1alpha1"),
		Label:         os.Getenv("LABEL"),
		LabelValue:    os.Getenv("LABEL_VALUE"),

		IncludeNamespaces: splitCSV(getString("INCLUDE_NAMESPACES", "")),
		ExcludeNamespaces: splitCSV(getString("EXCLUDE_NAMESPACES", "")),

		HTTPProxy:  firstNonEmpty(os.Getenv("HTTP_PROXY"), os.Getenv("http_proxy")),
		HTTPSProxy: firstNonEmpty(os.Getenv("HTTPS_PROXY"), os.Getenv("https_proxy")),

		LogLevel:    strings.ToUpper(getString("LOG_LEVEL", "INFO")),
		MetricsAddr: getString("METRICS_ADDR", ":9090"),
		DryRun:      dryRun,
	}

	for _, r := range cfg.Reports {
		if !allowedReports[r] {
			keys := make([]string, 0, len(allowedReports))
			for k := range allowedReports {
				keys = append(keys, k)
			}
			return nil, fmt.Errorf("report %q is not allowed, allowed reports: %s", r, strings.Join(keys, ", "))
		}
	}

	return cfg, nil
}

func getString(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return def
}

// getBool mirrors the original operator's semantics: only the literal
// string "true" is truthy, anything else (including unset) is false.
func getBool(name string, _ bool) bool {
	return os.Getenv(name) == "true"
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseNamespaceValueMap parses a comma-separated list of pattern=value
// pairs, e.g. "production=Production,testing-*=Testing". Empty input returns
// a nil (empty) mapping.
func parseNamespaceValueMap(s string) ([]NamespaceValueMapping, error) {
	if s == "" {
		return nil, nil
	}
	var out []NamespaceValueMapping
	for _, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		pattern, value, ok := strings.Cut(entry, "=")
		if !ok || strings.TrimSpace(pattern) == "" || strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("invalid entry %q, expected pattern=value", entry)
		}
		out = append(out, NamespaceValueMapping{Pattern: strings.TrimSpace(pattern), Value: strings.TrimSpace(value)})
	}
	return out, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
