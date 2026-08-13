// SPDX-License-Identifier: GPL-3.0-or-later

// Package naming renders the configurable, templated DefectDojo naming
// fields (engagement name, service, environment, test title, tags).
//
// Fields are plain strings by default (e.g. "Development") but may contain
// Go text/template syntax to derive values from the report being processed,
// e.g. "{{.Namespace}}" or "{{.ResourceKind}}/{{.ResourceName}}". This plays
// the same role as the upstream operator's DEFECT_DOJO_EVAL_* + eval()
// mechanism, without shelling out to an interpreter.
package naming

import (
	"bytes"
	"text/template"
)

// Context is the data made available to naming templates.
type Context struct {
	Namespace    string
	ReportName   string
	ReportKind   string
	ResourceKind string
	ResourceName string
	ProductName  string
}

// Render evaluates tmplStr as a Go template against ctx. Strings without
// template syntax are returned unchanged.
func Render(tmplStr string, ctx Context) (string, error) {
	if tmplStr == "" {
		return "", nil
	}
	t, err := template.New("naming").Parse(tmplStr)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, ctx); err != nil {
		return "", err
	}
	return buf.String(), nil
}
