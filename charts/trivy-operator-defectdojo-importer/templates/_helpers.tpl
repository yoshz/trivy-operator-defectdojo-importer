{{- define "trivy-operator-defectdojo-importer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "trivy-operator-defectdojo-importer.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "trivy-operator-defectdojo-importer.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "trivy-operator-defectdojo-importer.labels" -}}
helm.sh/chart: {{ include "trivy-operator-defectdojo-importer.chart" . }}
{{ include "trivy-operator-defectdojo-importer.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end -}}

{{- define "trivy-operator-defectdojo-importer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "trivy-operator-defectdojo-importer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "trivy-operator-defectdojo-importer.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{ default (include "trivy-operator-defectdojo-importer.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
{{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{- define "trivy-operator-defectdojo-importer.secretName" -}}
{{- default (include "trivy-operator-defectdojo-importer.fullname" .) .Values.defectDojo.existingSecret -}}
{{- end -}}

{{- define "trivy-operator-defectdojo-importer.secretKey" -}}
{{- if .Values.defectDojo.existingSecret -}}
{{ default "DEFECT_DOJO_API_KEY" .Values.defectDojo.existingSecretKey }}
{{- else -}}
DEFECT_DOJO_API_KEY
{{- end -}}
{{- end -}}

{{/*
Renders a list of {pattern, value} entries as a "pattern=value,pattern=value"
string, for the DEFECT_DOJO_PRODUCT_TYPE_MAP / DEFECT_DOJO_ENV_NAME_MAP env
vars. Call with the list itself as context, e.g.:
  {{ include "trivy-operator-defectdojo-importer.joinPatternValueMap" .Values.defectDojo.productTypeMap }}
*/}}
{{- define "trivy-operator-defectdojo-importer.joinPatternValueMap" -}}
{{- $pairs := list -}}
{{- range . -}}
{{- $pairs = append $pairs (printf "%s=%s" .pattern .value) -}}
{{- end -}}
{{- join "," $pairs -}}
{{- end -}}
