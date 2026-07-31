{{/*
Expand the name of the chart.
*/}}
{{- define "cnsl.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "cnsl.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart name and version label.
*/}}
{{- define "cnsl.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "cnsl.labels" -}}
helm.sh/chart: {{ include "cnsl.chart" . }}
{{ include "cnsl.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "cnsl.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cnsl.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service account name.
*/}}
{{- define "cnsl.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "cnsl.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Secret name (existing or chart-managed).
*/}}
{{- define "cnsl.secretName" -}}
{{- printf "%s-secrets" (include "cnsl.fullname" .) }}
{{- end }}

{{/*
Redis fullname (bundled Redis, when enabled).
*/}}
{{- define "cnsl.redis.fullname" -}}
{{- printf "%s-redis" (include "cnsl.fullname" .) }}
{{- end }}
