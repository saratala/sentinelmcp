{{/*
Expand the name of the chart.
*/}}
{{- define "sentinelmcp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sentinelmcp.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "sentinelmcp.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sentinelmcp.labels" -}}
helm.sh/chart: {{ include "sentinelmcp.chart" . }}
{{ include "sentinelmcp.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "sentinelmcp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sentinelmcp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "sentinelmcp.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "sentinelmcp.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Redis URL — internal or external */}}
{{- define "sentinelmcp.redisUrl" -}}
{{- if .Values.redis.enabled }}
{{- printf "redis://%s-redis:6379/0" (include "sentinelmcp.fullname" .) }}
{{- else }}
{{- .Values.externalRedis.url }}
{{- end }}
{{- end }}

{{/* Postgres URL — internal or external */}}
{{- define "sentinelmcp.postgresUrl" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "postgresql+asyncpg://%s:%s@%s-postgresql:5432/%s" .Values.postgresql.auth.username .Values.postgresql.auth.password (include "sentinelmcp.fullname" .) .Values.postgresql.auth.database }}
{{- else }}
{{- .Values.externalPostgresql.url }}
{{- end }}
{{- end }}
