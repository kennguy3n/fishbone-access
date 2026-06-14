{{/*
Helper templates for the shieldnet-access chart. Names follow the standard
Helm conventions so labels, selectors, and resource names stay consistent
across every component (ztna-api, pam-gateway, and the workers).
*/}}

{{/* Base name, overridable via nameOverride; truncated to the 63-char DNS limit. */}}
{{- define "shieldnet-access.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully-qualified app name. If fullnameOverride is set it wins; otherwise it is
release-name + chart-name, de-duplicated when the release name already contains
the chart name.
*/}}
{{- define "shieldnet-access.fullname" -}}
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

{{/* Chart name + version, sanitised for the helm.sh/chart label. */}}
{{- define "shieldnet-access.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Common labels applied to every object. */}}
{{- define "shieldnet-access.labels" -}}
helm.sh/chart: {{ include "shieldnet-access.chart" . }}
{{ include "shieldnet-access.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: shieldnet-access
{{- end -}}

{{/* Selector labels shared by all components (NOT including the component). */}}
{{- define "shieldnet-access.selectorLabels" -}}
app.kubernetes.io/name: {{ include "shieldnet-access.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Per-component labels. Call with a dict: (dict "ctx" $ "component" "ztna-api").
Adds the component selector label on top of the common label set.
*/}}
{{- define "shieldnet-access.componentLabels" -}}
{{ include "shieldnet-access.labels" .ctx }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* Per-component selector labels (used in Deployment/Service selectors). */}}
{{- define "shieldnet-access.componentSelectorLabels" -}}
{{ include "shieldnet-access.selectorLabels" .ctx }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* Per-component resource name, e.g. <release>-shieldnet-access-ztna-api. */}}
{{- define "shieldnet-access.componentName" -}}
{{- printf "%s-%s" (include "shieldnet-access.fullname" .ctx) .component | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* ServiceAccount name to use. */}}
{{- define "shieldnet-access.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "shieldnet-access.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Name of the Secret the workloads pull env from. If secrets.existingSecret is
set the chart creates no Secret and references the operator-managed one;
otherwise it is the chart-managed Secret.
*/}}
{{- define "shieldnet-access.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "shieldnet-access.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Name of the non-secret ConfigMap. */}}
{{- define "shieldnet-access.configMapName" -}}
{{- printf "%s-config" (include "shieldnet-access.fullname" .) -}}
{{- end -}}

{{/* Name of the bundled (dev-only) Postgres StatefulSet/Service. */}}
{{- define "shieldnet-access.postgresName" -}}
{{- printf "%s-postgres" (include "shieldnet-access.fullname" .) -}}
{{- end -}}

{{/* Fully-resolved image reference (repository:tag), tag defaulting to appVersion. */}}
{{- define "shieldnet-access.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/*
envFrom block shared by every workload: the non-secret ConfigMap plus the
Secret (chart-managed or operator-managed via existingSecret). Call with $.
*/}}
{{- define "shieldnet-access.envFrom" -}}
- configMapRef:
    name: {{ include "shieldnet-access.configMapName" . }}
- secretRef:
    name: {{ include "shieldnet-access.secretName" . }}
{{- end -}}

{{/* Extra raw env vars (global values.extraEnv). Call with $. */}}
{{- define "shieldnet-access.extraEnv" -}}
{{- with .Values.extraEnv }}
{{- toYaml . }}
{{- end }}
{{- end -}}
