{{/*
Reusable Deployment for a headless background worker (no HTTP surface, so no
Service and no probes — these binaries are queue drainers / schedulers). Call
with a dict:
  ctx       the root context ($)
  component the component name + binary command (e.g. "access-connector-worker")
  values    the per-component values map (replicaCount, resources, nodeSelector,
            tolerations, affinity)
*/}}
{{- define "shieldnet-access.workerDeployment" -}}
{{- $ctx := .ctx -}}
{{- $component := .component -}}
{{- $values := .values -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "shieldnet-access.componentName" (dict "ctx" $ctx "component" $component) }}
  labels:
    {{- include "shieldnet-access.componentLabels" (dict "ctx" $ctx "component" $component) | nindent 4 }}
spec:
  replicas: {{ $values.replicaCount }}
  selector:
    matchLabels:
      {{- include "shieldnet-access.componentSelectorLabels" (dict "ctx" $ctx "component" $component) | nindent 6 }}
  template:
    metadata:
      annotations:
        checksum/config: {{ include (print $ctx.Template.BasePath "/configmap.yaml") $ctx | sha256sum }}
        checksum/secret: {{ include (print $ctx.Template.BasePath "/secret.yaml") $ctx | sha256sum }}
        {{- with $ctx.Values.podAnnotations }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
      labels:
        {{- include "shieldnet-access.componentSelectorLabels" (dict "ctx" $ctx "component" $component) | nindent 8 }}
        {{- with $ctx.Values.podLabels }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
    spec:
      serviceAccountName: {{ include "shieldnet-access.serviceAccountName" $ctx }}
      {{- with $ctx.Values.imagePullSecrets }}
      imagePullSecrets:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      securityContext:
        {{- toYaml $ctx.Values.podSecurityContext | nindent 8 }}
      containers:
        - name: {{ $component }}
          image: {{ include "shieldnet-access.image" $ctx | quote }}
          imagePullPolicy: {{ $ctx.Values.image.pullPolicy }}
          command: [{{ $component | quote }}]
          envFrom:
            {{- include "shieldnet-access.envFrom" $ctx | nindent 12 }}
          {{- with (include "shieldnet-access.extraEnv" $ctx) }}
          env:
            {{- . | nindent 12 }}
          {{- end }}
          resources:
            {{- toYaml $values.resources | nindent 12 }}
          securityContext:
            {{- toYaml $ctx.Values.securityContext | nindent 12 }}
          volumeMounts:
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir: {}
      {{- with $values.nodeSelector }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with $values.tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with $values.affinity }}
      affinity:
        {{- toYaml . | nindent 8 }}
      {{- end }}
{{- end -}}
