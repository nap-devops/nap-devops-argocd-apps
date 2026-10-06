{{/*
Shared env vars for the app-backup.rb / app-restore.rb CronJobs — defined
once here so backup-cronjob.yaml and restore-cronjob.yaml stay in sync.
Same pattern as the WordPress sites' _helpers.tpl (see web-sandbox etc.).
*/}}
{{- define "backupRestore.env" -}}
- name: DB_TYPE
  value: "{{ .Values.backupRestore.db.type }}"
- name: DB_NAMESPACE
  value: "{{ .Values.backupRestore.db.namespace }}"
- name: DB_POD_NAME
  value: "{{ .Values.backupRestore.db.podName | default "" }}"
- name: DB_POD_LABEL
  value: "{{ .Values.backupRestore.db.podLabel | default "" }}"
- name: APP_NAMESPACE
  value: "{{ .Values.backupRestore.app.namespace }}"
- name: APP_POD_KEYWORD
  value: "{{ .Values.backupRestore.app.podKeyword | default "" }}"
- name: APP_POD_LABEL
  value: "{{ .Values.backupRestore.app.podLabel | default "" }}"
- name: APP_DATA_PATH
  value: "{{ .Values.backupRestore.app.dataPath }}"
- name: S3_STORAGE_URL
  value: "{{ .Values.backupRestore.storage.url }}"
- name: S3_BUCKET
  value: "{{ .Values.backupRestore.storage.bucket }}"
- name: S3_BUCKET_PATH
  value: "{{ .Values.backupRestore.storage.bucketPath }}"
- name: FILE_PREFIX
  value: "{{ .Values.backupRestore.storage.filePrefix }}"
- name: S3_TRANSFER_TIMEOUT_SEC
  value: "{{ .Values.backupRestore.s3TransferTimeoutSec | default 1800 }}"
- name: S3_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.backupRestore.namePrefix }}-backup-credentials
      key: S3_KEY
- name: S3_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ .Values.backupRestore.namePrefix }}-backup-credentials
      key: S3_SECRET
- name: DISCORD_WEBHOOK
  valueFrom:
    secretKeyRef:
      name: {{ .Values.backupRestore.namePrefix }}-backup-credentials
      key: DISCORD_WEBHOOK
{{- end -}}
