# trivy-operator-defectdojo-importer

A small Kubernetes controller that watches [trivy-operator](https://github.com/aquasecurity/trivy-operator)
report CRDs and forwards them to [DefectDojo](https://github.com/DefectDojo/django-DefectDojo)'s
`reimport-scan` API, similar in spirit to
[telekom-mms/trivy-dojo-report-operator](https://github.com/telekom-mms/trivy-dojo-report-operator),
but written in Go and with fixed naming rules instead of static/eval'd config:

- **Product type** is resolved from the report's namespace via
  `DEFECT_DOJO_PRODUCT_TYPE_MAP`, e.g. mapping `production`/`testing-*` to
  `Webapp`. Empty by default; any namespace matching nothing (or when the
  map is unset) falls back to `DEFECT_DOJO_PRODUCT_TYPE_NAME` (a naming
  template, `Research and Development` by default).
- **Product name** is the value of the first matching label in
  `DEFECT_DOJO_PRODUCT_NAME_LABELS` (`app.kubernetes.io/name`,
  `app` by default) - checked first on the report's *immediate controller*
  (e.g. its ReplicaSet), and only if none of them are found there, on the
  Kubernetes **Pod** itself. If nothing can be resolved, `DEFECT_DOJO_PRODUCT_NAME`
  (a naming template, `{{.ResourceName}}` by default - i.e. the underlying
  Kubernetes resource's name) is used instead.
- **Environment** is resolved from the report's namespace via
  `DEFECT_DOJO_ENV_NAME_MAP`, e.g. mapping `production` to `Production` and
  `testing-*` to `Testing`. Empty by default; falls back to
  `DEFECT_DOJO_ENV_NAME` (`Development` by default) the same way product type
  does.

Both namespace maps use the same syntax: a comma-separated list of
`pattern=Value` pairs, where `pattern` is either an exact namespace name or a
glob (`path.Match` syntax, e.g. `testing-*`), checked in order with the first
match winning.

## How pod resolution works

trivy-operator stamps every report with labels identifying the resource it
scanned:

```
trivy-operator.resource.kind: ReplicaSet
trivy-operator.resource.name: nginx-6d4cf56db6
trivy-operator.resource.namespace: default
```

That resource is always the *immediate* controller of the Pod (`Pod`,
`ReplicaSet`, `DaemonSet`, `StatefulSet`, `Job` or `ReplicationController`),
so the importer looks up the referenced object directly (to read its own
labels) and also finds a Pod it owns (to read that Pod's labels as a
fallback). `CronJob` and `Deployment` are also handled defensively (by
walking `CronJob -> Job -> Pod` / `Deployment -> ReplicaSet -> Pod` for the
Pod lookup, while still reading labels off the CronJob/Deployment object
itself) even though trivy-operator doesn't normally reference them directly.

For product name resolution specifically, every key in `DEFECT_DOJO_PRODUCT_NAME_LABELS`
is checked against the controller object first; only if *none* of them are
present there does the importer fall back to checking the same keys, in the
same order, against the Pod.

## Configuration

All configuration is via environment variables. `DEFECT_DOJO_URL` and
`DEFECT_DOJO_API_KEY` are required unless `DRY_RUN=true`. Boolean env vars use
the same semantics as the upstream Python operator: only the literal string
`"true"` is truthy, anything else (including unset) is `false`.

`*_NAME` naming fields (`DEFECT_DOJO_ENGAGEMENT_NAME`, `DEFECT_DOJO_SERVICE_NAME`,
`DEFECT_DOJO_ENV_NAME`, `DEFECT_DOJO_TEST_TITLE`, `DEFECT_DOJO_TAGS`,
`DEFECT_DOJO_PRODUCT_NAME`, `DEFECT_DOJO_PRODUCT_TYPE_NAME`) accept plain
strings or a [Go text/template](https://pkg.go.dev/text/template) referencing
`.Namespace .ReportName .ReportKind .ResourceKind .ResourceName .PodName
.PodLabels`. This replaces the upstream operator's `DEFECT_DOJO_EVAL_*` and
Python `eval()` mechanism with something that isn't a code-injection vector.
Note `DEFECT_DOJO_PRODUCT_NAME` and `DEFECT_DOJO_PRODUCT_TYPE_NAME` are only
*fallbacks* - rendered only when `DEFECT_DOJO_PRODUCT_NAME_LABELS`/
`DEFECT_DOJO_PRODUCT_TYPE_MAP` don't resolve a value for a given report (see
above).

`*_MAP` env vars (`DEFECT_DOJO_PRODUCT_TYPE_MAP`, `DEFECT_DOJO_ENV_NAME_MAP`)
are a comma-separated list of `pattern=Value` pairs, where `pattern` is either
an exact namespace name or a glob (`path.Match` syntax, e.g. `testing-*`),
checked in order with the first match winning, e.g.
`production=Production,acceptance=Acceptance,testing-*=Testing`. Both are empty
by default; a namespace matching nothing (or an empty/unset map) falls back
to the corresponding `_NAME` field.

| Env var | Default | Required | Description |
|---|---|---|---|
| `DEFECT_DOJO_URL` | - | Yes¹ | Base URL of the DefectDojo instance |
| `DEFECT_DOJO_API_KEY` | - | Yes¹ | DefectDojo API v2 token |
| `DEFECT_DOJO_ACTIVE` | `false` | No | Import findings as active |
| `DEFECT_DOJO_VERIFIED` | `false` | No | Import findings as verified |
| `DEFECT_DOJO_CLOSE_OLD_FINDINGS` | `false` | No | Close old findings not present in this scan |
| `DEFECT_DOJO_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE` | `false` | No | Scope "close old findings" to the whole product, not just the engagement |
| `DEFECT_DOJO_PUSH_TO_JIRA` | `false` | No | Push findings to Jira |
| `DEFECT_DOJO_MINIMUM_SEVERITY` | `Info` | No | Minimum severity to import |
| `DEFECT_DOJO_AUTO_CREATE_CONTEXT` | `false` | No | Auto-create the product/engagement/test if missing |
| `DEFECT_DOJO_DEDUPLICATION_ON_ENGAGEMENT` | `false` | No | Scope deduplication to the engagement |
| `DEFECT_DOJO_DO_NOT_REACTIVATE` | `false` | No | Don't reactivate closed findings that reappear |
| `DEFECT_DOJO_ENGAGEMENT_NAME` | `{{.Namespace}}` | No | Engagement name (string or template) |
| `DEFECT_DOJO_SERVICE_NAME` | `""` (empty) | No | Service name (string or template) |
| `DEFECT_DOJO_ENV_NAME` | `Development` | No | Environment name fallback (string or template), used when `DEFECT_DOJO_ENV_NAME_MAP` doesn't match |
| `DEFECT_DOJO_ENV_NAME_MAP` | `""` (empty) | No | Namespace → environment name map (see above) |
| `DEFECT_DOJO_TEST_TITLE` | `Kubernetes` | No | Test title (string or template) |
| `DEFECT_DOJO_TAGS` | `""` (empty) | No | Comma-separated tags (string or template) |
| `DEFECT_DOJO_PRODUCT_NAME` | `{{.ResourceName}}` | No | Fallback product name (string or template), used when none of `DEFECT_DOJO_PRODUCT_NAME_LABELS` can be resolved |
| `DEFECT_DOJO_PRODUCT_NAME_LABELS` | `app.kubernetes.io/name,app` | No | Comma-separated label keys for the product name, checked in order, on the controller before the Pod (see "How pod resolution works" above) |
| `DEFECT_DOJO_PRODUCT_TYPE_NAME` | `Research and Development` | No | Product type fallback (string or template), used when `DEFECT_DOJO_PRODUCT_TYPE_MAP` doesn't match |
| `DEFECT_DOJO_PRODUCT_TYPE_MAP` | `""` (empty) | No | Namespace → product type map (see above) |
| `REPORTS` | `vulnerabilityreports` | No | Comma-separated report CRDs to watch: `vulnerabilityreports`, `configauditreports`, `exposedsecretreports`, `infraassessmentreports`, `rbacassessmentreports` |
| `REPORT_API_GROUP` | `aquasecurity.github.io` | No | |
| `REPORT_API_VERSION` | `v1alpha1` | No | |
| `LABEL` | unset | No | Only watch reports carrying this label |
| `LABEL_VALUE` | unset | No | Required value for `LABEL` (if unset, any value matches) |
| `INCLUDE_NAMESPACES` | `""` (empty) | No | Comma-separated namespaces to watch - exact or glob (`path.Match` syntax, e.g. `testing-*`); empty means all namespaces |
| `EXCLUDE_NAMESPACES` | `""` (empty) | No | Comma-separated namespaces to skip - exact or glob; always wins over `INCLUDE_NAMESPACES` when both match |
| `LOG_LEVEL` | `INFO` | No | |
| `METRICS_ADDR` | `:9090` | No | Serves Prometheus metrics at `/metrics` |
| `DRY_RUN` | `false` | No | Resolve and log product type/name/naming fields per report instead of calling DefectDojo (see below); also makes `DEFECT_DOJO_URL`/`DEFECT_DOJO_API_KEY` optional |
| `HTTP_PROXY` / `HTTPS_PROXY` | unset | No | Proxy for DefectDojo API calls |

¹ Not required when `DRY_RUN=true`.

## Running locally against a real cluster (dry-run)

The importer picks up `KUBECONFIG` the same way `kubectl` does (falling back
to `~/.kube/config`), so pointing it at any cluster you can already reach is
just:

```bash
export KUBECONFIG=/path/to/your/kubeconfig
```

Set `DRY_RUN=true` to skip `DEFECT_DOJO_URL`/`DEFECT_DOJO_API_KEY` entirely
and every DefectDojo API call - instead, for each report it watches, it logs
the resolved pod, product type, product name, and rendered naming fields
(engagement/service/environment/test title/tags) and moves on:

```bash
KUBECONFIG=/path/to/your/kubeconfig DRY_RUN=true LOG_LEVEL=DEBUG \
  DEFECT_DOJO_PRODUCT_TYPE_MAP="production=Webapp,acceptance=Webapp,testing-*=Webapp" \
  DEFECT_DOJO_ENV_NAME_MAP="production=Production,acceptance=Acceptance,testing-*=Testing" \
  go run ./cmd/importer
```

(Both `*_MAP` vars are empty by default - see [Configuration](#configuration)
above - so it's only worth setting them locally if you want to see the
namespace-derived product type/environment resolution rather than the
`DEFECT_DOJO_PRODUCT_TYPE_NAME`/`DEFECT_DOJO_ENV_NAME` fallbacks.)

Each existing matching report in the cluster produces one log line like:

```
level=INFO msg="dry-run: resolved report mapping (nothing sent to DefectDojo)" kind=VulnerabilityReport report=nginx-6d4cf56db6-nginx namespace=production resourceKind=ReplicaSet resourceName=nginx-6d4cf56db6 podName=nginx-6d4cf56db6-abcde controllerLabels=map[app.kubernetes.io/name:nginx] podLabels=map[app.kubernetes.io/name:nginx pod-template-hash:6d4cf56db6] productType="Webapp" productName=nginx engagement=production service="" environment=Production testTitle=Kubernetes tags=[]
```

`REPORTS` limits which report CRDs are watched (useful to shrink the noise
during testing, e.g. `REPORTS=vulnerabilityreports`), `LABEL`/`LABEL_VALUE`
further narrow it to reports carrying a specific label, and
`INCLUDE_NAMESPACES`/`EXCLUDE_NAMESPACES` narrow it by namespace, e.g.
`INCLUDE_NAMESPACES=production,testing-*` to only see reports from those.

## Known differences from telekom-mms/trivy-dojo-report-operator

- No `TRANSFORMATION_*` subprocess hook - not needed for this use case.
- No persisted "already processed" state (upstream uses kopf's
  `status.diff-base` storage). This importer reprocesses all matching reports
  on every restart. This is safe because `reimport-scan` is idempotent - it
  upserts findings for the same product/engagement/test rather than
  duplicating them - but it does mean every restart re-sends every current
  report to DefectDojo.
- Naming templates use Go's `text/template` instead of Python `eval()`.

## Building

```bash
go build ./...
```

## Container image

```bash
docker build -t trivy-operator-defectdojo-importer .
```

## Deploying

### Helm (recommended)

```bash
helm repo add trivy-operator-defectdojo-importer https://yoshz.github.io/trivy-operator-defectdojo-importer/
helm repo update
helm install trivy-dojo-importer trivy-operator-defectdojo-importer/trivy-operator-defectdojo-importer \
  --namespace trivy-system --create-namespace \
  --set defectDojo.url=https://defectdojo.example.com \
  --set defectDojo.apiKey=<your-api-key>
```

See [charts/trivy-operator-defectdojo-importer/values.yaml](charts/trivy-operator-defectdojo-importer/values.yaml)
for the full set of configurable values, including `defectDojo.existingSecret`
to reference a pre-existing Secret instead of passing `defectDojo.apiKey`
directly, `defectDojo.productTypeMap`/`defectDojo.envNameMap` for the
namespace matching rules, `includeNamespaces`/`excludeNamespaces` to restrict
which namespaces are watched, `reports` for which report CRDs to watch, and
`metrics.serviceMonitor.enabled` if you run the Prometheus Operator.

### Plain manifests

See [deploy/rbac.yaml](deploy/rbac.yaml), [deploy/secret.yaml.example](deploy/secret.yaml.example)
and [deploy/deployment.yaml](deploy/deployment.yaml). Copy the secret example,
fill in your API key, and adjust the namespace/image/env vars to match your
cluster.

## License

Licensed under the [GNU General Public License v3.0](LICENSE) or later.
