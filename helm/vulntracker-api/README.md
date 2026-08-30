# vulntracker-api Helm chart

Deploys the VulnTracker FastAPI service to Kubernetes.

## Quick start

```bash
# External Secrets Operator (default)
helm install vulntracker ./helm/vulntracker-api \
  --namespace vulntracker --create-namespace \
  --set image.repository=<registry>/vulntracker-api \
  --set image.digest=sha256:... \
  --set config.PUBLIC_BASE_URL=https://vulntracker.example.com \
  --set ingress.enabled=true --set ingress.host=vulntracker.example.com

# Argo CD Vault Plugin
helm install vulntracker ./helm/vulntracker-api --set secrets.provider=avp
```

## Secret management

The container only ever reads a Kubernetes `Secret` (`<release>-secrets`). How it
gets populated is selected by `secrets.provider`:

| `provider` | What the chart renders | Prerequisite |
| ---------- | ---------------------- | ------------ |
| `eso` (default) | An `ExternalSecret` (`external-secrets.io/v1`) | External Secrets Operator + a `(Cluster)SecretStore` named in `secrets.eso.secretStoreRef` |
| `avp` | A `Secret` whose values are `<path:...>` placeholders | Argo CD Vault Plugin rendering the Application |

Secret keys are declared once in `secrets.items`; the `Deployment` is identical
for both providers. To add a secret (e.g. a Postgres URL) add an item and put the
value in your backend at the configured path — no template changes.

- **ESO** reads `secrets.eso.remoteKey` (path) / item `key` (property).
- **AVP** builds `<path:{secrets.avp.path}#{key}>` — `avp.path` must include the
  KV-v2 `data/` segment.

## Security defaults

- Non-root (uid 10001), read-only root FS, all capabilities dropped,
  `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault`
- `automountServiceAccountToken: false` (the app never calls the API server)
- `NetworkPolicy`: ingress only from the ingress controller to `:8000`; egress
  only to DNS and the notification service
- CPU/memory requests and limits set
- Startup / readiness / liveness probes on `/health`

## Known limitation

`config.DATABASE_URL` defaults to SQLite on a local volume — single replica only.
For real use, point it at a managed database and add its credentials to
`secrets.items`.
