# Optional built-in OIDC authentication

The Tekton Dashboard does not require authentication by default. Clusters that
expose the dashboard on a public URL typically place an OIDC-aware reverse
proxy (for example [oauth2-proxy](../walkthrough/walkthrough-oauth2-proxy.md))
in front of the Service.

The dashboard supports an **optional** OIDC flow in the same process.
When disabled (default), behaviour is unchanged. When enabled, users sign
in through their OIDC provider before the UI or Kubernetes API proxy is used.

## Flow

1. Unauthenticated request → redirect to `/auth/login`
2. `/auth/login` → OIDC provider authorization endpoint
3. Provider redirects to `/auth/callback` with an authorization code
4. Dashboard validates the ID token, sets an HTTP-only session cookie
5. `/auth/logout` clears the session

Health (`/health`, `/readiness`) and `/auth/*` routes are never gated.

## Flags and environment

| Flag | Environment | Description |
|------|-------------|-------------|
| `--auth-enabled` | — | Enable OIDC gate |
| `--auth-oidc-issuer-url` | — | Issuer URL (`.well-known/openid-configuration`) |
| `--auth-oidc-client-id` | `AUTH_OIDC_CLIENT_ID` | OAuth client ID |
| `--auth-oidc-client-secret` | `AUTH_OIDC_CLIENT_SECRET` | OAuth client secret |
| `--auth-redirect-url` | — | Registered redirect URI (…/auth/callback) |
| `--auth-cookie-secret` | `AUTH_COOKIE_SECRET` | HMAC secret for session cookies |
| `--auth-email-domains` | — | Optional comma-separated allow list; empty = any email in token |
| `--auth-base-url` | — | Optional external base URL for logout redirect |

When `--auth-enabled` is true, `/v1/properties` includes `authEnabled` and
`loginURL`. If `--logout-url` is unset, logout defaults to `/auth/logout`.

## Authorization (RBAC)

Authentication confirms user identity. **Authorization** (which PipelineRuns a
user may view or create) still follows Kubernetes RBAC on the dashboard
ServiceAccount, the same as upstream. Per-user impersonation is not implemented
in this change; see the [access control](../install.md#access-control) section
for proxy-based impersonation patterns.

## Local testing

Use any OIDC provider that supports the authorization code flow with an ID
token containing `email` and `sub` claims. Register redirect URI
`http://localhost:9097/auth/callback` when using port-forward.

```bash
go test ./pkg/auth/...
```

---

Except as otherwise noted, the content of this page is licensed under the
[Creative Commons Attribution 4.0 License](https://creativecommons.org/licenses/by/4.0/).
Code samples are licensed under the [Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0).
