# MCP OIDC Proxy — Operations Reference

## Audit Events

All audit events are emitted as structured `tracing` log fields with `audit_event` key.
Filter with: `audit_event=*` or individual event names below.

### Registration Lifecycle

| Event | Level | Trigger |
|-------|-------|---------|
| `client_registered` | info | New client created via POST /client-registration |
| `client_registration_idempotent` | debug | Existing client returned (deterministic re-registration) |
| `client_updated` | info | Client metadata updated via PUT/PATCH |
| `client_deactivated` | info | Client deactivated via DELETE; includes `transactions_revoked` and `auth_codes_revoked` counts |

### Authorization Flow

| Event | Level | Trigger |
|-------|-------|---------|
| `proxy_authorize_started` | info | Authorization redirect to IDP initiated |
| `authorize_rejected_deactivated` | warn | Authorize blocked — client was deactivated |
| `authorize_rejected_unknown` | warn | Authorize blocked — unknown client_id |
| `authorize_rejected_redirect_uri` | warn | Authorize blocked — redirect_uri mismatch |

### Token Exchange

| Event | Level | Trigger |
|-------|-------|---------|
| `proxy_callback_success` | info | IDP code exchange succeeded; proxy auth code issued |
| `proxy_token_issued` | info | Tokens delivered to client |
| `token_rejected_deactivated` | warn | Token exchange blocked — client deactivated |
| `token_rejected_unknown` | warn | Token exchange blocked — unknown client |
| `token_rejected_bad_secret` | warn | Token exchange blocked — client_secret mismatch |
| `token_rejected_expired_code` | warn | Token exchange blocked — expired or replayed auth code |
| `token_rejected_pkce_mismatch` | warn | Token exchange blocked — PKCE code_verifier mismatch |

## Revocation Procedures

### Deactivate a Client

```bash
curl -X DELETE https://gateway.example.com/.well-known/oauth-authorization-server/client-registration/{client_id}
```

**What happens:**
1. Client record marked `active: false` (permanent, not reversible via API)
2. All pending proxy transactions for that client_id are purged
3. All unredeemed proxy authorization codes for that client_id are purged
4. Future authorize and token requests for that client_id fail closed

**What does NOT happen:**
- Tokens already delivered to the client are not revoked at the IDP
- If the downstream IDP supports token revocation, use the IDP's revocation endpoint directly

### Verify Revocation Took Effect

Check the audit log for the `client_deactivated` event:

```
audit_event=client_deactivated client_id=agw_... transactions_revoked=N auth_codes_revoked=N
```

Then confirm subsequent requests fail:

```bash
# Should return 400 invalid_client
curl "https://gateway.example.com/.well-known/oauth-authorization-server/authorize?client_id={client_id}&..."

# Should return 401 invalid_client
curl -X POST https://gateway.example.com/.well-known/oauth-authorization-server/token -d "client_id={client_id}&..."
```

## State Expiration

| State Type | TTL | Anti-Replay |
|-----------|-----|-------------|
| Proxy transaction (authorize→callback) | 10 minutes | Single-use: removed on consumption |
| Proxy authorization code (callback→token) | 5 minutes | Single-use: removed on consumption |

Expired entries are garbage-collected on the next insert operation.

## Configuration

Enable the OIDC proxy by adding `oidcProxy` to `mcpAuthentication`:

```yaml
mcpAuthentication:
  issuer: https://your-idp.example.com
  audiences:
  - your-audience
  jwks:
    url: https://your-idp.example.com/.well-known/jwks.json
  oidcProxy:
    clientId: gateway-client-id-registered-with-idp
    clientSecret: gateway-client-secret
```

When `oidcProxy` is absent, the gateway operates in pass-through mode (validates JWTs but does not proxy authorization flows). All audit events and revocation controls remain active for the registration lifecycle.
