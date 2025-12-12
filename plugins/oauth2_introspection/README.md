OAuth2 Introspection Auth Plugin (Resolve User Only)
===================================================

This plugin integrates OAuth2/OIDC access token introspection (RFC 7662) with MCP Gateway using the `HTTP_AUTH_RESOLVE_USER` hook only. It validates `Authorization: Bearer <token>` against your Identity Provider (IDP) introspection endpoint and makes both the token (redacted by default) and introspection data available to downstream components via the plugin context table.

Key features
- Validate Bearer tokens using your IDP’s introspection endpoint
- Validate audience check and required scopes
- Propagate token and introspection details to the plugin context for downstream use

Configuration
Add this plugin to your plugin manager configuration (YAML), for example:

```yaml
plugins:
  - name: oauth2_introspection
    module: plugins.examples.oauth2_introspection.oauth2_introspection
    class: OAuth2IntrospectionPlugin
    hooks:
      - HTTP_AUTH_RESOLVE_USER
    config:
      introspection_url: https://idp.example.com/oauth2/introspect
      client_id: ${OAUTH_CLIENT_ID}
      client_secret: ${OAUTH_CLIENT_SECRET}
      auth_method: basic            # basic | post
      audience: my-api-audience     # optional
      required_scopes: ["openid"]  # optional
      request_timeout_seconds: 30
      expose_raw_token_in_context: false
```

Downstream access to token/introspection
- The plugin stores `token` and `introspection` in the plugin context state under the key `tc_token`.
- The value is a list; a new entry is appended on each successful introspection during a request lifecycle. Each entry looks like:

  ```json
  {
    "token": "***redacted***",
    "introspection": {}
  }
  ```

- By default, the `token` is redacted as `***redacted***`. Set `expose_raw_token_in_context: true` in the config if you need the raw token (use with caution).
- Other parts of the pipeline can retrieve it via the plugin context table.
