# oauthrs

A small OAuth 2.0 resource server for Go: RFC 9068 JWT access tokens, RFC 7662 introspection for opaque tokens, RFC 6750 bearer challenges and RFC 9728 protected resource metadata.

```sh
go get github.com/altalune-id/oauthrs
```

```go
const resource = "https://notes.example/mcp"
v, _ := oauthrs.New(oauthrs.Config{Issuer: "https://auth.example/p/acme", Audience: resource})
metadata, _ := oauthrs.MetadataURL(resource)
h := oauthrs.Middleware(v, metadata)(oauthrs.RequireScope(metadata, "notes:read")(tool))
```

Handlers read the verified token with `oauthrs.FromContext`. See `example_test.go`.

Dependencies: the standard library, golang.org/x/sync and go-jose, and `github.com/altalune-id/oidcrp`. Licensed under Apache-2.0 (see `LICENSE` and `NOTICE`).
