package oauthrs_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/altalune-id/oauthrs"
)

func TestMetadataURL(t *testing.T) {
	for resource, want := range map[string]string{
		"https://notes.example/mcp":          "https://notes.example/.well-known/oauth-protected-resource/mcp",
		"https://notes.example:8443/v1/mcp/": "https://notes.example:8443/.well-known/oauth-protected-resource/v1/mcp",
		"https://notes.example":              "https://notes.example/.well-known/oauth-protected-resource",
		"https://notes.example/mcp?t=1":      "https://notes.example/.well-known/oauth-protected-resource/mcp?t=1",
		"https://notes.example/?t=1":         "https://notes.example/.well-known/oauth-protected-resource?t=1",
		"http://127.0.0.1:8080/mcp":          "http://127.0.0.1:8080/.well-known/oauth-protected-resource/mcp",
	} {
		got, err := oauthrs.MetadataURL(resource)
		require.NoError(t, err, resource)
		assert.Equal(t, want, got, "RFC 9728 §3.1: %s", resource)
	}
	for _, bad := range []string{"", "::", "/mcp", "https://notes.example/mcp#x", "mailto:a@b"} {
		_, err := oauthrs.MetadataURL(bad)
		assert.Error(t, err, bad)
	}
}

func TestMetadataHandler(t *testing.T) {
	h := oauthrs.MetadataHandler(oauthrs.ProtectedResource{
		Resource: "https://notes.example/mcp", AuthorizationServers: []string{"https://id.example/p/notes"}, ScopesSupported: []string{"notes:read"},
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"), "a browser-based MCP client reads it cross-origin")
	assert.Contains(t, w.Header().Get("Cache-Control"), "public")
	var got map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, map[string]any{
		"resource": "https://notes.example/mcp", "authorization_servers": []any{"https://id.example/p/notes"},
		"scopes_supported": []any{"notes:read"}, "bearer_methods_supported": []any{"header"},
	}, got)

	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", nil))
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestParseProtectedResource(t *testing.T) {
	pr, err := oauthrs.ParseProtectedResource([]byte(`{"resource":"https://notes.example/mcp","authorization_servers":["https://id.example/p/notes"],"x":1}`))
	require.NoError(t, err)
	assert.Equal(t, oauthrs.ProtectedResource{
		Resource: "https://notes.example/mcp", AuthorizationServers: []string{"https://id.example/p/notes"}, Extra: map[string]any{"x": float64(1)},
	}, pr)

	pr, err = oauthrs.ParseProtectedResource([]byte(`{"Resource":"https://evil.example","AUTHORIZATION_SERVERS":["https://evil.example"]}`))
	require.NoError(t, err)
	assert.Empty(t, pr.Resource, "only the exact RFC 9728 keys count, never a case-folded match")
	assert.Empty(t, pr.AuthorizationServers, "only the exact RFC 9728 keys count, never a case-folded match")
	assert.Equal(t, "https://evil.example", pr.Extra["Resource"], "a case-folded key is only an extra member")

	for _, bad := range []string{`[]`, `"x"`, `{"resource":1}`, `{"authorization_servers":"x"}`, `not json`} {
		_, err := oauthrs.ParseProtectedResource([]byte(bad))
		assert.Error(t, err, bad)
	}
}

func TestMetadataExtraMembers(t *testing.T) {
	pr := oauthrs.ProtectedResource{
		Resource: "https://notes.example/api", AuthorizationServers: []string{"https://auth.example/p/acme"},
		Extra: map[string]any{"cli_client_id": "cli123", "resource": "https://evil.example/api"},
	}
	w := httptest.NewRecorder()
	oauthrs.MetadataHandler(pr).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusOK, w.Code)
	got, err := oauthrs.ParseProtectedResource(w.Body.Bytes())
	require.NoError(t, err)
	assert.Equal(t, "https://notes.example/api", got.Resource, "RFC 9728 §2: an extra member never overrides a standard one")
	assert.Equal(t, map[string]any{"cli_client_id": "cli123"}, got.Extra, "RFC 9728 §2: further parameters round-trip")
}

func TestMetadataHandlerUnmarshallableExtra(t *testing.T) {
	h := oauthrs.MetadataHandler(oauthrs.ProtectedResource{Resource: "https://notes.example/api", Extra: map[string]any{"x": func() {}}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
