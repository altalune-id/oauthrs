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
	assert.Equal(t, oauthrs.ProtectedResource{Resource: "https://notes.example/mcp", AuthorizationServers: []string{"https://id.example/p/notes"}}, pr)

	pr, err = oauthrs.ParseProtectedResource([]byte(`{"Resource":"https://evil.example","AUTHORIZATION_SERVERS":["https://evil.example"]}`))
	require.NoError(t, err)
	assert.Equal(t, oauthrs.ProtectedResource{}, pr, "only the exact RFC 9728 keys count, never a case-folded match")

	for _, bad := range []string{`[]`, `"x"`, `{"resource":1}`, `{"authorization_servers":"x"}`, `not json`} {
		_, err := oauthrs.ParseProtectedResource([]byte(bad))
		assert.Error(t, err, bad)
	}
}
