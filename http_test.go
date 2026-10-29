package oauthrs_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/altalune-id/oauthrs"
)

const metaURL = "https://notes.example/.well-known/oauth-protected-resource/mcp"

func TestBearerToken(t *testing.T) {
	for header, want := range map[string]string{"Bearer abc.def.ghi": "abc.def.ghi", "bearer  othra_pt_x ": "othra_pt_x"} {
		r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		r.Header.Set("Authorization", header)
		got, err := oauthrs.BearerToken(r)
		require.NoError(t, err, header)
		assert.Equal(t, want, got)
	}
	for _, header := range []string{"", "Basic dXNlcjpwYXNz", "DPoP abc", "Bearerabc"} {
		r := httptest.NewRequest(http.MethodGet, "/mcp?access_token=abc", nil)
		r.Header.Set("Authorization", header)
		_, err := oauthrs.BearerToken(r)
		assert.True(t, oauthrs.IsMissingTokenError(err), "%q: no Bearer credentials, and never the query (RFC 9700 §2.4)", header)
	}
	for _, header := range []string{"Bearer", "Bearer a b", "Bearer a,b", "Bearer =abc", "Bearer a\"b"} {
		r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		r.Header.Set("Authorization", header)
		_, err := oauthrs.BearerToken(r)
		assert.True(t, oauthrs.IsMalformedRequestError(err), "%q is not an RFC 6750 §2.1 b64token", header)
	}
}

func TestChallenge(t *testing.T) {
	assert.Equal(t, `Bearer resource_metadata="`+metaURL+`"`, oauthrs.Challenge(metaURL, &oauthrs.MissingTokenError{}),
		"RFC 6750 §3.1: no error code when the request had no token")
	assert.Equal(t, `Bearer resource_metadata="`+metaURL+`", error="invalid_token"`, oauthrs.Challenge(metaURL, &oauthrs.InvalidTokenError{Reason: "x"}))
	assert.Equal(t, `Bearer resource_metadata="`+metaURL+`", error="invalid_request"`, oauthrs.Challenge(metaURL, &oauthrs.MalformedRequestError{}))
	assert.Equal(t, `Bearer resource_metadata="`+metaURL+`", error="invalid_token"`, oauthrs.Challenge(metaURL, &oauthrs.ExpiredTokenError{}))
	assert.Equal(t, `Bearer resource_metadata="`+metaURL+`", error="insufficient_scope", scope="notes:write"`,
		oauthrs.Challenge(metaURL, &oauthrs.InsufficientScopeError{Scope: "notes:write"}))
}

func TestMiddleware(t *testing.T) {
	idp := newIDP(t)
	v := newVerifier(t, idp)
	var seen *oauthrs.Token
	h := oauthrs.Middleware(v, metaURL)(oauthrs.RequireScope(metaURL, "notes:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = oauthrs.FromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})))
	call := func(token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	w := call(idp.AccessToken(map[string]any{"aud": audience, "scope": "notes:read"}))
	assert.Equal(t, http.StatusNoContent, w.Code)
	require.NotNil(t, seen)
	assert.Equal(t, idp.User.Subject, seen.Subject)

	w = call("")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, `Bearer resource_metadata="`+metaURL+`"`, w.Header().Get("WWW-Authenticate"))

	for _, c := range []struct {
		header, challenge string
		code              int
	}{
		{"Basic dXNlcjpwYXNz", `Bearer resource_metadata="` + metaURL + `"`, http.StatusUnauthorized},
		{"Bearer a b", `Bearer resource_metadata="` + metaURL + `", error="invalid_request"`, http.StatusBadRequest},
	} {
		r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		r.Header.Set("Authorization", c.header)
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assert.Equal(t, c.code, w.Code, "RFC 6750 §3.1: %q", c.header)
		assert.Equal(t, c.challenge, w.Header().Get("WWW-Authenticate"), c.header)
	}

	w = call(idp.AccessToken(map[string]any{"aud": "https://other.example"}))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Header().Get("WWW-Authenticate"), `error="invalid_token"`)

	w = call(idp.AccessToken(map[string]any{"aud": audience, "scope": "openid"}))
	assert.Equal(t, http.StatusForbidden, w.Code, "RFC 6750 §3.1: insufficient_scope is 403")
	assert.Contains(t, w.Header().Get("WWW-Authenticate"), `error="insufficient_scope", scope="notes:read"`)

	broken := newVerifier(t, idp, func(c *oauthrs.Config) { c.Issuer = idp.Issuer() + "/nowhere" })
	w = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+idp.AccessToken(map[string]any{"aud": audience}))
	oauthrs.Middleware(broken, metaURL)(http.NotFoundHandler()).ServeHTTP(w, r)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "an unreachable issuer is the server's fault, never a 401")

	_, ok := oauthrs.FromContext(context.Background())
	assert.False(t, ok)
	got, ok := oauthrs.FromContext(oauthrs.WithToken(context.Background(), seen))
	assert.True(t, ok)
	assert.Same(t, seen, got, "a Connect interceptor puts the token where FromContext reads it")
	w = httptest.NewRecorder()
	oauthrs.RequireScope(metaURL, "notes:read")(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/mcp", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code, "RequireScope without Middleware fails closed")
}

func TestRequireScope_All(t *testing.T) {
	idp := newIDP(t)
	v := newVerifier(t, idp)
	h := oauthrs.Middleware(v, metaURL)(oauthrs.RequireScope(metaURL, "notes:read", "notes:write")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	call := func(scope string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		r.Header.Set("Authorization", "Bearer "+idp.AccessToken(map[string]any{"aud": audience, "scope": scope}))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	assert.Equal(t, http.StatusNoContent, call("notes:write notes:read").Code)
	w := call("notes:read")
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Header().Get("WWW-Authenticate"), `error="insufficient_scope", scope="notes:read notes:write"`,
		"RFC 6750 §3: the challenge names every scope the call needs")
}

func TestMiddleware_OnError(t *testing.T) {
	idp := newIDP(t)
	broken := newVerifier(t, idp, func(c *oauthrs.Config) { c.Issuer = idp.Issuer() + "/nowhere" })
	var got error
	var path string
	h := oauthrs.Middleware(broken, metaURL, oauthrs.OnError(func(r *http.Request, err error) {
		path, got = r.URL.Path, err
	}))(http.NotFoundHandler())
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+idp.AccessToken(map[string]any{"aud": audience}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.Error(t, got, "the app hears why it answered 503")
	assert.Equal(t, "/mcp", path)

	got = nil
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, got, "a refused token is the caller's fault, not reported")

	w = httptest.NewRecorder()
	oauthrs.Middleware(broken, metaURL, oauthrs.OnError(nil))(http.NotFoundHandler()).ServeHTTP(w, r)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "a nil hook is ignored")
}
