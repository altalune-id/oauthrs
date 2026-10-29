package oauthrs_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/altalune-id/oidcrp/oidcrptest"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/altalune-id/oauthrs"
)

const audience = "https://notes.example/mcp"

var now = time.Unix(1_800_000_000, 0)

func newIDP(t *testing.T) *oidcrptest.IDP {
	t.Helper()
	idp := oidcrptest.New(t)
	idp.Now = func() time.Time { return now }
	return idp
}

func newVerifier(t *testing.T, idp *oidcrptest.IDP, opts ...func(*oauthrs.Config)) *oauthrs.Verifier {
	t.Helper()
	cfg := oauthrs.Config{Issuer: idp.Issuer(), Audience: audience, HTTPClient: idp.Client()}
	for _, o := range opts {
		o(&cfg)
	}
	v, err := oauthrs.New(cfg)
	require.NoError(t, err)
	return v.WithClock(func() time.Time { return now })
}

func TestNew_RequiresIssuerAndAudience(t *testing.T) {
	_, err := oauthrs.New(oauthrs.Config{Audience: audience})
	require.Error(t, err)
	_, err = oauthrs.New(oauthrs.Config{Issuer: "https://id.example/p/acme"})
	require.Error(t, err)
}

func TestVerify_AccessToken(t *testing.T) {
	idp := newIDP(t)
	v := newVerifier(t, idp)
	raw := idp.AccessToken(map[string]any{"aud": audience, "scope": "notes:read notes:write", "sid": "Q7mZp2LkV9xRt4NbW8cYd", "jti": "K9tWq4ZbN2xLm7VcR5pHs"})
	tok, err := v.Verify(context.Background(), raw)
	require.NoError(t, err)
	assert.Equal(t, &oauthrs.Token{
		Issuer: idp.Issuer(), Subject: idp.User.Subject, ClientID: "test-client", Scopes: []string{"notes:read", "notes:write"},
		JWTID: "K9tWq4ZbN2xLm7VcR5pHs", SessionID: "Q7mZp2LkV9xRt4NbW8cYd", ExpiresAt: now.Add(15 * time.Minute),
	}, tok)
	assert.True(t, tok.HasScope("notes:write"))
	assert.False(t, tok.HasScope("notes"))

	tok, err = v.Verify(context.Background(), idp.AccessToken(map[string]any{"aud": []string{"https://other.example", audience}}))
	require.NoError(t, err, "RFC 9068 §4: aud contains this resource")
	assert.Equal(t, []string{"openid"}, tok.Scopes)
}

func TestVerify_Refusals(t *testing.T) {
	idp := newIDP(t)
	v := newVerifier(t, idp)
	good := map[string]any{"aud": audience}
	with := func(k string, val any) map[string]any {
		c := map[string]any{"aud": audience}
		c[k] = val
		return c
	}
	for name, raw := range map[string]string{
		"an ID token (RFC 9068 §4: typ at+jwt is pinned)": idp.IDToken(idp.AccessTokenClaims(good)),
		"another issuer":                        idp.AccessToken(with("iss", "https://evil.example")),
		"another audience":                      idp.AccessToken(with("aud", "https://other.example/mcp")),
		"no audience":                           idp.AccessToken(map[string]any{"aud": nil}),
		"expired":                               idp.AccessToken(with("exp", now.Add(-time.Minute).Unix())),
		"no exp":                                idp.AccessToken(with("exp", nil)),
		"issued in the future":                  idp.AccessToken(with("iat", now.Add(10*time.Minute).Unix())),
		"not yet valid (nbf)":                   idp.AccessToken(with("nbf", now.Add(10*time.Minute).Unix())),
		"no sub":                                idp.AccessToken(with("sub", nil)),
		"no client_id (RFC 9068 §2.2)":          idp.AccessToken(with("client_id", nil)),
		"no jti (RFC 9068 §2.2)":                idp.AccessToken(with("jti", nil)),
		"garbage":                               "a.b.c",
		"an opaque token with no introspection": "othra_pt_x",
		"empty":                                 "",
	} {
		_, err := v.Verify(context.Background(), raw)
		assert.True(t, oauthrs.IsInvalidTokenError(err), "%s: %v", name, err)
	}
	_, err := v.Verify(context.Background(), idp.AccessToken(with("exp", now.Add(-time.Minute).Unix())))
	assert.True(t, oauthrs.IsExpiredTokenError(err), "an expired token says so, for the challenge")
}

func TestVerify_SkewAndAlgorithms(t *testing.T) {
	idp := newIDP(t)
	v := newVerifier(t, idp, func(c *oauthrs.Config) { c.ClockSkew = time.Minute })
	_, err := v.Verify(context.Background(), idp.AccessToken(map[string]any{"aud": audience, "exp": now.Add(-30 * time.Second).Unix()}))
	require.NoError(t, err, "within the clock skew")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for name, alg := range map[string]jose.SignatureAlgorithm{"HS256": jose.HS256, "an unpublished key": jose.RS256} {
		var signKey any = key
		if alg == jose.HS256 {
			signKey = []byte("a-shared-secret-of-thirty-two-b!")
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: signKey}, (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", "k1"))
		require.NoError(t, err)
		payload, err := json.Marshal(idp.AccessTokenClaims(map[string]any{"aud": audience}))
		require.NoError(t, err)
		obj, err := signer.Sign(payload)
		require.NoError(t, err)
		raw, err := obj.CompactSerialize()
		require.NoError(t, err)
		_, err = v.Verify(context.Background(), raw)
		assert.True(t, oauthrs.IsInvalidTokenError(err), "%s is refused: %v", name, err)
	}
}

func TestVerify_FollowsKeyRotation(t *testing.T) {
	idp := newIDP(t)
	v := newVerifier(t, idp)
	_, err := v.Verify(context.Background(), idp.AccessToken(map[string]any{"aud": audience}))
	require.NoError(t, err)
	idp.RotateKey()
	_, err = v.Verify(context.Background(), idp.AccessToken(map[string]any{"aud": audience}))
	require.NoError(t, err, "OIDC Core §10.1.1: a new kid refetches the JWKS")
}

func TestVerify_SharesAKeySource(t *testing.T) {
	idp := newIDP(t)
	api := newVerifier(t, idp, func(c *oauthrs.Config) { c.Audience = "https://notes.example/api" })
	mcp, err := oauthrs.New(oauthrs.Config{Issuer: idp.Issuer(), Audience: audience, Keys: api.Keys()})
	require.NoError(t, err)
	_, err = mcp.WithClock(func() time.Time { return now }).Verify(context.Background(), idp.AccessToken(map[string]any{"aud": audience}))
	require.NoError(t, err, "two resources of one app share the issuer's cached keys")
	_, err = mcp.Verify(context.Background(), idp.AccessToken(map[string]any{"aud": "https://notes.example/api"}))
	assert.True(t, oauthrs.IsInvalidTokenError(err), "but each checks its own audience")
}
