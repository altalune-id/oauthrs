package oauthrs_test

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/altalune-id/oidcrp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/altalune-id/oauthrs"
)

func withIntrospection(ttl time.Duration) func(*oauthrs.Config) {
	return func(c *oauthrs.Config) {
		c.Introspection = &oauthrs.Introspection{ClientID: "notes-rs", ClientSecret: "s3cret", TokenPrefix: "othra_pt_", CacheTTL: ttl}
	}
}

func TestVerify_PersonalTokenThroughIntrospection(t *testing.T) {
	idp := newIDP(t)
	idp.Introspector("notes-rs", "s3cret")
	idp.Opaque("othra_pt_live", map[string]any{
		"sub": "F5pLm2XwQ8kRt3VnZ7bYc", "aud": audience, "scope": "notes:read", "exp": now.Add(time.Hour).Unix(),
	})
	v := newVerifier(t, idp, withIntrospection(time.Minute))
	tok, err := v.Verify(context.Background(), "othra_pt_live")
	require.NoError(t, err)
	assert.Equal(t, &oauthrs.Token{
		Issuer: idp.Issuer(), Subject: "F5pLm2XwQ8kRt3VnZ7bYc", Scopes: []string{"notes:read"}, ExpiresAt: now.Add(time.Hour), Personal: true,
	}, tok)
	_, err = v.Verify(context.Background(), "othra_pt_live")
	require.NoError(t, err)
	assert.Equal(t, 1, idp.Introspections(), "an active answer is cached for a short while")

	for range 2 {
		_, err = v.Verify(context.Background(), "othra_pt_revoked")
		assert.True(t, oauthrs.IsInvalidTokenError(err), "inactive: %v", err)
	}
	assert.Equal(t, 2, idp.Introspections(), "an inactive answer is cached for a short while too")
}

func TestVerify_IntrospectionChecks(t *testing.T) {
	idp := newIDP(t)
	idp.Introspector("notes-rs", "s3cret")
	idp.Opaque("othra_pt_other_aud", map[string]any{"sub": "u", "aud": "https://other.example/mcp", "exp": now.Add(time.Hour).Unix()})
	idp.Opaque("othra_pt_other_iss", map[string]any{"sub": "u", "aud": audience, "iss": "https://evil.example", "exp": now.Add(time.Hour).Unix()})
	idp.Opaque("othra_pt_no_sub", map[string]any{"aud": audience, "exp": now.Add(time.Hour).Unix()})
	idp.Opaque("othra_pt_expired", map[string]any{"sub": "u", "aud": audience, "exp": now.Add(-time.Minute).Unix()})
	v := newVerifier(t, idp, withIntrospection(time.Minute))
	for _, raw := range []string{"othra_pt_other_aud", "othra_pt_other_iss", "othra_pt_no_sub", "othra_pt_expired"} {
		_, err := v.Verify(context.Background(), raw)
		assert.True(t, oauthrs.IsInvalidTokenError(err), "%s: %v", raw, err)
	}

	wrong := newVerifier(t, idp, func(c *oauthrs.Config) {
		c.Introspection = &oauthrs.Introspection{ClientID: "notes-rs", ClientSecret: "wrong", TokenPrefix: "othra_pt_"}
	})
	_, err := wrong.Verify(context.Background(), "othra_pt_other_aud")
	require.Error(t, err)
	assert.False(t, oauthrs.IsInvalidTokenError(err), "a refused introspection is the server's fault, never the caller's token")
}

func TestVerify_IntrospectionCacheExpires(t *testing.T) {
	idp := newIDP(t)
	idp.Introspector("notes-rs", "s3cret")
	idp.Opaque("othra_pt_soon", map[string]any{"sub": "u", "aud": audience, "exp": now.Add(10 * time.Second).Unix()})
	clock := now
	v := newVerifier(t, idp, withIntrospection(time.Minute)).WithClock(func() time.Time { return clock })
	_, err := v.Verify(context.Background(), "othra_pt_soon")
	require.NoError(t, err)
	clock = now.Add(20 * time.Second)
	_, err = v.Verify(context.Background(), "othra_pt_soon")
	assert.True(t, oauthrs.IsInvalidTokenError(err), "the cache never outlives the token's exp: %v", err)
	assert.Equal(t, 2, idp.Introspections())
}

func TestVerify_IntrospectionCacheCapped(t *testing.T) {
	idp := newIDP(t)
	idp.Introspector("notes-rs", "s3cret")
	idp.Opaque("othra_pt_live", map[string]any{"sub": "u", "aud": audience, "exp": now.Add(time.Hour).Unix()})
	clock := now
	v := newVerifier(t, idp, withIntrospection(time.Hour)).WithClock(func() time.Time { return clock })
	_, err := v.Verify(context.Background(), "othra_pt_live")
	require.NoError(t, err)
	clock = now.Add(59 * time.Second)
	_, err = v.Verify(context.Background(), "othra_pt_live")
	require.NoError(t, err)
	assert.Equal(t, 1, idp.Introspections())
	clock = now.Add(61 * time.Second)
	_, err = v.Verify(context.Background(), "othra_pt_live")
	require.NoError(t, err)
	assert.Equal(t, 2, idp.Introspections(), "a revoke reaches every app within 60 s, whatever CacheTTL says")
}

func TestVerify_IntrospectionCacheOff(t *testing.T) {
	idp := newIDP(t)
	idp.Introspector("notes-rs", "s3cret")
	idp.Opaque("othra_pt_live", map[string]any{"sub": "u", "aud": audience, "exp": now.Add(time.Hour).Unix()})
	v := newVerifier(t, idp, withIntrospection(-1))
	for range 2 {
		_, err := v.Verify(context.Background(), "othra_pt_live")
		require.NoError(t, err)
	}
	assert.Equal(t, 2, idp.Introspections(), "a negative CacheTTL asks every time, so a revoke shows at once")
}

func TestVerify_IntrospectsOnlyPrefixedTokens(t *testing.T) {
	idp := newIDP(t)
	idp.Introspector("notes-rs", "s3cret")
	v := newVerifier(t, idp, withIntrospection(time.Minute))
	for _, raw := range []string{"notes_ak_live_key", "othra_ptx", "OTHRA_PT_upper"} {
		_, err := v.Verify(context.Background(), raw)
		assert.True(t, oauthrs.IsInvalidTokenError(err), raw)
	}
	assert.Zero(t, idp.Introspections(), "an app's own opaque credential never reaches the issuer")
}

func TestNew_IntrospectionNeedsTokenPrefix(t *testing.T) {
	_, err := oauthrs.New(oauthrs.Config{
		Issuer: "https://auth.example", Audience: audience, Introspection: &oauthrs.Introspection{ClientID: "notes-rs", ClientSecret: "s3cret"},
	})
	require.Error(t, err)
}

func TestNew_RefusesKeysOfAnotherIssuer(t *testing.T) {
	idp := newIDP(t)
	_, err := oauthrs.New(oauthrs.Config{
		Issuer: "https://auth.example", Audience: audience, Keys: oidcrp.NewKeySource(idp.Issuer(), idp.Client()),
	})
	require.Error(t, err, "RFC 9068 §4: the signing keys are the configured issuer's")
}

func TestVerify_PrecheckRefusesLocally(t *testing.T) {
	idp := newIDP(t)
	idp.Introspector("notes-rs", "s3cret")
	idp.Opaque("othra_pt_live", map[string]any{"sub": "u", "aud": audience, "exp": now.Add(time.Hour).Unix()})
	v := newVerifier(t, idp, func(c *oauthrs.Config) {
		withIntrospection(time.Minute)(c)
		c.Introspection.Precheck = func(tok string) bool { return tok == "othra_pt_live" }
	})
	for range 3 {
		_, err := v.Verify(context.Background(), "othra_pt_random")
		assert.True(t, oauthrs.IsInvalidTokenError(err), "%v", err)
	}
	assert.Zero(t, idp.Introspections(), "a token in the wrong format never reaches the issuer")
	_, err := v.Verify(context.Background(), "othra_pt_live")
	require.NoError(t, err)
	assert.Equal(t, 1, idp.Introspections())
}

func TestVerify_RefusedAnswerCachedBriefly(t *testing.T) {
	idp := newIDP(t)
	idp.Introspector("notes-rs", "s3cret")
	clock := now
	v := newVerifier(t, idp, withIntrospection(-1)).WithClock(func() time.Time { return clock })
	for range 3 {
		_, err := v.Verify(context.Background(), "othra_pt_unknown")
		assert.True(t, oauthrs.IsInvalidTokenError(err), "%v", err)
	}
	assert.Equal(t, 1, idp.Introspections(), "RFC 7662 §4: an inactive token stays refused, so its answer is reused even with caching off")
	clock = now.Add(31 * time.Second)
	_, err := v.Verify(context.Background(), "othra_pt_unknown")
	assert.True(t, oauthrs.IsInvalidTokenError(err), "%v", err)
	assert.Equal(t, 2, idp.Introspections(), "a refused answer is reused for 30 s only")
}

func TestVerify_RevokeShowsAtOnceWithCacheOff(t *testing.T) {
	idp := newIDP(t)
	idp.Introspector("notes-rs", "s3cret")
	idp.Opaque("othra_pt_live", map[string]any{"sub": "u", "aud": audience, "exp": now.Add(time.Hour).Unix()})
	v := newVerifier(t, idp, withIntrospection(-1))
	_, err := v.Verify(context.Background(), "othra_pt_live")
	require.NoError(t, err)
	idp.Revoke("othra_pt_live")
	_, err = v.Verify(context.Background(), "othra_pt_live")
	assert.True(t, oauthrs.IsInvalidTokenError(err), "RFC 7009 §2: a revoked token is refused at once: %v", err)
}

type gatedTransport struct {
	next    http.RoundTripper
	arrived chan struct{}
	release chan struct{}
	once    sync.Once
	calls   atomic.Int32
}

func (g *gatedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == "/introspect" {
		g.calls.Add(1)
		g.once.Do(func() { close(g.arrived) })
		<-g.release
	}
	return g.next.RoundTrip(r)
}

func TestVerify_ConcurrentIntrospectionsShareOneCall(t *testing.T) {
	idp := newIDP(t)
	idp.Introspector("notes-rs", "s3cret")
	idp.Opaque("othra_pt_live", map[string]any{"sub": "u", "aud": audience, "exp": now.Add(time.Hour).Unix()})
	gate := &gatedTransport{next: idp.Client().Transport, arrived: make(chan struct{}), release: make(chan struct{})}
	v := newVerifier(t, idp, withIntrospection(-1), func(c *oauthrs.Config) { c.HTTPClient = &http.Client{Transport: gate} })
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Go(func() { _, errs[i] = v.Verify(context.Background(), "othra_pt_live") })
	}
	<-gate.arrived
	time.Sleep(100 * time.Millisecond)
	close(gate.release)
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, int32(1), gate.calls.Load(), "concurrent calls for one token share one introspection")
}

func TestVerify_IntrospectionBudget(t *testing.T) {
	idp := newIDP(t)
	idp.Introspector("notes-rs", "s3cret")
	idp.Opaque("othra_pt_live", map[string]any{"sub": "u", "aud": audience, "exp": now.Add(time.Hour).Unix()})
	idp.Opaque("othra_pt_other", map[string]any{"sub": "u", "aud": audience, "exp": now.Add(time.Hour).Unix()})
	clock := now
	v := newVerifier(t, idp, func(c *oauthrs.Config) {
		withIntrospection(time.Minute)(c)
		c.Introspection.MaxPerMinute = 1
	}).WithClock(func() time.Time { return clock })
	_, err := v.Verify(context.Background(), "othra_pt_live")
	require.NoError(t, err)

	_, err = v.Verify(context.Background(), "othra_pt_other")
	require.ErrorIs(t, err, oauthrs.ErrIntrospectionBudget)
	assert.False(t, oauthrs.IsInvalidTokenError(err), "a spent budget is the server's limit, never the caller's token")
	_, err = v.Verify(context.Background(), "othra_pt_live")
	require.NoError(t, err, "a cached token keeps working")
	assert.Equal(t, 1, idp.Introspections())

	clock = now.Add(time.Minute)
	_, err = v.Verify(context.Background(), "othra_pt_other")
	require.NoError(t, err, "the budget refills")
}
