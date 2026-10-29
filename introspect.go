package oauthrs

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	defaultIntrospectionTTL = 30 * time.Second
	maxIntrospectionTTL     = time.Minute
	maxCachedTokens         = 10_000
	maxResponseBytes        = 1 << 20
)

// Introspection is this resource server's registration at the issuer's RFC 7662 introspection endpoint.
type Introspection struct {
	ClientID     string
	ClientSecret string
	// TokenPrefix is the issuer's opaque-token prefix, such as Othra's "othra_pt_"; only tokens that start with it are introspected.
	TokenPrefix string
	// CacheTTL bounds how long an active answer is reused, never past the token's exp: 0 means 30 s, at most 60 s, negative turns it off.
	// Inactive answers are never cached.
	CacheTTL time.Duration
}

type introspectionAnswer struct {
	Active    bool     `json:"active"`
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  audience `json:"aud"`
	ClientID  string   `json:"client_id"`
	Scope     string   `json:"scope"`
	ExpiresAt int64    `json:"exp"`
}

// SECURITY: RFC 7662 §4: an answer counts only when active and it names this issuer, this resource and a live subject.
func (v *Verifier) introspect(ctx context.Context, raw string) (*Token, error) {
	sum := sha256.Sum256([]byte(raw))
	now := v.now()
	if tok, ok := v.cache.get(sum, now); ok {
		return tok, nil
	}
	ans, err := v.askIntrospection(ctx, raw)
	if err != nil {
		return nil, err
	}
	switch {
	case !ans.Active:
		return nil, invalid("introspection says inactive")
	case ans.Issuer != "" && ans.Issuer != v.cfg.Issuer:
		return nil, invalid("introspection names another issuer")
	case !slices.Contains(ans.Audience, v.cfg.Audience):
		return nil, invalid("introspection names another resource")
	case ans.Subject == "":
		return nil, invalid("introspection names no subject")
	case ans.ExpiresAt == 0 || !now.Before(time.Unix(ans.ExpiresAt, 0)):
		return nil, &InvalidTokenError{Reason: "expired", Err: &ExpiredTokenError{}}
	}
	tok := &Token{
		Issuer: v.cfg.Issuer, Subject: ans.Subject, ClientID: ans.ClientID, Scopes: strings.Fields(ans.Scope),
		ExpiresAt: time.Unix(ans.ExpiresAt, 0), Personal: true,
	}
	ttl := v.cfg.Introspection.CacheTTL
	switch {
	case ttl < 0:
		return tok, nil
	case ttl == 0:
		ttl = defaultIntrospectionTTL
	case ttl > maxIntrospectionTTL:
		ttl = maxIntrospectionTTL
	}
	until := now.Add(ttl)
	if tok.ExpiresAt.Before(until) {
		until = tok.ExpiresAt
	}
	v.cache.put(sum, tok, until)
	return tok, nil
}

func (v *Verifier) askIntrospection(ctx context.Context, raw string) (*introspectionAnswer, error) {
	meta, err := v.keys.Metadata(ctx)
	switch {
	case err != nil:
		return nil, fmt.Errorf("oauthrs: issuer metadata: %w", err)
	case meta.IntrospectionEndpoint == "":
		return nil, errors.New("oauthrs: the issuer has no introspection endpoint")
	}
	form := url.Values{"token": {raw}}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.IntrospectionEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oauthrs: introspection: %w", err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "application/json")
	r.SetBasicAuth(url.QueryEscape(v.cfg.Introspection.ClientID), url.QueryEscape(v.cfg.Introspection.ClientSecret))
	resp, err := v.keys.HTTPClient().Do(r)
	if err != nil {
		return nil, fmt.Errorf("oauthrs: introspection: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	switch {
	case err != nil:
		return nil, fmt.Errorf("oauthrs: introspection: %w", err)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("oauthrs: introspection answered %d", resp.StatusCode)
	}
	var ans introspectionAnswer
	if err := json.Unmarshal(body, &ans); err != nil {
		return nil, fmt.Errorf("oauthrs: introspection: %w", err)
	}
	return &ans, nil
}

type cachedToken struct {
	tok   *Token
	until time.Time
}

// NOTE: positive answers only, keyed by the token's hash, bounded in size; a full cache drops expired entries or skips caching.
type introspectionCache struct {
	mu      sync.Mutex
	entries map[[sha256.Size]byte]cachedToken
}

func newIntrospectionCache() *introspectionCache {
	return &introspectionCache{entries: map[[sha256.Size]byte]cachedToken{}}
}

func (c *introspectionCache) get(key [sha256.Size]byte, now time.Time) (*Token, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || !now.Before(e.until) {
		delete(c.entries, key)
		return nil, false
	}
	return e.tok, true
}

func (c *introspectionCache) put(key [sha256.Size]byte, tok *Token, until time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[key]; !ok && len(c.entries) >= maxCachedTokens {
		for k := range c.entries {
			delete(c.entries, k)
			break
		}
	}
	c.entries[key] = cachedToken{tok: tok, until: until}
}
