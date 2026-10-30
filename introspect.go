package oauthrs

import (
	"cmp"
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
	refusedTTL              = 30 * time.Second
	defaultIntrospectionTO  = 10 * time.Second
	maxCachedTokens         = 10_000
	maxResponseBytes        = 1 << 20
)

// ErrIntrospectionBudget signals that Introspection.MaxPerMinute is spent; it is the server's limit, never the caller's token.
var ErrIntrospectionBudget = errors.New("oauthrs: introspection budget exhausted")

// Introspection is this resource server's registration at the issuer's RFC 7662 introspection endpoint.
type Introspection struct {
	ClientID     string
	ClientSecret string
	// TokenPrefix is the issuer's opaque-token prefix, such as Othra's "othra_pt_"; only tokens that start with it are introspected.
	TokenPrefix string
	// CacheTTL bounds how long an active answer is reused, never past the token's exp: 0 means 30 s, at most 60 s, negative turns it off.
	// A refused answer, such as inactive, is reused for 30 s whatever CacheTTL says, since a refused token never turns active.
	CacheTTL time.Duration
	// Precheck, when set, refuses a prefixed token locally, with no introspection call, unless it has the issuer's token format.
	// For Othra: the prefix, 43 base62 characters, then a 6-character base62 CRC32 checksum of them.
	Precheck func(token string) bool
	// MaxPerMinute, when positive, caps introspection calls for all tokens together; pair it with per-client rate limiting.
	MaxPerMinute int
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

// NOTE: concurrent calls for one token share one introspection, which outlives a caller that gives up.
func (v *Verifier) introspect(ctx context.Context, raw string) (*Token, error) {
	sum := sha256.Sum256([]byte(raw))
	now := v.now()
	if tok, ok := v.cache.get(sum, now); ok {
		return tok, nil
	}
	if _, ok := v.refused.get(sum, now); ok {
		return nil, invalid("introspection refused it recently")
	}
	ch := v.flights.DoChan(string(sum[:]), func() (any, error) {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cmp.Or(v.keys.HTTPClient().Timeout, defaultIntrospectionTO))
		defer cancel()
		return v.introspectOnce(fctx, sum, raw)
	})
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("oauthrs: introspection: %w", ctx.Err())
	case r := <-ch:
		tok, _ := r.Val.(*Token)
		return tok, r.Err
	}
}

func (v *Verifier) introspectOnce(ctx context.Context, sum [sha256.Size]byte, raw string) (*Token, error) {
	if !v.budget.take(v.now()) {
		return nil, ErrIntrospectionBudget
	}
	ans, err := v.askIntrospection(ctx, raw)
	if err != nil {
		return nil, err
	}
	now := v.now()
	tok, err := v.accept(ans, now)
	if err != nil {
		v.refused.put(sum, nil, now.Add(refusedTTL))
		return nil, err
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

// SECURITY: RFC 7662 §4: an answer counts only when active and it names this issuer, this resource and a live subject.
func (v *Verifier) accept(ans *introspectionAnswer, now time.Time) (*Token, error) {
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
	return &Token{
		Issuer: v.cfg.Issuer, Subject: ans.Subject, ClientID: ans.ClientID, Scopes: strings.Fields(ans.Scope),
		ExpiresAt: time.Unix(ans.ExpiresAt, 0), Personal: true,
	}, nil
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

// NOTE: keyed by the token's hash and bounded in size; a full cache evicts one entry.
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

type budget struct {
	rate float64

	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func newBudget(perMinute int) *budget {
	return &budget{rate: float64(max(perMinute, 0)), tokens: float64(max(perMinute, 0))}
}

func (b *budget) take(now time.Time) bool {
	if b.rate == 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.After(b.last) && !b.last.IsZero() {
		b.tokens = min(b.rate, b.tokens+b.rate*now.Sub(b.last).Minutes())
	}
	if now.After(b.last) {
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
