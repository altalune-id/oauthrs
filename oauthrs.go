package oauthrs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/altalune-id/oidcrp"
	"github.com/go-jose/go-jose/v4"
)

const (
	defaultClockSkew = 30 * time.Second
	maxTokenBytes    = 16 << 10
)

// Config is one resource server at one issuer.
type Config struct {
	// Issuer is the authorization server's issuer; its discovery document names the JWKS and the introspection endpoint.
	Issuer string
	// Audience is this resource server's identifier, which an access token's aud must contain (RFC 8707, RFC 9068 §4).
	Audience string
	// HTTPClient reaches the issuer; it should refuse redirects and private hosts. Ignored when Keys is set.
	HTTPClient *http.Client
	// Keys is the issuer's discovery and JWKS cache, shared by the resource servers of one app; nil builds one.
	Keys      *oidcrp.KeySource
	ClockSkew time.Duration
	// Introspection, when set, accepts opaque tokens (RFC 7662) such as personal tokens.
	Introspection *Introspection
}

// Token is what a verified access token says about the call.
type Token struct {
	Issuer    string
	Subject   string
	ClientID  string
	Scopes    []string
	JWTID     string
	SessionID string
	ExpiresAt time.Time
	// Personal reports an opaque token accepted through introspection, such as a personal token; it names no client.
	Personal bool
}

// HasScope reports whether the token grants scope.
func (t *Token) HasScope(scope string) bool { return slices.Contains(t.Scopes, scope) }

// Verifier checks the bearer tokens of one resource server; safe for concurrent use.
type Verifier struct {
	cfg   Config
	keys  *oidcrp.KeySource
	now   func() time.Time
	cache *introspectionCache
}

// New builds a Verifier; Issuer and Audience are required.
func New(cfg Config) (*Verifier, error) {
	switch {
	case cfg.Issuer == "":
		return nil, errors.New("oauthrs: an issuer is required")
	case cfg.Audience == "":
		return nil, errors.New("oauthrs: an audience is required")
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = defaultClockSkew
	}
	keys := cfg.Keys
	if keys == nil {
		keys = oidcrp.NewKeySource(cfg.Issuer, cfg.HTTPClient)
	}
	return &Verifier{cfg: cfg, keys: keys, now: time.Now, cache: newIntrospectionCache()}, nil
}

// WithClock replaces the clock, for tests.
func (v *Verifier) WithClock(now func() time.Time) *Verifier {
	v.now = now
	return v
}

// Keys is the issuer's key source, to share with another resource server of the same app.
func (v *Verifier) Keys() *oidcrp.KeySource { return v.keys }

// Verify checks bearer: an RFC 9068 JWT, or an opaque token through introspection; a refused token is an *InvalidTokenError.
func (v *Verifier) Verify(ctx context.Context, bearer string) (*Token, error) {
	switch {
	case bearer == "" || len(bearer) > maxTokenBytes:
		return nil, invalid("empty or too long")
	case strings.Count(bearer, ".") == 2:
		return v.verifyJWT(ctx, bearer)
	case v.cfg.Introspection != nil:
		return v.introspect(ctx, bearer)
	}
	return nil, invalid("opaque token without introspection")
}

type accessClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  audience `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	ClientID  string   `json:"client_id"`
	JWTID     string   `json:"jti"`
	Scope     string   `json:"scope"`
	SessionID string   `json:"sid"`
}

// SECURITY: RFC 9068 §4: typ at+jwt is pinned, so an ID token never passes; a published key, an allowed alg, iss, aud, exp, iat, nbf.
func (v *Verifier) verifyJWT(ctx context.Context, raw string) (*Token, error) {
	meta, err := v.keys.Metadata(ctx)
	if err != nil {
		return nil, fmt.Errorf("oauthrs: issuer metadata: %w", err)
	}
	jws, err := jose.ParseSigned(raw, meta.SigningAlgorithms())
	if err != nil || len(jws.Signatures) != 1 {
		return nil, &InvalidTokenError{Reason: "not a single-signature JWS with an allowed alg", Err: err}
	}
	header := jws.Signatures[0].Header
	if !oidcrp.IsAccessTokenType(header) {
		return nil, invalid("typ is not at+jwt")
	}
	key, err := v.keys.Key(ctx, header.KeyID)
	switch {
	case oidcrp.ReasonOf(err) == oidcrp.ReasonIDToken:
		return nil, &InvalidTokenError{Reason: "unknown kid", Err: err}
	case err != nil:
		return nil, fmt.Errorf("oauthrs: issuer keys: %w", err)
	case key.Algorithm != "" && key.Algorithm != header.Algorithm:
		return nil, invalid("the key's alg is not the token's")
	}
	payload, err := jws.Verify(key)
	if err != nil {
		return nil, &InvalidTokenError{Reason: "signature", Err: err}
	}
	var cl accessClaims
	if err := json.Unmarshal(payload, &cl); err != nil {
		return nil, &InvalidTokenError{Reason: "claims", Err: err}
	}
	if err := v.checkJWT(cl); err != nil {
		return nil, err
	}
	return &Token{
		Issuer: cl.Issuer, Subject: cl.Subject, ClientID: cl.ClientID, Scopes: strings.Fields(cl.Scope), JWTID: cl.JWTID,
		SessionID: cl.SessionID, ExpiresAt: time.Unix(cl.ExpiresAt, 0),
	}, nil
}

func (v *Verifier) checkJWT(cl accessClaims) error {
	now, skew := v.now(), v.cfg.ClockSkew
	switch {
	case cl.Issuer != v.cfg.Issuer:
		return invalid("iss does not match")
	case !slices.Contains(cl.Audience, v.cfg.Audience):
		return invalid("aud does not name this resource")
	case cl.ExpiresAt == 0:
		return invalid("no exp")
	case !now.Before(time.Unix(cl.ExpiresAt, 0).Add(skew)):
		return &InvalidTokenError{Reason: "expired", Err: &ExpiredTokenError{}}
	case cl.IssuedAt == 0 || time.Unix(cl.IssuedAt, 0).After(now.Add(skew)):
		return invalid("iat is missing or in the future")
	case cl.NotBefore != 0 && time.Unix(cl.NotBefore, 0).After(now.Add(skew)):
		return invalid("not yet valid")
	case cl.Subject == "" || cl.ClientID == "" || cl.JWTID == "":
		return invalid("sub, client_id or jti is missing")
	}
	return nil
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}
