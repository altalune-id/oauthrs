package oauthrs

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

type contextKey struct{}

var b64token = regexp.MustCompile(`^[A-Za-z0-9\-._~+/]+=*$`)

// BearerToken reads the RFC 6750 §2.1 header; another scheme is no token, and the query or body is never read (RFC 9700 §2.4).
func BearerToken(r *http.Request) (string, error) {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	scheme, token, _ := strings.Cut(h, " ")
	if h == "" || !strings.EqualFold(scheme, "Bearer") {
		return "", &MissingTokenError{}
	}
	token = strings.TrimSpace(token)
	if !b64token.MatchString(token) {
		return "", &MalformedRequestError{}
	}
	return token, nil
}

// Challenge is the WWW-Authenticate value for err (RFC 6750 §3), naming the resource's RFC 9728 metadata.
func Challenge(metadataURL string, err error) string {
	c := "Bearer resource_metadata=" + strconv.Quote(metadataURL)
	if scope, ok := insufficientScope(err); ok {
		return c + `, error="insufficient_scope", scope=` + strconv.Quote(scope)
	}
	if IsMissingTokenError(err) {
		return c
	}
	if IsMalformedRequestError(err) {
		return c + `, error="invalid_request"`
	}
	return c + `, error="invalid_token"`
}

func insufficientScope(err error) (string, bool) {
	if e, ok := errors.AsType[*InsufficientScopeError](err); ok {
		return e.Scope, true
	}
	return "", false
}

// MiddlewareOption tunes Middleware.
type MiddlewareOption func(*middlewareConfig)

type middlewareConfig struct {
	onError func(*http.Request, error)
}

// OnError reports the failures Middleware answers 503 for, such as an unreachable issuer, so the app can log them; nil is ignored.
func OnError(f func(*http.Request, error)) MiddlewareOption {
	return func(c *middlewareConfig) { c.onError = f }
}

// Middleware verifies each request's bearer token into its context; a refused token is a 401, a malformed header a 400 (RFC 6750 §3.1).
func Middleware(v *Verifier, metadataURL string, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	var cfg middlewareConfig
	for _, o := range opts {
		o(&cfg)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, err := BearerToken(r)
			var tok *Token
			if err == nil {
				tok, err = v.Verify(r.Context(), raw)
			}
			switch {
			case err == nil:
				next.ServeHTTP(w, r.WithContext(WithToken(r.Context(), tok)))
			case IsMalformedRequestError(err):
				w.Header().Set("WWW-Authenticate", Challenge(metadataURL, err))
				w.WriteHeader(http.StatusBadRequest)
			case IsMissingTokenError(err) || IsInvalidTokenError(err):
				w.Header().Set("WWW-Authenticate", Challenge(metadataURL, err))
				w.WriteHeader(http.StatusUnauthorized)
			default:
				if cfg.onError != nil {
					cfg.onError(r, err)
				}
				w.WriteHeader(http.StatusServiceUnavailable)
			}
		})
	}
}

// RequireScope answers 403 insufficient_scope naming every scope unless the token grants them all; with no token it answers 401.
func RequireScope(metadataURL string, scopes ...string) func(http.Handler) http.Handler {
	need := strings.Join(scopes, " ")
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok, ok := FromContext(r.Context())
			switch {
			case !ok:
				w.Header().Set("WWW-Authenticate", Challenge(metadataURL, &MissingTokenError{}))
				w.WriteHeader(http.StatusUnauthorized)
			case !hasAll(tok, scopes):
				w.Header().Set("WWW-Authenticate", Challenge(metadataURL, &InsufficientScopeError{Scope: need}))
				w.WriteHeader(http.StatusForbidden)
			default:
				next.ServeHTTP(w, r)
			}
		})
	}
}

func hasAll(tok *Token, scopes []string) bool {
	for _, s := range scopes {
		if !tok.HasScope(s) {
			return false
		}
	}
	return true
}

// WithToken puts tok in ctx, for a caller that verifies outside Middleware, such as a Connect interceptor.
func WithToken(ctx context.Context, tok *Token) context.Context {
	return context.WithValue(ctx, contextKey{}, tok)
}

// FromContext returns the Token Middleware or WithToken put in ctx.
func FromContext(ctx context.Context) (*Token, bool) {
	tok, ok := ctx.Value(contextKey{}).(*Token)
	return tok, ok
}
