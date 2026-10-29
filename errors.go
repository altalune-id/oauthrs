package oauthrs

import "errors"

// MissingTokenError signals a request with no bearer token.
type MissingTokenError struct{}

func (*MissingTokenError) Error() string { return "oauthrs: no bearer token" }

// InvalidTokenError signals a token this resource server must refuse; Reason is for logs, never for the caller.
type InvalidTokenError struct {
	Reason string
	Err    error
}

func (e *InvalidTokenError) Error() string { return "oauthrs: invalid token: " + e.Reason }

func (e *InvalidTokenError) Unwrap() error { return e.Err }

// MalformedRequestError signals a Bearer Authorization header that is not a valid RFC 6750 §2.1 credential.
type MalformedRequestError struct{}

func (*MalformedRequestError) Error() string { return "oauthrs: malformed Bearer Authorization header" }

// ExpiredTokenError signals a token past its exp; it always comes wrapped in an *InvalidTokenError.
type ExpiredTokenError struct{}

func (*ExpiredTokenError) Error() string { return "oauthrs: token expired" }

// InsufficientScopeError signals a valid token without the scopes a call needs; Scope lists them space-separated.
type InsufficientScopeError struct {
	Scope string
}

func (e *InsufficientScopeError) Error() string { return "oauthrs: missing scope " + e.Scope }

// IsMissingTokenError reports whether err's tree holds a *MissingTokenError.
func IsMissingTokenError(err error) bool {
	_, ok := errors.AsType[*MissingTokenError](err)
	return ok
}

// IsInvalidTokenError reports whether err's tree holds an *InvalidTokenError.
func IsInvalidTokenError(err error) bool {
	_, ok := errors.AsType[*InvalidTokenError](err)
	return ok
}

// IsMalformedRequestError reports whether err's tree holds a *MalformedRequestError.
func IsMalformedRequestError(err error) bool {
	_, ok := errors.AsType[*MalformedRequestError](err)
	return ok
}

// IsExpiredTokenError reports whether err's tree holds an *ExpiredTokenError.
func IsExpiredTokenError(err error) bool {
	_, ok := errors.AsType[*ExpiredTokenError](err)
	return ok
}

// IsInsufficientScopeError reports whether err's tree holds an *InsufficientScopeError.
func IsInsufficientScopeError(err error) bool {
	_, ok := errors.AsType[*InsufficientScopeError](err)
	return ok
}

func invalid(reason string) error { return &InvalidTokenError{Reason: reason} }
