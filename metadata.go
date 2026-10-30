package oauthrs

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// WellKnownPath is the RFC 9728 §3 well-known path, inserted between a resource identifier's host and its path.
const WellKnownPath = "/.well-known/oauth-protected-resource"

// ProtectedResource is the RFC 9728 §2 metadata a resource server publishes and an authorization server checks.
type ProtectedResource struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	// Extra holds further metadata parameters (RFC 9728 §2), such as an app's public CLI client id; it never overrides the ones above.
	Extra map[string]any `json:"-"`
}

func isStandardMember(key string) bool {
	switch key {
	case "resource", "authorization_servers", "scopes_supported", "bearer_methods_supported":
		return true
	}
	return false
}

// MetadataURL is where the RFC 9728 §3.1 metadata of resource lives: the well-known path between its host and its path, its query kept.
func MetadataURL(resource string) (string, error) {
	u, err := url.Parse(resource)
	switch {
	case err != nil:
		return "", errors.New("oauthrs: the resource is not a URL")
	case u.Scheme != "https" && u.Scheme != "http" || u.Host == "":
		return "", errors.New("oauthrs: the resource is not an absolute http(s) URL")
	case u.Fragment != "" || strings.Contains(resource, "#"):
		return "", errors.New("oauthrs: the resource carries a fragment")
	}
	out := u.Scheme + "://" + u.Host + WellKnownPath + strings.TrimSuffix(u.EscapedPath(), "/")
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out, nil
}

// MetadataHandler serves pr. SECURITY: unauthenticated by design, as a client reads it before it holds a token.
func MetadataHandler(pr ProtectedResource) http.Handler {
	if len(pr.BearerMethodsSupported) == 0 {
		pr.BearerMethodsSupported = []string{"header"}
	}
	body, err := marshalMetadata(pr)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method != http.MethodGet && r.Method != http.MethodHead:
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		case err != nil:
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = w.Write(body)
	})
}

func marshalMetadata(pr ProtectedResource) ([]byte, error) {
	base, err := json.Marshal(pr)
	if err != nil || len(pr.Extra) == 0 {
		return base, err
	}
	var doc map[string]any
	if err := json.Unmarshal(base, &doc); err != nil {
		return nil, err
	}
	for k, v := range pr.Extra {
		if !isStandardMember(k) {
			doc[k] = v
		}
	}
	return json.Marshal(doc)
}

// ParseProtectedResource reads an RFC 9728 document. NOTE: only the exact keys count, as encoding/json would match "Resource" to resource.
func ParseProtectedResource(body []byte) (ProtectedResource, error) {
	var doc map[string]json.RawMessage
	if !bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) || json.Unmarshal(body, &doc) != nil {
		return ProtectedResource{}, errors.New("oauthrs: the metadata is not a JSON object")
	}
	var pr ProtectedResource
	for key, raw := range doc {
		var dst any
		switch key {
		case "resource":
			dst = &pr.Resource
		case "authorization_servers":
			dst = &pr.AuthorizationServers
		case "scopes_supported":
			dst = &pr.ScopesSupported
		case "bearer_methods_supported":
			dst = &pr.BearerMethodsSupported
		default:
			var v any
			_ = json.Unmarshal(raw, &v)
			if pr.Extra == nil {
				pr.Extra = map[string]any{}
			}
			pr.Extra[key] = v
			continue
		}
		if json.Unmarshal(raw, dst) != nil {
			return ProtectedResource{}, errors.New("oauthrs: the metadata field " + key + " has the wrong type")
		}
	}
	return pr, nil
}
