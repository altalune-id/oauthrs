package oauthrs_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/altalune-id/oidcrp/oidcrptest"

	"github.com/altalune-id/oauthrs"
)

func ExampleMiddleware() {
	idp := oidcrptest.Start()
	defer idp.Close()

	const resource = "https://notes.example/mcp"
	v, err := oauthrs.New(oauthrs.Config{Issuer: idp.Issuer(), Audience: resource, HTTPClient: idp.Client()})
	if err != nil {
		panic(err)
	}
	metadata, err := oauthrs.MetadataURL(resource)
	if err != nil {
		panic(err)
	}
	tool := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, _ := oauthrs.FromContext(r.Context())
		fmt.Fprint(w, "hello ", tok.Subject)
	})
	h := oauthrs.Middleware(v, metadata)(oauthrs.RequireScope(metadata, "notes:read")(tool))

	for _, bearer := range []string{"", idp.AccessToken(map[string]any{"aud": resource, "scope": "notes:read"})} {
		r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		fmt.Println(w.Code, w.Header().Get("WWW-Authenticate")+w.Body.String())
	}
	// Output:
	// 401 Bearer resource_metadata="https://notes.example/.well-known/oauth-protected-resource/mcp"
	// 200 hello 110169484474386276334
}
