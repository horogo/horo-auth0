package hrauth0

import (
	"net/http"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"github.com/horogo/horo-log"
	"github.com/horogo/horo"
	"strings"
	"context"
)

type Auth0 struct {
	jwksURI        string
	signingMethod  jose.SignatureAlgorithm
	expectedClaims jwt.Expected

	keyStore keyStore
	log      *hrlog.Logger
}

// New creates a new Auth0. The audience, issuer,
// cert variables are set accordingly to which
// provided by Auth0
func New(audience []string, issuer string, jwksURI string) *Auth0 {
	assert1(audience != nil, "audience cannot be nil")
	assert1(issuer != "", "issuer cannot be empty")
	assert1(jwksURI != "", "cert cannot be empty")
	auth := &Auth0{
		expectedClaims: jwt.Expected{
			Issuer:   issuer,
			Audience: audience,
		},
		jwksURI:       jwksURI,
		signingMethod: jose.RS256,
		keyStore:      newKeyStore(),
		log:           hrlog.New(),
	}
	auth.log.SetPrefix("[HORO-AUTH0]")
	return auth
}

// Handler return a Horo Handler middleware
func (au *Auth0) Handler() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := au.getClaims(r)
			if err != nil {
				au.log.Errorln("Cannot extract claims:", err)
				http.Error(w, "cannot extract auth claims", http.StatusUnauthorized)
			} else {
				au.log.Debugln("Subject:", claims.Subject)
				au.log.Debugln("Scope:", claims.Scope)

				ac := horo.Authentication{
					Authenticated: true,
					Subject:       claims.Subject,
					Authorities:   strings.Split(claims.Scope, " "),
				}

				r := r.WithContext(context.WithValue(r.Context(), horo.AuthKey, ac))

				next.ServeHTTP(w, r)
			}
		})
	}
}
