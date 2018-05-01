package hrauth0

import (
	"net/http"
	"github.com/dgrijalva/jwt-go"
)

type Auth0 struct {
	audience   []string
	issuer     string
	jwkCertURI string
	signingMethod jwt.SigningMethod

	debug bool
	certs certStore
}

// New creates a new Auth0. The audience, issuer,
// cert variables are set accordingly to which
// provided by Auth0
func New(audience []string, issuer string, jwkCertURI string) *Auth0 {
	assert1(audience != nil, "audience cannot be nil")
	assert1(issuer != "", "issuer cannot be empty")
	assert1(jwkCertURI != "", "cert cannot be empty")
	return &Auth0{
		audience:   audience,
		issuer:     issuer,
		jwkCertURI: jwkCertURI,
		debug:      false,
		certs: certStore{
			store: make(map[string]string),
		},
		signingMethod: jwt.SigningMethodRS256,
	}
}

// SetDebug turns turn debug logging on or off
func (au *Auth0) SetDebug(value bool) {
	au.debug = value
	au.debugf("Set debug to %t\n", value)
}

// Handler return a Horo Handler middleware
func (au *Auth0) Handler() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		})
	}
}