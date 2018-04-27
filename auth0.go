package auth0

type Auth0 struct {
	audience, issuer, cert string

	// If enabled, print additional log info
	debug bool

	// The minimum interval in seconds for JWKS to refresh
	certRefreshRate        uint
}

// New creates a new Auth0. The audience, issuer,
// cert variables are set accordingly to which
// provided by Auth0
func New(audience, issuer, cert string) *Auth0 {
	assert1(audience != "", "audience cannot be empty")
	assert1(issuer != "", "issuer cannot be empty")
	assert1(cert != "", "cert cannot be empty")
	return &Auth0{
		audience:        audience,
		issuer:          issuer,
		cert:            cert,
		debug:           false,
		certRefreshRate: 60,
	}
}

// SetDebug turns turn debug logging on or off
func (au *Auth0) SetDebug(value bool) {
	au.debug = value
	au.debugPrint("Set debug to %t\n", value)
}

// SetCertRefreshRate sets the minimum interval
// in seconds for JWKS to refresh
func (au *Auth0) SetCertRefreshRate(value uint) {
	au.certRefreshRate = value
	au.debugPrint("Set CertRefreshRate to %t\n", value)
}