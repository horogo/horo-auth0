package hrauth0

import (
	"sync"
	"net/http"
	"github.com/dgrijalva/jwt-go"
	"strings"
	"errors"
	"log"
)

type certStore struct {
	store      map[string]string
	sync.RWMutex
}

type JWKS struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

type Claims struct {
	jwt.StandardClaims
	Scope string `json:"scope"`
	Audience []string `json:"aud"`
}

func (au *Auth0) checkJWT(r *http.Request) (*jwt.Token, error) {
	// Use the specified token extractor to extract a token from the request
	token, err := extractToken(r);


	if err != nil {
		au.debugf("Error extracting JWT: %v\n", err)
		return nil, err
	}

	// If the token is empty...
	if token == "" {
		msg := "required authorization token not found"
		au.debugf(msg)
		return nil, errors.New("required authorization token not found")
	}

	// Now parse the token
	parsedToken, err := jwt.ParseWithClaims(token, &Claims{}, validationKeyGetter)


}

func (au *Auth0) validationKeyGetter(token *jwt.Token) (interface{}, error) {
	claims := token.Claims.(*Claims)

	aud := config.JWTAudience
	if !claims.VerifyAudience(aud, false) {
		return token, errors.New("Invalid audience")
	}

	iss := config.JWTIssuer
	if !claims.VerifyIssuer(iss, false) {
		return token, errors.New("Invalid issuer")
	}

	cert, err := getPermCert(token)
	if err != nil {
		log.Fatalln("Cannot get auth certificate:", err)
	}

	result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
	return result, nil
}

func extractToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", nil // No error, just no token
	}

	// TODO: Make this a bit more robust, parsing-wise
	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", errors.New("Authorization header format must be Bearer {token}")
	}

	return authHeaderParts[1], nil
}
