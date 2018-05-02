package hrauth0

import (
	"net/http"

	"gopkg.in/square/go-jose.v2/jwt"
	"strings"
	"errors"
	"gopkg.in/square/go-jose.v2"
	"sync"
	"encoding/json"
	"time"
)

var (
	ErrTokenNotFound      = errors.New("token not found")
	ErrInvalidAlgorithm   = errors.New("only RS256 is supported")
	ErrNoJWTHeaders       = errors.New("no headers in the token")
	ErrInvalidContentType = errors.New("should have a JSON content type for JWKS endpoint")
	ErrNoKeyFound         = errors.New("no Keys has been found")
)

type keyStore struct {
	store map[string]jose.JSONWebKey
	sync.RWMutex
}

type JWKS struct {
	Keys []jose.JSONWebKey `json:"keys"`
}

type Claims struct {
	jwt.Claims
	Scope string `json:"scope"`
}

func newKeyStore() keyStore {
	return keyStore{
		store: make(map[string]jose.JSONWebKey),
	}
}

func (au *Auth0) getClaims(r *http.Request) (*Claims, error) {
	token, err := extractToken(r)
	if err != nil {
		return nil, err
	}

	if len(token.Headers) < 1 {
		return nil, ErrNoJWTHeaders
	}

	header := token.Headers[0]
	if header.Algorithm != string(au.signingMethod) {
		return nil, ErrInvalidAlgorithm
	}

	claims := &Claims{}
	key, err := au.getKey(header.KeyID)
	if err != nil {
		return nil, err
	}

	if err = token.Claims(key, claims); err != nil {
		return nil, err
	}

	expected := au.expectedClaims.WithTime(time.Now())
	err = claims.Validate(expected)

	if err != nil {
		return nil, err
	}

	return claims, nil
}

// extractToken looks for jwt token in request header
func extractToken(r *http.Request) (*jwt.JSONWebToken, error) {
	raw := ""
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[0:7], "BEARER ") {
		raw = h[7:]
	}

	if raw == "" {
		return nil, ErrTokenNotFound
	}

	return jwt.ParseSigned(raw)
}

func (au *Auth0) getKey(id string) (jose.JSONWebKey, error) {
	au.keyStore.RLock()
	searchedKey, exist := au.keyStore.store[id]
	au.keyStore.RUnlock()

	if !exist {
		if keys, err := au.downloadKeys(); err != nil {
			return jose.JSONWebKey{}, err
		} else {
			au.keyStore.Lock()
			for _, key := range keys {
				au.keyStore.store[key.KeyID] = key

				if key.KeyID == id {
					searchedKey = key
					exist = true
				}
			}
			au.keyStore.Unlock()
		}
	}

	if exist {
		return searchedKey, nil
	}

	return jose.JSONWebKey{}, ErrNoKeyFound
}

func (au *Auth0) downloadKeys() ([]jose.JSONWebKey, error) {
	r, err := http.Get(au.jwksURI)

	if err != nil {
		return []jose.JSONWebKey{}, err
	}
	defer r.Body.Close()

	if header := r.Header.Get("Content-Type"); !strings.HasPrefix(header, "application/json") {
		return []jose.JSONWebKey{}, ErrInvalidContentType
	}

	var jwks = JWKS{}
	err = json.NewDecoder(r.Body).Decode(&jwks)

	if err != nil {
		return []jose.JSONWebKey{}, err
	}

	if len(jwks.Keys) < 1 {
		return []jose.JSONWebKey{}, ErrNoKeyFound
	}

	return jwks.Keys, nil
}
