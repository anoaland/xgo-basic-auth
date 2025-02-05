package auth

import (
	"encoding/json"
	"fmt"
	"hash"

	// errors "github.com/anoaland/xgo/errors"
	"github.com/anoaland/xgo"
	"github.com/golang-jwt/jwt/v5"
)

type BasicAuthStorage interface {
	StoreUserRefreshToken(userId any, token string)
	GetUserRefreshToken(userId any)
}

type BasicAuthJWT struct {
	AccessToken  string
	RefreshToken string
}

type BasicAuthPasswordConfig struct {
	Iterations  int
	PassLen     int
	SaltLen     int
	Hash        func() hash.Hash
	HexEncoding bool
}

type BasicAuthClient[T interface{}] struct {
	jwtSecret       string
	jwtAudience     string
	jwtIssuer       string
	method          jwt.SigningMethod
	jwtSignatureKey []byte
	passwordConfig  BasicAuthPasswordConfig
}

func New[T interface{}](method jwt.SigningMethod,
	jwtSecret string,
	jwtAudience string,
	jwtIssuer string,
	passwordConfig BasicAuthPasswordConfig) *BasicAuthClient[T] {
	jwtSignatureKey := []byte(jwtSecret)
	return &BasicAuthClient[T]{
		jwtSecret:       jwtSecret,
		jwtAudience:     jwtAudience,
		jwtIssuer:       jwtIssuer,
		method:          method,
		jwtSignatureKey: jwtSignatureKey,
		passwordConfig:  passwordConfig,
	}
}

func (c BasicAuthClient[T]) GetUserFromToken(token string) (any, error) {
	return c.GetBasicUserFromToken(token)
}

func (c BasicAuthClient[T]) GetBasicUserFromToken(tokenString string) (*T, error) {

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {

		if token.Method != c.method {
			return nil, xgo.NewHttpUnauthorizedError("WEB_AUTH_CLIENT__GetBasicUserFromToken", fmt.Errorf("unexpected signing method: %v", token.Header["alg"]))
		}

		secret := []byte(c.jwtSecret)
		return secret, nil
	})

	if err != nil {
		return nil, xgo.NewHttpUnauthorizedError("WEB_AUTH_CLIENT__GetBasicUserFromToken", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, xgo.NewHttpUnauthorizedError("WEB_AUTH_CLIENT__GetBasicUserFromToken__claims_not_found", err)
	}

	// Create a new instance of T
	user := new(T)
	claimsBytes, _ := json.Marshal(claims)  // Marshal the claims into JSON bytes
	err = json.Unmarshal(claimsBytes, user) // Unmarshal the JSON bytes into the user instance
	if err != nil {
		return nil, xgo.NewHttpInternalError("WEB_AUTH_CLIENT__GetBasicUserFromToken__JSONUnmarshal", err)
	}

	return user, nil
}

func (c BasicAuthClient[T]) SignIn(user T) (*BasicAuthJWT, error) {

	claims := jwt.MapClaims{
		"iss": c.jwtIssuer,
		"aud": c.jwtAudience,
	}

	userMap := make(map[string]interface{})
	userBytes, err := json.Marshal(user)
	if err != nil {
		return nil, xgo.NewHttpInternalError("WEB_AUTH_CLIENT__SignIn__Marshal", err)
	}

	err = json.Unmarshal(userBytes, &userMap)
	if err != nil {
		return nil, xgo.NewHttpInternalError("WEB_AUTH_CLIENT__SignIn__Unmarshal", err)
	}

	for key, value := range userMap {
		claims[key] = value
	}

	token := jwt.NewWithClaims(c.method, claims)
	tokenString, err := token.SignedString(c.jwtSignatureKey)
	if err != nil {
		return nil, xgo.NewHttpInternalError("WEB_AUTH_CLIENT__SignIn__SignedString", err)
	}

	res := BasicAuthJWT{
		AccessToken:  tokenString,
		RefreshToken: tokenString,
	}

	return &res, nil
}

// func (c BasicAuthClient) RefreshToken(refreshToken string) (*BasicAuthJWT, error) {

// }
