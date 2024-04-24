package auth

import (
	"fmt"
	"hash"

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

type BasicAuthClient struct {
	jwtSecret       string
	jwtAudience     string
	jwtIssuer       string
	method          jwt.SigningMethod
	jwtSignatureKey []byte
	passwordConfig  BasicAuthPasswordConfig
}

func New(method jwt.SigningMethod,
	jwtSecret string,
	jwtAudience string,
	jwtIssuer string,
	passwordConfig BasicAuthPasswordConfig) *BasicAuthClient {
	jwtSignatureKey := []byte(jwtSecret)
	return &BasicAuthClient{
		jwtSecret:       jwtSecret,
		jwtAudience:     jwtAudience,
		jwtIssuer:       jwtIssuer,
		method:          method,
		jwtSignatureKey: jwtSignatureKey,
		passwordConfig:  passwordConfig,
	}
}

func (c BasicAuthClient) GetUserFromToken(token string) (any, error) {
	return c.GetBasicUserFromToken(token)
}

func (c BasicAuthClient) GetBasicUserFromToken(token string) (*BasicUser, error) {
	u := BasicUser{}
	_, err := jwt.ParseWithClaims(token, &u, func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("signing method invalid")
		} else if method != c.method {
			return nil, fmt.Errorf("signing method invalid")
		}

		return c.jwtSignatureKey, nil
	})

	if err != nil {
		return nil, err
	}

	return &u, nil
}

func (c BasicAuthClient) SignIn(user BasicUser) (*BasicAuthJWT, error) {

	claims := &user
	claims.Issuer = c.jwtIssuer
	claims.Audience = []string{c.jwtAudience}

	token := jwt.NewWithClaims(c.method, claims)
	tokenString, err := token.SignedString(c.jwtSignatureKey)

	if err != nil {
		return nil, err
	}

	res := BasicAuthJWT{
		AccessToken:  tokenString,
		RefreshToken: tokenString,
	}

	return &res, nil
}

// func (c BasicAuthClient) RefreshToken(refreshToken string) (*BasicAuthJWT, error) {

// }
