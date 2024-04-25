package auth

import (
	"encoding/json"
	"fmt"
	"hash"
	"log"

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
		log.Println("method", token.Method, "===", c.method)

		if token.Method != c.method {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		secret := []byte(c.jwtSecret)
		return secret, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("claims not found")
	}

	// Create a new instance of T
	user := new(T)
	claimsBytes, _ := json.Marshal(claims)  // Marshal the claims into JSON bytes
	err = json.Unmarshal(claimsBytes, user) // Unmarshal the JSON bytes into the user instance
	if err != nil {
		return nil, err
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
		return nil, err
	}
	json.Unmarshal(userBytes, &userMap)
	for key, value := range userMap {
		claims[key] = value
	}

	log.Printf("USER %v", userMap)
	log.Printf("APA %v", claims)

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
