package auth

import (
	"github.com/anoaland/xgo/auth"
	"github.com/golang-jwt/jwt/v5"
)

type BasicUser struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func (u *BasicUser) AsAppUser() *auth.AppUser {
	return &auth.AppUser{
		Username: u.Username,
	}
}
