package auth

import (
	"crypto/sha1"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

var passwordConfig BasicAuthPasswordConfig = BasicAuthPasswordConfig{
	Iterations:  1000,
	PassLen:     256,
	SaltLen:     16,
	Hash:        sha1.New,
	HexEncoding: true,
}

func TestBasicAuthClient_GetUserFromToken(t *testing.T) {
	// Set up test data
	jwtSecret := "secret"
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlcm5hbWUiOiJqb2huZG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJhdWQiOiJURVNUX0FVRCIsImlzcyI6IlRFU1RfSVNTIn0.2eyYmOoXFRcN9_YlSfJdrxaPdqZazkY-FzC1NWhB5jM"
	expectedUsername := "johndoe"
	expectedAudience := jwt.ClaimStrings{"TEST_AUD"}
	expectedIssuer := "TEST_ISS"

	// Initialize BasicAuthClient
	authClient := New(jwt.SigningMethodHS256, jwtSecret, "", "", passwordConfig)

	// Call the method under test
	user, err := authClient.GetBasicUserFromToken(tokenString)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, expectedUsername, user.Username)
	assert.Equal(t, expectedAudience, user.Audience)
	assert.Equal(t, expectedIssuer, user.Issuer)
}

func TestBasicAuthClient_SignIn(t *testing.T) {

	authClient := New(jwt.SigningMethodHS256, "secret", "TESTER_AUD", "TESTER_ISSUER", passwordConfig)

	user := BasicUser{
		Username: "foo",
	}

	token, _ := authClient.SignIn(user)

	assert.NotEmpty(t, token.AccessToken)
}

func TestBasicAuthClient_HashPasswordTest(t *testing.T) {
	authClient := New(jwt.SigningMethodHS256, "secret", "TESTER_AUD", "TESTER_ISSUER", passwordConfig)

	password := "iwakpitik"
	// hashedPasswordWithSalt, salt := authClient.HashPassword(password)
	hashedPasswordWithSalt, _ := authClient.HashPasswordWithEncodedSalt(password)
	hashedPassword, salt := authClient.HashPassword(password)

	assert.NotEmpty(t, hashedPasswordWithSalt)
	assert.NotEmpty(t, hashedPassword)
	assert.NotEmpty(t, salt)

	verified1 := authClient.VerifyPasswordWithEncodedSalt(hashedPasswordWithSalt, password)
	assert.True(t, verified1)

	verified2 := authClient.VerifyPassword(hashedPassword, salt, password)
	assert.True(t, verified2)

	// log.Fatal(hashedPassword, salt)

}
