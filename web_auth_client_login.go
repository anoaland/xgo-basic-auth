package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"

	"golang.org/x/crypto/pbkdf2"
)

func (c BasicAuthClient[T]) Login(username string, password string) {

}

func (c BasicAuthClient[T]) EncodeToString(src []byte) string {
	if c.passwordConfig.HexEncoding {

		return hex.EncodeToString(src)
	}

	return base64.StdEncoding.EncodeToString(src)
}

func (c BasicAuthClient[T]) DecodeString(src string) ([]byte, error) {
	if c.passwordConfig.HexEncoding {
		return hex.DecodeString(src)
	}

	return base64.StdEncoding.DecodeString(src)
}

func (c BasicAuthClient[T]) HashPassword(passwordText string) (string, string) {
	password := []byte(passwordText)
	salt := make([]byte, c.passwordConfig.SaltLen) // generate a random salt
	_, err := rand.Read(salt)
	if err != nil {
		panic(err)
	}

	derivedKey := pbkdf2.Key(password,
		salt,
		c.passwordConfig.Iterations,
		c.passwordConfig.PassLen,
		c.passwordConfig.Hash)

	// If you want to convert the derived key to hex as in the Node.js code
	hexDerivedKey := c.EncodeToString(derivedKey)
	saltString := c.EncodeToString(salt)

	return hexDerivedKey, saltString
}

func (c BasicAuthClient[T]) VerifyPassword(hashedPassword string, salt string, passwordText string) bool {

	decodedPasswordHash, err := c.DecodeString(hashedPassword)
	if err != nil {
		return false
	}

	decodedSalt, err := c.DecodeString(salt)
	if err != nil {
		return false
	}

	password := []byte(passwordText)

	newHash := pbkdf2.Key(
		password,
		decodedSalt,
		c.passwordConfig.Iterations,
		c.passwordConfig.PassLen,
		c.passwordConfig.Hash)

	return hmac.Equal(decodedPasswordHash, newHash)
}

func (c BasicAuthClient[T]) HashPasswordWithEncodedSalt(password string) (string, error) {
	salt := make([]byte, c.passwordConfig.SaltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	hash := pbkdf2.Key([]byte(password),
		salt,
		c.passwordConfig.Iterations,
		c.passwordConfig.PassLen,
		c.passwordConfig.Hash)
	saltedHash := append(salt, hash...)
	encodedSaltedHash := c.EncodeToString(saltedHash)
	return encodedSaltedHash, nil
}

func (c BasicAuthClient[T]) VerifyPasswordWithEncodedSalt(hashedPassword string, password string) bool {
	decodedSaltedHash, err := c.DecodeString(hashedPassword)
	if err != nil {
		return false
	}

	salt := decodedSaltedHash[:c.passwordConfig.SaltLen]
	hash := decodedSaltedHash[c.passwordConfig.SaltLen:]

	newHash := pbkdf2.Key([]byte(password),
		salt,
		c.passwordConfig.Iterations,
		c.passwordConfig.PassLen,
		c.passwordConfig.Hash)
	return hmac.Equal(hash, newHash)
}
