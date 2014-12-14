package secure

import (
	"crypto/sha256"
	"golang.org/x/crypto/pbkdf2"
)

func GenerateKey(password string, sz int) []byte {
	return pbkdf2.Key([]byte(password), []byte{}, 4096, sz, sha256.New)
}
