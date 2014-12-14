package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func hex(data []byte) string {
	return fmt.Sprintf("%x", data)
}

func TestAESGCM(t *testing.T) {
	assert := assert.New(t)

	password := "test"
	key := GenerateKey(password, 32)
	assert.Equal("94c5f2dc9616ec392659d1e6998a36d1ddd66ca569d1919a545d1014e6ae011d", hex(key))

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("%v", err)
		t.FailNow()
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("%v", err)
		t.FailNow()
	}

	assert.Equal(12, gcm.NonceSize())

	nonce := make([]byte, gcm.NonceSize())
	tag := []byte("TAG")
	data := []byte("DATA")

	sealed := gcm.Seal(nil, nonce, data, tag)
	assert.Equal("3ca44c7a5587af39a4c7e326b1a160b52fbad716", hex(sealed))

	unsealed, err := gcm.Open(nil, nonce, sealed, tag)
	assert.Nil(err)
	assert.Equal(data, unsealed)
}

func TestProtocol(t *testing.T) {
	assert := assert.New(t)
	assert.True(true)

}
