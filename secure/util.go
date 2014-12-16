package secure

import (
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
)

func GenerateKey(password string, sz int) []byte {
	return pbkdf2.Key([]byte(password), []byte{}, 4096, sz, sha256.New)
}

func (msg Message) MarshalBytes() []byte {
	data := make([]byte, 12+1+len(msg.Tag)+len(msg.Data))
	copy(data, msg.Nonce)
	data[12] = byte(len(msg.Tag))
	copy(data[13:], msg.Tag)
	copy(data[13+len(msg.Tag):], msg.Data)
	return data
}

func (msg *Message) UnmarshalBytes(data []byte) error {
	if len(data) < 13 {
		return fmt.Errorf("invalid message")
	}
	tagLength := int(data[12])
	if len(data) < 12+tagLength {
		return fmt.Errorf("invalid message, taglength=%v", tagLength)
	}
	msg.Nonce = data[:12]
	data = data[13:]
	msg.Tag = data[:tagLength]
	msg.Data = data[tagLength:]
	return nil
}
