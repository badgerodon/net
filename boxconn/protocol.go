package boxconn

import (
	"bytes"
	"code.google.com/p/go-uuid/uuid"
	"code.google.com/p/go.crypto/nacl/box"
	"encoding/binary"
	"fmt"
	"math/rand"
)

const (
	lenSize   = 8
	nonceSize = 24
	keySize   = 32
)

type (
	Protocol struct {
		reader             Reader
		writer             Writer
		myNonce, peerNonce [nonceSize]byte
		sharedKey          [keySize]byte
	}
	Message struct {
		Nonce [nonceSize]byte
		Data  []byte
	}
	Reader interface {
		ReadMessage() (Message, error)
	}
	Writer interface {
		WriteMessage(Message) error
	}
)

var zeroNonce [nonceSize]byte

// Generate a nonce: timestamp (uuid) + random
func generateNonce() [nonceSize]byte {
	var nonce [nonceSize]byte
	copy(nonce[:16], uuid.NewUUID())
	binary.BigEndian.PutUint64(nonce[16:], uint64(rand.Int63()))
	return nonce
}

// The next nonce (incremented big-endianly)
func incrementNonce(nonce [nonceSize]byte) [nonceSize]byte {
	for i := nonceSize - 1; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
	return nonce
}

func NewProtocol(r Reader, w Writer) *Protocol {
	return &Protocol{
		reader: r,
		writer: w,
	}
}

// Handshake establishes a session between two parties. Keys can be generated
// using box.GenerateKeys. allowedKeys is a list of keys which are allowed
// for the session.
func (p *Protocol) Handshake(privateKey, publicKey [keySize]byte, allowedKeys ...[keySize]byte) error {
	// write our nonce & public key
	err := p.WriteRaw(publicKey[:])
	if err != nil {
		return err
	}

	// read the client's nonce & public key
	data, err := p.ReadRaw()
	if err != nil {
		return err
	}
	var peerKey [keySize]byte
	copy(peerKey[:], data)

	// verify that this is a key we allow
	allow := false
	for _, k := range allowedKeys {
		if bytes.Equal(k[:], peerKey[:]) {
			allow = true
			break
		}
	}
	if !allow {
		return fmt.Errorf("key not allowed: %x", peerKey[:])
	}

	// compute a shared key we can use for the rest of the session
	box.Precompute(&p.sharedKey, &peerKey, &privateKey)

	// now to prevent replay attacks we trade session tokens
	token := []byte(uuid.NewUUID())
	err = p.Write(token)
	if err != nil {
		return err
	}

	// read peer session token
	peerToken, err := p.Read()
	if err != nil {
		return err
	}

	// send the peer session token back
	err = p.Write(peerToken)
	if err != nil {
		return err
	}

	// read the response
	receivedToken, err := p.Read()
	if err != nil {
		return err
	}

	if !bytes.Equal(token, receivedToken) {
		return fmt.Errorf("invalid session token")
	}

	return nil
}

// ReadRaw reads a message from the reader, checks its nonce
//   value, but does not decrypt it
func (p *Protocol) ReadRaw() ([]byte, error) {
	msg, err := p.reader.ReadMessage()
	if err != nil {
		return nil, err
	}
	if p.peerNonce == zeroNonce {
		p.peerNonce = msg.Nonce
	} else {
		p.peerNonce = incrementNonce(p.peerNonce)
	}

	if !bytes.Equal(msg.Nonce[:], p.peerNonce[:]) {
		return nil, fmt.Errorf("invalid nonce")
	}

	return msg.Data, nil
}

// Read reads a raw message from the reader, then decrypts it
func (p *Protocol) Read() ([]byte, error) {
	data, err := p.ReadRaw()
	if err != nil {
		return nil, err
	}

	data, ok := box.OpenAfterPrecomputation(nil, data, &p.peerNonce, &p.sharedKey)
	if !ok {
		return nil, fmt.Errorf("error decrypting message")
	}
	return data, nil
}

// WriteRaw writes the data (unsealed) to the writer and increments the nonce
func (p *Protocol) WriteRaw(data []byte) error {
	if p.myNonce == zeroNonce {
		p.myNonce = generateNonce()
	} else {
		p.myNonce = incrementNonce(p.myNonce)
	}
	return p.writer.WriteMessage(Message{
		Nonce: p.myNonce,
		Data:  data,
	})
}

// Write writes the data (sealed) to the writer and increments the nonce
func (p *Protocol) Write(data []byte) error {
	if p.myNonce == zeroNonce {
		p.myNonce = generateNonce()
	} else {
		p.myNonce = incrementNonce(p.myNonce)
	}

	data = box.SealAfterPrecomputation(nil, data, &p.myNonce, &p.sharedKey)

	return p.writer.WriteMessage(Message{
		Nonce: p.myNonce,
		Data:  data,
	})
}
