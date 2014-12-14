package boxconn

import (
	"bytes"
	"code.google.com/p/go-uuid/uuid"
	"golang.org/x/crypto/nacl/box"
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
		privateKey, publicKey, peerKey, sharedKey [keySize]byte
	}
	Message struct {
		Nonce [nonceSize]byte
		Data  []byte
	}
	Reader interface {
		ReadMessage() (Message, error)
	}
	ReaderFunc func() (Message, error)
	Writer     interface {
		WriteMessage(Message) error
	}
	WriterFunc func(Message) error
)

func (rf ReaderFunc) ReadMessage() (Message, error) {
	return rf()
}
func (wf WriterFunc) WriteMessage(msg Message) error {
	return wf(msg)
}

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
	p.privateKey = privateKey
	p.publicKey = publicKey

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
	p.peerKey = peerKey
	fmt.Println("PRIVATE KEY:", privateKey)
	fmt.Println("PEER KEY:", peerKey)

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
	fmt.Println("SHARED KEY:", p.sharedKey)

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

	fmt.Println("READ RAW", msg.Data)

	return msg.Data, nil
}

// Read reads a raw message from the reader, then decrypts it
func (p *Protocol) Read() ([]byte, error) {
	sealed, err := p.ReadRaw()
	if err != nil {
		return nil, err
	}

	unsealed, ok := box.Open(nil, sealed, &p.peerNonce, &p.peerKey, &p.privateKey)
	if !ok {
		return nil, fmt.Errorf("error decrypting message")
	}

	fmt.Println("READ", unsealed)

	return unsealed, nil
}

// WriteRaw writes the data (unsealed) to the writer and increments the nonce
func (p *Protocol) WriteRaw(data []byte) error {
	if p.myNonce == zeroNonce {
		p.myNonce = generateNonce()
	} else {
		p.myNonce = incrementNonce(p.myNonce)
	}

	fmt.Println("WRITE RAW", data)

	return p.writer.WriteMessage(Message{
		Nonce: p.myNonce,
		Data:  data,
	})
}

// Write writes the data (sealed) to the writer and increments the nonce
func (p *Protocol) Write(unsealed []byte) error {
	if p.myNonce == zeroNonce {
		p.myNonce = generateNonce()
	} else {
		p.myNonce = incrementNonce(p.myNonce)
	}

	sealed := box.Seal(nil, unsealed, &p.myNonce, &p.peerKey, &p.sharedKey)

	fmt.Println("WRITE", sealed)

	return p.writer.WriteMessage(Message{
		Nonce: p.myNonce,
		Data:  sealed,
	})
}
