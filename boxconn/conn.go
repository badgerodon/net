// Package boxconn encrypts an underlying network connection
// using NaCL's box public-key encryption. See https://github.com/badgerodon/net/boxconn
// for more details.
package boxconn

import (
	"bytes"
	"code.google.com/p/go-uuid/uuid"
	"code.google.com/p/go.crypto/nacl/box"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"time"
)

const (
	lenSize   = 8
	nonceSize = 24
	keySize   = 32
)

type (
	// Conn is a secure connection over an underlying net.Conn
	Conn struct {
		underlying                                net.Conn
		privateKey, publicKey, sharedKey, peerKey [keySize]byte
		recvBuffer                                []byte
		myNonce, peerNonce                        [nonceSize]byte
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

// Dial connects to the address on the named network. See net.Dial for
// more details
func Dial(network, address string, privateKey, publicKey [keySize]byte, allowedKeys ...[keySize]byte) (*Conn, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return Handshake(conn, privateKey, publicKey, allowedKeys...)
}

// Handshake establishes a session between two parties. Keys can be generated
// using box.GenerateKeys. allowedKeys is a list of keys which are allowed
// for the session.
func Handshake(conn net.Conn, privateKey, publicKey [keySize]byte, allowedKeys ...[keySize]byte) (*Conn, error) {
	c := &Conn{
		underlying: conn,
	}

	c.privateKey = privateKey
	c.publicKey = publicKey

	// send our public key
	_, err := c.underlying.Write(c.publicKey[:])
	if err != nil {
		return nil, err
	}

	// read our peer's public key
	_, err = io.ReadFull(c.underlying, c.peerKey[:])
	if err != nil {
		return nil, err
	}

	// verify that this is a key we allow
	allow := false
	for _, k := range allowedKeys {
		if bytes.Equal(k[:], c.peerKey[:]) {
			allow = true
		}
	}
	if !allow {
		return nil, fmt.Errorf("key not allowed")
	}

	// compute a shared key we can use for the rest of the session
	box.Precompute(&c.sharedKey, &c.peerKey, &c.privateKey)

	// now to prevent replay attacks we trade session tokens
	// incrementing nonces take over after that
	token := []byte(uuid.NewUUID())
	err = c.send(token)
	if err != nil {
		return nil, err
	}

	// read peer session token
	peerToken, err := c.ReadMessage()
	if err != nil {
		return nil, err
	}

	// send it back
	err = c.send(peerToken)
	if err != nil {
		return nil, err
	}

	// read the response
	receivedToken, err := c.ReadMessage()
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(token, receivedToken) {
		return nil, fmt.Errorf("invalid session token")
	}
	return c, nil
}

// Encrypt, frame and send a message
func (c *Conn) send(msg []byte) error {
	if c.myNonce == zeroNonce {
		c.myNonce = generateNonce()
	} else {
		c.myNonce = incrementNonce(c.myNonce)
	}

	buf := make([]byte, nonceSize+lenSize, nonceSize+lenSize+len(msg)+box.Overhead)
	copy(buf, c.myNonce[:])

	buf = box.Seal(buf, msg, &c.myNonce, &c.peerKey, &c.privateKey)
	binary.BigEndian.PutUint64(buf[nonceSize:], uint64(len(buf)-nonceSize-lenSize))

	_, err := c.underlying.Write(buf)
	if err != nil {
		return err
	}
	return nil
}

// ReadMessage reads the next encrypted message from the underlying connection.
// The secure connection is not actually a stream of bytes, each time a message
// is written it is framed with a nonce and a length.
func (c *Conn) ReadMessage() ([]byte, error) {
	header := make([]byte, nonceSize+lenSize)
	_, err := io.ReadFull(c.underlying, header)
	if err != nil {
		return nil, err
	}

	var nonce [nonceSize]byte
	copy(nonce[:], header[:nonceSize])

	// verify that this is an ok nonce
	if c.peerNonce == zeroNonce {
		c.peerNonce = nonce
	} else {
		c.peerNonce = incrementNonce(c.peerNonce)
	}

	if !bytes.Equal(nonce[:], c.peerNonce[:]) {
		return nil, fmt.Errorf("invalid nonce")
	}

	length := int(binary.BigEndian.Uint64(header[nonceSize:]))

	buf := make([]byte, length)
	_, err = io.ReadFull(c.underlying, buf)
	if err != nil {
		return nil, err
	}

	msg, ok := box.Open(nil, buf, &nonce, &c.peerKey, &c.privateKey)
	if !ok {
		return nil, fmt.Errorf("invalid message")
	}
	return msg, nil
}

// Read reads data from the connection.
// Read can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetReadDeadline.
func (c *Conn) Read(b []byte) (n int, err error) {
	// if we have anything left over from the last read
	if len(c.recvBuffer) > 0 {
		copied := copy(b, c.recvBuffer)
		c.recvBuffer = c.recvBuffer[copied:]
		return copied, nil
	}

	msg, err := c.ReadMessage()
	if err != nil {
		return 0, err
	}

	copied := copy(b, msg)
	if copied < len(msg) {
		c.recvBuffer = msg[copied:]
	}
	return copied, nil
}

// Write writes data to the connection.
// Write can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (c *Conn) Write(b []byte) (n int, err error) {
	err = c.send(b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (c *Conn) Close() error {
	return c.underlying.Close()
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.underlying.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.underlying.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail with a timeout (see type Error) instead of
// blocking. The deadline applies to all future I/O, not just
// the immediately following call to Read or Write.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful Read or Write calls.
//
// A zero value for t means I/O operations will not time out.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.underlying.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls.
// A zero value for t means Read will not time out.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.underlying.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.underlying.SetWriteDeadline(t)
}
