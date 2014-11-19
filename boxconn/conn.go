// Package boxconn encrypts an underlying network connection
// using NaCL's box public-key encryption. See https://github.com/badgerodon/net/boxconn
// for more details.
package boxconn

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"time"
)

type (
	// Conn is a secure connection over an underlying net.Conn
	Conn struct {
		underlying net.Conn
		recvBuffer []byte
		protocol   *Protocol
	}
)

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
	c.protocol = NewProtocol(c, c)

	return c, c.protocol.Handshake(privateKey, publicKey, allowedKeys...)
}

// ReadMessage reads a message (nonce, data) from the connection
func (c *Conn) ReadMessage() (Message, error) {
	header := make([]byte, nonceSize+lenSize)
	_, err := io.ReadFull(c.underlying, header)
	if err != nil {
		return Message{}, err
	}

	var msg Message
	copy(msg.Nonce[:], header[:nonceSize])

	length := int(binary.BigEndian.Uint64(header[nonceSize:]))

	msg.Data = make([]byte, length)
	_, err = io.ReadFull(c.underlying, msg.Data)
	if err != nil {
		return Message{}, err
	}
	return msg, nil
}

// WriteMessage writes a message (nonce, data) to the connection
func (c *Conn) WriteMessage(msg Message) error {
	header := make([]byte, nonceSize+lenSize)
	copy(header[:nonceSize], msg.Nonce[:])
	binary.BigEndian.PutUint64(header[nonceSize:], uint64(len(msg.Data)))
	_, err := io.Copy(c.underlying, io.MultiReader(bytes.NewReader(header), bytes.NewReader(msg.Data)))
	return err
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

	msg, err := c.protocol.Read()
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
	err = c.protocol.Write(b)
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
