package multiplex

import (
	"io"
	"net"
	"sync"
	"time"
)

type (
	Conn struct {
		multiplexer *Multiplexer
		buffer      []byte
		id          UUID
		in          chan Message
		closed      bool
		mu          sync.Mutex
	}
)

func NewConn(m *Multiplexer, id UUID) *Conn {
	c := &Conn{
		multiplexer: m,
		id:          id,
		in:          make(chan Message),
	}
	return c
}

// Read reads data from the connection.
func (c *Conn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()

	if closed {
		return 0, io.EOF
	}

	sz := len(c.buffer)
	if sz > 0 {
		copy(b, c.buffer)
		if len(b) < sz {
			c.buffer = c.buffer[len(b):]
			return len(b), nil
		} else {
			c.buffer = nil
			return sz, nil
		}
	}
	next, ok := <-c.in
	if !ok {
		return 0, io.EOF
	}
	if next.Code == CloseMessage {
		c.Close()
		return 0, io.EOF
	}
	sz = len(next.Data)
	if sz > len(b) {
		c.buffer = next.Data[len(b):]
		sz = len(b)
	}
	copy(b, next.Data)
	return sz, nil
}

// Write writes data to the connection.
func (c *Conn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return 0, io.EOF
	}
	return c.multiplexer.Write(Message{c.id, DataMessage, b})
}

// Close closes the connection.
func (c *Conn) Close() error {
	c.mu.Lock()
	if !c.closed {
		c.multiplexer.unregister(c)
		c.closed = true
	}
	c.mu.Unlock()
	return nil
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.multiplexer.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.multiplexer.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.multiplexer.conn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.multiplexer.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.multiplexer.conn.SetWriteDeadline(t)
}
