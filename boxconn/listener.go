package boxconn

import (
	"net"
)

type (
	Listener struct {
		underlying            net.Listener
		privateKey, publicKey [32]byte
		allowedKeys           [][32]byte
	}
)

// Listen starts a listener and wraps it in a secure connection. (See net.Listener for details on network and laddr).
func Listen(network, laddr string, privateKey, publicKey [32]byte, allowedKeys ...[32]byte) (*Listener, error) {
	underlying, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return &Listener{
		underlying:  underlying,
		privateKey:  privateKey,
		publicKey:   publicKey,
		allowedKeys: allowedKeys,
	}, nil
}

// Accept waits for and returns the next connection to the listener.
func (l *Listener) Accept() (net.Conn, error) {
	for {
		conn, err := l.underlying.Accept()
		if err != nil {
			return nil, err
		}

		boxconn, err := Handshake(conn, l.privateKey, l.publicKey, l.allowedKeys...)
		// if the handshake fails, we skip close the connection and skip it
		if err != nil {
			conn.Close()
			continue
		}

		return boxconn, nil
	}
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (l *Listener) Close() error {
	return l.underlying.Close()
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.underlying.Addr()
}
