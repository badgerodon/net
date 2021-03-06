package client

import (
	"fmt"
	"net"

	"github.com/badgerodon/net/socketmaster/protocol"
	"github.com/hashicorp/yamux"
)

// Listen connects to the socket master, binds a port, and accepts
// multiplexed traffic as new connections
func Listen(socketMasterAddress string, socketDefinition protocol.SocketDefinition) (net.Listener, error) {
	// connect to the socket master
	conn, err := net.Dial("tcp", socketMasterAddress)
	if err != nil {
		return nil, err
	}

	// bind to a port
	err = protocol.WriteHandshakeRequest(conn, protocol.HandshakeRequest{
		SocketDefinition: socketDefinition,
	})
	if err != nil {
		conn.Close()
		return nil, err
	}

	// see if that worked
	res, err := protocol.ReadHandshakeResponse(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if res.Status != "OK" {
		conn.Close()
		return nil, fmt.Errorf("%s", res.Status)
	}

	// start a new session
	session, err := yamux.Server(conn, yamux.DefaultConfig())
	if err != nil {
		conn.Close()
		return nil, err
	}

	return session, nil
}
