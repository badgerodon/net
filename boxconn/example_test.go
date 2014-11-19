package boxconn_test

import (
	"code.google.com/p/go.crypto/nacl/box"
	"crypto/rand"
	"fmt"
	. "github.com/badgerodon/net/boxconn"
	"net"
)

func ExampleHandshake() {
	sPub, sPriv, _ := box.GenerateKey(rand.Reader)
	cPub, cPriv, _ := box.GenerateKey(rand.Reader)

	// server
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		c, _ := l.Accept()
		defer c.Close()

		bc, _ := Handshake(c, *sPriv, *sPub, *cPub)
		msg := make([]byte, 1024)
		n, _ := bc.Read(msg)
		fmt.Println("SERVER:", string(msg[:n]))
		bc.Write([]byte("pong"))
	}()

	// client
	c, _ := net.Dial("tcp", l.Addr().String())
	defer c.Close()

	bc, _ := Handshake(c, *cPriv, *cPub, *sPub)
	bc.Write([]byte("ping"))
	msg := make([]byte, 1024)
	n, _ := bc.Read(msg)
	fmt.Println("CLIENT:", string(msg[:n]))
	// Output:
	// SERVER: ping
	// CLIENT: pong
}
