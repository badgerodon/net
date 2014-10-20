package boxconn

import (
	"bytes"
	"code.google.com/p/go.crypto/nacl/box"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"testing"
)

type replayConn struct {
	net.Conn
	w io.Writer
}

func (rc replayConn) Write(b []byte) (n int, err error) {
	_, err = rc.w.Write(b)
	if err != nil {
		return
	}
	return rc.Conn.Write(b)
}

func TestConn(t *testing.T) {
	skPub, skPriv, _ := box.GenerateKey(rand.Reader)
	ckPub, ckPriv, _ := box.GenerateKey(rand.Reader)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l.Close()

	errors := make(chan error, 2)

	var replayBuffer bytes.Buffer
	go func() {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Errorf("failed to connect to server: %v", err)
			t.FailNow()
		}
		defer c.Close()

		rc := replayConn{c, &replayBuffer}

		bc, err := Handshake(rc, *ckPriv, *ckPub, *skPub)
		if err != nil {
			t.Errorf("failed to establish connection: %v", err)
			t.FailNow()
		}
		defer bc.Close()

		n, err := bc.Write([]byte("Hello World"))
		if err != nil {
			errors <- fmt.Errorf("failed to write: %v", err)
			return
		}
		if n != 11 {
			errors <- fmt.Errorf("expected to write %v bytes, wrote %v", 11, n)
			return
		}
		errors <- nil
	}()

	runServer := func() {
		go func() {
			c, err := l.Accept()
			if err != nil {
				errors <- fmt.Errorf("failed to receive connection: %v", err)
				return
			}
			defer c.Close()

			bc, err := Handshake(c, *skPriv, *skPub, *ckPub)
			if err != nil {
				errors <- fmt.Errorf("failed to receive connection: %v", err)
				return
			}
			defer bc.Close()

			buf := make([]byte, 1024)
			n, err := bc.Read(buf)
			if err != nil {
				errors <- fmt.Errorf("failed to read: %v", err)
				return
			}
			if n != 11 {
				errors <- fmt.Errorf("expected to read %v bytes, read %v", 11, n)
				return
			}

			// test replay attack

			errors <- nil
		}()
	}
	runServer()

	for i := 0; i < 2; i++ {
		err := <-errors
		if err != nil {
			t.Errorf("%v", err)
		}
	}

	go func() {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Errorf("failed to connect to server: %v", err)
			t.FailNow()
		}
		defer c.Close()

		c.Write(replayBuffer.Bytes())
	}()

	runServer()
	err = <-errors
	if err == nil {
		t.Errorf("replay should not succeed but it did")
	}
}
