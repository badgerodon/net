package boxconn

import (
	"code.google.com/p/go.crypto/nacl/box"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestConn(t *testing.T) {
	skPub, skPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("failed to generate server keys: %v", err)
		t.FailNow()
	}

	ckPub, ckPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("failed to generate client keys: %v", err)
		t.FailNow()
	}

	server, err := Listen("tcp", "127.0.0.1:0", *skPriv, *skPub, *ckPub)
	if err != nil {
		t.Errorf("failed to start server: %v", err)
		t.FailNow()
	}
	defer server.Close()

	errors := make(chan error, 2)

	go func() {
		bc, err := Dial("tcp", server.Addr().String(), *ckPriv, *ckPub, *skPub)
		if err != nil {
			t.Errorf("failed to connect to server: %v", err)
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

	go func() {
		bc, err := server.Accept()
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
		errors <- nil
	}()

	for i := 0; i < 2; i++ {
		err := <-errors
		if err != nil {
			t.Errorf("%v", err)
		}
	}
}
