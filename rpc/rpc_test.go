package rpc

import (
	"encoding/json"
	"net"
	"testing"
)

func TestRPC(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Errorf("failed to start listener: %v", err)
	}
	defer l.Close()

	server := NewServer()
	server.Handle("Add", func(params []json.RawMessage) interface{} {
		sum := 0
		for i := 0; i < len(params); i++ {
			var v int
			json.Unmarshal(params[i], &v)
			sum += v
		}
		return sum
	})
	go server.Serve(l)

	client, err := Dial("tcp", l.Addr().String())
	if err != nil {
		t.Errorf("failed to dial server: %v", err)
	}
	defer client.Close()

	var result int
	err = client.Call("Add", []interface{}{1, 2, 3}, &result)
	if err != nil {
		t.Errorf("failed to make rpc call: %v", err)
	}
	if result != 6 {
		t.Errorf("expected `6` got %v", result)
	}
}
