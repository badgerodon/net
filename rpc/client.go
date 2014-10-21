package rpc

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
)

type (
	Client struct {
		conn      net.Conn
		requests  chan clientRequest
		responses chan Response
		closed    bool
		mu        sync.Mutex
	}
	clientRequest struct {
		method   string
		params   []json.RawMessage
		response chan Response
	}
)

// Dial connects to an rpc server
func Dial(network, address string) (*Client, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return NewClient(conn), nil
}

// NewClient creates a new client on top of a connection
func NewClient(conn net.Conn) *Client {
	c := &Client{
		conn:      conn,
		requests:  make(chan clientRequest, 1),
		responses: make(chan Response, 1),
	}

	go func() {
		for {
			var res Response
			err := json.NewDecoder(conn).Decode(&res)
			if err != nil {
				close(c.responses)
				return
			}
			c.responses <- res
		}
	}()

	go func() {
		nextID := 1
		waiting := make(map[int]chan Response)
		var err error
		for {
			select {
			case creq, ok := <-c.requests:
				if !ok {
					return
				}
				// if the connection is busted fail immediately
				if err != nil {
					creq.response <- Response{
						Error: &Error{Code: 0, Message: err.Error()},
					}
					continue
				}
				// build a request and send it
				req := Request{
					Method: creq.method,
					Params: creq.params,
					ID:     nextID,
				}
				var bs []byte
				bs, err = json.Marshal(req)
				if err != nil {
					creq.response <- Response{
						Error: &Error{Code: 0, Message: err.Error()},
					}
					err = nil
					continue
				}
				_, err = c.conn.Write(bs)
				// if sending fails, I guess we're busted
				if err != nil {
					creq.response <- Response{
						Error: &Error{Code: 0, Message: err.Error()},
					}
					continue
				}
				waiting[nextID] = creq.response
				nextID++
			case res := <-c.responses:
				ch, ok := waiting[res.ID]
				if ok {
					ch <- res
					delete(waiting, res.ID)
				}
			}
		}
	}()

	return c
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true
	close(c.requests)
	return c.conn.Close()
}

// Call calls a method on the server. It is safe to call
// this method from multiple goroutines. `result` should be
// a pointer if you expect a result.
func (c *Client) Call(method string, params []interface{}, result interface{}) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return io.EOF
	}
	c.mu.Unlock()

	// convert the parameters into json
	encodedParams := make([]json.RawMessage, len(params))
	for i, param := range params {
		var err error
		encodedParams[i], err = json.Marshal(param)
		if err != nil {
			return err
		}
	}

	// send the request (multiple requests can happen in parallel, so we wait on a channel)
	ch := make(chan Response, 1)
	c.requests <- clientRequest{
		method:   method,
		params:   encodedParams,
		response: ch,
	}
	res := <-ch

	// return an error if the result has an error. we just ignore the code
	if res.Error != nil {
		return fmt.Errorf("%v", res.Error.Message)
	}

	// Decode the result
	if result != nil && res.Result != nil {
		err := json.Unmarshal(*res.Result, result)
		if err != nil {
			return err
		}
	}
	return nil
}
