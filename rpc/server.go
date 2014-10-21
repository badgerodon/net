package rpc

import (
	"encoding/json"
	"net"
	"sync"
)

type (
	Server struct {
		handlers map[string]Handler
		mu       sync.Mutex
	}
	Handler func(params []json.RawMessage) interface{}
)

func NewServer() *Server {
	return &Server{
		handlers: make(map[string]Handler),
	}
}

func (s *Server) Handle(method string, handler Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.handlers[method] = handler
}

func (s *Server) ServeConnection(conn net.Conn) error {
	defer conn.Close()

	requests := make(chan Request, 1)
	responses := make(chan Response, 1)

	errors := make(chan error, 3)
	go func() {
		defer close(requests)
		for {
			var req Request
			err := json.NewDecoder(conn).Decode(&req)
			if err != nil {
				errors <- err
				return
			}
			requests <- req
		}
	}()
	go func() {
		defer close(responses)
		for req := range requests {
			s.mu.Lock()
			handler, ok := s.handlers[req.Method]
			s.mu.Unlock()

			go func() {
				res := Response{
					ID: req.ID,
				}
				if ok {
					result := handler(req.Params)
					if result != nil {
						if err, ok := result.(error); ok {
							res.Error = &Error{
								Code:    4500,
								Message: err.Error(),
							}
						} else {
							bs, err := json.Marshal(result)
							if err != nil {
								errors <- err
								return
							}
							res.Result = new(json.RawMessage)
							*res.Result = json.RawMessage(bs)
						}
					}
				} else {
					res.Error = &Error{
						Code:    4404,
						Message: "unknown method",
					}
				}
				responses <- res
			}()
		}
	}()

	go func() {
		for res := range responses {
			bs, err := json.Marshal(res)
			if err != nil {
				errors <- err
				return
			}
			_, err = conn.Write(bs)
			if err != nil {
				errors <- err
				return
			}
		}
	}()
	return <-errors
}

func (s *Server) Serve(l net.Listener) error {
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		go s.ServeConnection(conn)
	}
	return nil
}

func (s *Server) ListenAndServe(network, address string) error {
	l, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	return s.Serve(l)
}
