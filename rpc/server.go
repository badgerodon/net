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
	Handler       func(params []json.RawMessage) interface{}
	RequestReader interface {
		ReadRequest() (Request, error)
	}
	ResponseWriter interface {
		WriteResponse(Response) error
	}
	RequestReaderFunc  func() (Request, error)
	ResponseWriterFunc func(Response) error
)

func (rrf RequestReaderFunc) ReadRequest() (Request, error) {
	return rrf()
}
func (rwf ResponseWriterFunc) WriteResponse(r Response) error {
	return rwf(r)
}

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

func (s *Server) Serve(r RequestReader, w ResponseWriter) error {
	requests := make(chan Request, 1)
	responses := make(chan Response, 1)
	errors := make(chan error, 3)

	go func() {
		defer close(requests)
		for {
			req, err := r.ReadRequest()
			if err != nil {
				errors <- err
				return
			}
			requests <- req
		}
	}()
	go func() {
		var rw sync.RWMutex
		defer func() {
			rw.Lock()
			defer rw.Unlock()
			close(responses)
		}()
		for req := range requests {
			s.mu.Lock()
			handler, ok := s.handlers[req.Method]
			s.mu.Unlock()

			go func() {
				rw.RLock()
				defer rw.RUnlock()

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
			err := w.WriteResponse(res)
			if err != nil {
				errors <- err
				return
			}
		}
	}()

	return <-errors
}

func (s *Server) ServeConnection(conn net.Conn) error {
	return s.Serve(
		RequestReaderFunc(func() (Request, error) {
			var req Request
			return req, json.NewDecoder(conn).Decode(&req)
		}),
		ResponseWriterFunc(func(res Response) error {
			return json.NewEncoder(conn).Encode(res)
		}),
	)
}

func (s *Server) ServeConnections(lis net.Listener) error {
	for {
		conn, err := lis.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			s.ServeConnection(conn)
		}()
	}
}
