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
	Reader  interface {
		ReadRequest() (Request, error)
	}
	Writer interface {
		WriteResponse(Response) error
	}
	ReaderFunc func() (Request, error)
	WriterFunc func(Response) error
)

func (rf ReaderFunc) ReadRequest() (Request, error) {
	return rf()
}
func (wf WriterFunc) WriteResponse(r Response) error {
	return wf(r)
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

func (s *Server) Serve(r Reader, w Writer) error {
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
		ReaderFunc(func() (Request, error) {
			var req Request
			return req, json.NewDecoder(conn).Decode(&req)
		}),
		WriterFunc(func(res Response) error {
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
