package server

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/badgerodon/net/socketmaster/protocol"
	"github.com/hashicorp/yamux"
)

type (
	upstreamListener struct {
		id         int64
		listener   net.Listener
		downstream map[int64]*downstreamConnection
		tlsConfig  *tls.Config
		mu         sync.RWMutex
	}
	downstreamConnection struct {
		id               int64
		session          *yamux.Session
		socketDefinition protocol.SocketDefinition
	}
)

func (u *upstreamListener) closeDownstream(id int64) {
	u.mu.Lock()
	d, ok := u.downstream[id]
	if ok {
		d.session.Close()
	}
	u.mu.Unlock()

	u.update()
}

func (u *upstreamListener) findDownstream(req *http.Request) *downstreamConnection {
	u.mu.RLock()
	defer u.mu.RUnlock()

	for _, d := range u.downstream {
		if d.socketDefinition.HTTP != nil {
			if strings.HasSuffix(req.Host, d.socketDefinition.HTTP.DomainSuffix) &&
				strings.HasPrefix(req.URL.Path, d.socketDefinition.HTTP.PathPrefix) {
				return d
			}
		}
	}

	return nil
}

func (u *upstreamListener) route(conn net.Conn) {
	u.mu.RLock()
	if u.tlsConfig != nil {
		conn = tls.Server(conn, u.tlsConfig)
	}
	useHTTP := false
	candidates := make([]*downstreamConnection, 0, len(u.downstream))
	for _, d := range u.downstream {
		candidates = append(candidates, d)
		if d.socketDefinition.HTTP != nil {
			useHTTP = true
		}
	}
	u.mu.RUnlock()

	if len(candidates) == 0 {
		conn.Close()
		return
	}

	if useHTTP {
		go func() {
			defer conn.Close()

			var lastStream *yamux.Stream
			var lastSession *yamux.Session
			defer func() {
				if lastStream != nil {
					lastStream.Close()
				}
			}()

			for {
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}

				d := u.findDownstream(req)
				if d == nil {
					msg := "Not Found"
					err = (&http.Response{
						Status:        "404 Not Found",
						StatusCode:    404,
						Proto:         "HTTP/1.1",
						ProtoMajor:    1,
						ProtoMinor:    1,
						Body:          ioutil.NopCloser(strings.NewReader(msg)),
						ContentLength: int64(len(msg)),
						Request:       req,
					}).Write(conn)
					if err != nil {
						return
					}
					return
				}

				if d.session != lastSession && lastStream != nil {
					lastStream.Close()
				}
				lastSession = d.session

				lastStream, err = lastSession.OpenStream()
				if err != nil {
					log.Printf("[socketmaster] failed to open stream: %v\n", err)
					return
				}

				err = req.Write(lastStream)
				if err != nil {
					return
				}
				res, err := http.ReadResponse(bufio.NewReader(lastStream), req)
				if err != nil {
					return
				}
				err = res.Write(conn)
				if err != nil {
					return
				}
			}
		}()
	} else {
		//TODO: round robin?
		d := candidates[0]
		stream, err := d.session.OpenStream()
		if err != nil {
			log.Printf("[socketmaster] failed to open stream: %v\n", err)
			conn.Close()
			return
		}

		go func() {
			signal := make(chan struct{}, 2)
			go func() {
				io.Copy(stream, conn)
				signal <- struct{}{}
			}()
			go func() {
				io.Copy(conn, stream)
				signal <- struct{}{}
			}()
			<-signal
			conn.Close()
			stream.Close()
		}()
	}
}

func (u *upstreamListener) update() {
	if len(u.downstream) == 0 {
		u.close()
	} else {
		u.mu.Lock()
		defer u.mu.Unlock()

		// rebuild the TLS config
		certs := make([]tls.Certificate, 0)
		for _, d := range u.downstream {
			if d.socketDefinition.TLS != nil {
				cert, err := tls.X509KeyPair([]byte(d.socketDefinition.TLS.Cert), []byte(d.socketDefinition.TLS.Key))
				if err == nil {
					certs = append(certs, cert)
				}
			}
		}
		if len(certs) > 0 {
			u.tlsConfig = &tls.Config{Certificates: certs}
			u.tlsConfig.BuildNameToCertificate()
		} else {
			u.tlsConfig = nil
		}
	}
}

func (u *upstreamListener) close() {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.listener != nil {
		u.listener.Close()
		u.listener = nil
	}
}

type (
	Server struct {
		li       net.Listener
		upstream map[int64]*upstreamListener
		nextID   int64
		mu       sync.Mutex
	}
)

func New(li net.Listener) *Server {
	s := &Server{
		li:       li,
		upstream: make(map[int64]*upstreamListener),
		nextID:   1,
	}
	return s
}

func (s *Server) handleDownstreamConnection(conn net.Conn) {
	// a downstream connection starts with a handshake specifying what socket to
	// listen on
	req, err := protocol.ReadHandshakeRequest(conn)
	if err != nil {
		log.Printf("[socketmaster] error reading request: %v", err)
		conn.Close()
		return
	}
	protocol.WriteHandshakeResponse(conn, protocol.HandshakeResponse{
		Status: "OK",
	})

	// establish a multiplexed session over the connection
	session, err := yamux.Client(conn, yamux.DefaultConfig())
	if err != nil {
		log.Printf("[socketmaster] error reading request: %v", err)
		conn.Close()
		return
	}

	downstream := &downstreamConnection{
		id:               s.nextID,
		session:          session,
		socketDefinition: req.SocketDefinition,
	}
	s.nextID++

	var upstream *upstreamListener
outer:
	for _, u := range s.upstream {
		for _, d := range u.downstream {
			if req.SocketDefinition.Address == d.socketDefinition.Address &&
				req.SocketDefinition.Port == d.socketDefinition.Port {
				upstream = u
				break outer
			}
		}
	}

	if upstream == nil {
		li, err := net.Listen("tcp", fmt.Sprint(req.SocketDefinition.Address, ":", req.SocketDefinition.Port))
		if err != nil {
			log.Printf("[socketmaster] failed to create upstream connection: %v\n", err)
			session.Close()
			return
		}

		upstream = &upstreamListener{
			id:         s.nextID,
			listener:   li,
			downstream: map[int64]*downstreamConnection{},
		}
		s.nextID++
		s.upstream[upstream.id] = upstream

		go func() {
			for {
				conn, err := li.Accept()
				if err != nil {
					// if this is a temporary error we will try again
					if ne, ok := err.(net.Error); ok && ne.Temporary() {
						time.Sleep(1 * time.Second)
						continue
					}
					break
				}

				go upstream.route(conn)
			}
			upstream.close()
			s.mu.Lock()
			delete(s.upstream, upstream.id)
			s.mu.Unlock()
		}()
	}

	upstream.downstream[downstream.id] = downstream
	upstream.update()
}

func (s *Server) Serve() error {
	var tempDelay time.Duration // how long to sleep on accept failure
	for {
		conn, err := s.li.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				time.Sleep(tempDelay)
				continue
			}
			return err
		}

		s.mu.Lock()
		s.handleDownstreamConnection(conn)
		s.mu.Unlock()
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, u := range s.upstream {
		u.close()
	}
	s.upstream = make(map[int64]*upstreamListener)
	return nil
}
