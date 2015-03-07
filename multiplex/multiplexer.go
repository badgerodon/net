package multiplex

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"sync"

	"github.com/rogpeppe/fastuuid"
)

const chunkSize = 8192

type (
	UUID        [24]byte
	Multiplexer struct {
		conn      net.Conn
		accept    chan *Conn
		streams   map[UUID]*Conn
		closed    bool
		mu        sync.Mutex
		writeLock sync.Mutex
	}
	Message struct {
		StreamID UUID
		Code     byte
		Data     []byte
	}
)

const DataMessage byte = 1
const CloseMessage byte = 2

func (msg *Message) Read(r io.Reader) error {
	_, err := io.ReadFull(r, msg.StreamID[:])
	if err != nil {
		return err
	}
	err = binary.Read(r, binary.BigEndian, &msg.Code)
	if err != nil {
		return err
	}
	if msg.Code == DataMessage {
		var sz int64
		err = binary.Read(r, binary.BigEndian, &sz)
		if err != nil {
			return err
		}
		msg.Data = make([]byte, sz)
		_, err = io.ReadFull(r, msg.Data)
		if err != nil {
			return err
		}
	}
	return nil
}

func (msg *Message) Write(w io.Writer) (int, error) {
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	n, err := bw.Write(msg.StreamID[:])
	if err != nil {
		return n, err
	}
	err = binary.Write(bw, binary.BigEndian, msg.Code)
	if err != nil {
		return n, err
	}
	n += 1
	if msg.Code == DataMessage {
		err = binary.Write(bw, binary.BigEndian, int64(len(msg.Data)))
		if err != nil {
			return n, err
		}
		n += 8
		sz, err := bw.Write(msg.Data)
		n += sz
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func (uuid UUID) String() string {
	return hex.EncodeToString(uuid[:])
}

var generator = fastuuid.MustNewGenerator()

func New(conn net.Conn) *Multiplexer {
	m := &Multiplexer{
		conn:    conn,
		accept:  make(chan *Conn),
		streams: make(map[UUID]*Conn),
	}
	go m.dispatch()
	return m
}

func (m *Multiplexer) dispatch() {
	defer m.Close()

	br := bufio.NewReader(m.conn)
	var err error
	for {
		var msg Message
		err = msg.Read(br)
		if err != nil {
			break
		}

		m.mu.Lock()
		conn, ok := m.streams[msg.StreamID]
		if !ok {
			conn = NewConn(m, msg.StreamID)
			m.streams[msg.StreamID] = conn
		}
		m.mu.Unlock()

		if !ok {
			m.accept <- conn
		}
		conn.in <- msg
	}
}

// Accept waits for and returns the next connection to the listener.
func (m *Multiplexer) Accept() (c net.Conn, err error) {
	conn, ok := <-m.accept
	if !ok {
		return nil, io.EOF
	}
	return conn, nil
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (m *Multiplexer) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	streams := m.streams
	m.streams = nil
	m.closed = true
	m.mu.Unlock()

	m.closed = true
	for _, stream := range streams {
		stream.Close()
	}
	close(m.accept)
	return m.conn.Close()
}

// Addr returns the listener's network address.
func (m *Multiplexer) Addr() net.Addr {
	return m.conn.LocalAddr()
}

// Create a new stream
func (m *Multiplexer) Open() (c net.Conn, err error) {
	conn := NewConn(m, generator.Next())
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.streams[conn.id] = conn
	m.mu.Unlock()

	return conn, nil
}

func (m *Multiplexer) Write(msg Message) (int, error) {
	m.writeLock.Lock()
	sz, err := msg.Write(m.conn)
	defer m.writeLock.Unlock()

	return sz, err
}

func (m *Multiplexer) unregister(conn *Conn) {
	m.mu.Lock()
	delete(m.streams, conn.id)
	close(conn.in)
	m.mu.Unlock()
	m.Write(Message{conn.id, CloseMessage, nil})
}
