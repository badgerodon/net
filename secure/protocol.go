package secure

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log"
	"net"

	"fmt"
)

type (
	Message struct {
		Nonce []byte
		Data  []byte
		Tag   []byte
	}
	Reader interface {
		ReadMessage() (Message, error)
	}
	ReaderFunc func() (Message, error)
	Writer     interface {
		WriteMessage(Message) error
	}
	WriterFunc func(Message) error
	Protocol   struct {
		Debug  bool
		reader Reader
		writer Writer
		lt, rt []byte
		aead   cipher.AEAD
	}
)

func increment(bs []byte) {
	for i := len(bs) - 1; i >= 0; i-- {
		if bs[i] == 255 {
			bs[i] = 0
		} else {
			bs[i]++
			break
		}
	}
}

func (rf ReaderFunc) ReadMessage() (Message, error) {
	return rf()
}
func (wf WriterFunc) WriteMessage(msg Message) error {
	return wf(msg)
}

func NewProtocol(reader Reader, writer Writer) *Protocol {
	return &Protocol{
		reader: reader,
		writer: writer,
	}
}

func WrapConnection(conn net.Conn) *Protocol {
	return NewProtocol(
		ReaderFunc(func() (Message, error) {
			var sz uint64
			var msg Message
			err := binary.Read(conn, binary.BigEndian, &sz)
			if err != nil {
				return msg, err
			}
			buf := make([]byte, sz)
			_, err = io.ReadFull(conn, buf)
			if err != nil {
				return msg, err
			}
			return msg, msg.UnmarshalBytes(buf)
		}),
		WriterFunc(func(msg Message) error {
			data := msg.MarshalBytes()
			err := binary.Write(conn, binary.BigEndian, uint64(len(data)))
			if err != nil {
				return err
			}
			_, err = conn.Write(data)
			return err
		}),
	)
}

func (p *Protocol) Accept(keys map[string][]byte) error {
	// generate a token
	p.lt = make([]byte, 4)
	_, err := io.ReadFull(rand.Reader, p.lt)
	if err != nil {
		return err
	}
	if p.Debug {
		log.Printf("[secure] local-token=%v\n", p.lt)
	}

	// read the first message
	msg, err := p.reader.ReadMessage()
	if err != nil {
		if p.Debug {
			log.Printf("[secure] failed to open first message: %v\n", err)
		}
		return err
	}

	// the first message's tag is the key name
	key, ok := keys[string(msg.Tag)]
	if !ok {
		return fmt.Errorf("unknown key: %s", string(msg.Tag))
	}

	if p.Debug {
		log.Printf("[secure] key=%v\n", key)
	}

	// create an aes cipher to decode
	block, err := aes.NewCipher(key)
	if err != nil {
		if p.Debug {
			log.Printf("[secure] failed to create cipher: %v\n", err)
		}
		return err
	}
	p.aead, err = cipher.NewGCM(block)
	if err != nil {
		if p.Debug {
			log.Printf("[secure] failed to create gcm: %v\n", err)
		}
		return err
	}

	// the encrypted data is the peer's token
	p.rt, err = p.aead.Open(nil, msg.Nonce, msg.Data, msg.Tag)
	if err != nil {
		if p.Debug {
			log.Printf("[secure] failed to open second message: %v\n", err)
		}
		return err
	}
	if p.Debug {
		log.Printf("[secure] remote-token=%v\n", p.rt)
	}

	// write the local token
	err = p.Write(p.lt)
	if err != nil {
		return err
	}

	return nil
}

func (p *Protocol) Connect(name string, key []byte) error {
	// generate a token
	p.lt = make([]byte, 4)
	_, err := io.ReadFull(rand.Reader, p.lt)
	if err != nil {
		return err
	}
	if p.Debug {
		log.Printf("[secure] local-token=%v\n", p.lt)
	}

	// create an aes cipher to encode
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	p.aead, err = cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// write the local token
	err = p.write(p.lt, []byte(name))
	if err != nil {
		return err
	}

	// read the first message
	msg, err := p.Read()
	if err != nil {
		return err
	}

	p.rt = msg

	return nil
}

// Read the next message
func (p *Protocol) Read() ([]byte, error) {
	msg, err := p.reader.ReadMessage()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(msg.Tag, p.lt) {
		if p.Debug {
			log.Printf("[secure] invalid sequence number %v expected %v\n", msg.Tag, p.lt)
		}
		return nil, fmt.Errorf("invalid sequence number")
	}
	increment(p.lt)
	opened, err := p.aead.Open(nil, msg.Nonce, msg.Data, msg.Tag)
	if err != nil {
		return nil, err
	}

	if p.Debug {
		log.Printf("[secure] read message=%v\n", msg)
	}

	return opened, nil
}

// Write the message
func (p *Protocol) Write(data []byte) error {
	err := p.write(data, p.rt)
	increment(p.rt)
	if err != nil {
		return err
	}
	return nil
}

func (p *Protocol) write(data []byte, tag []byte) error {
	nonce := make([]byte, 12)
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return err
	}

	sealed := p.aead.Seal(nil, nonce, data, tag)

	if p.Debug {
		log.Printf("[secure] write nonce=%v, tag=%v, data=%v\n", nonce, p.rt, sealed)
	}

	msg := Message{
		Nonce: nonce,
		Data:  sealed,
		Tag:   tag,
	}
	err = p.writer.WriteMessage(msg)
	if err != nil {
		return err
	}
	return nil
}
