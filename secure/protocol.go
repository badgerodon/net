package secure

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"

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
		return err
	}
	p.aead, err = cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// the encrypted data is the peer's token
	p.rt, err = p.aead.Open(nil, msg.Nonce, msg.Data, msg.Tag)
	if err != nil {
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
	nonce := make([]byte, 12)
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return err
	}

	sealed := p.aead.Seal(nil, nonce, data, p.rt)

	if p.Debug {
		log.Printf("[secure] write nonce=%v, tag=%v, data=%v\n", nonce, p.rt, sealed)
	}

	msg := Message{
		Nonce: nonce,
		Data:  sealed,
		Tag:   p.rt,
	}
	err = p.writer.WriteMessage(msg)
	if err != nil {
		return err
	}
	increment(p.rt)
	return nil
}
