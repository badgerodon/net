package multiplex

import (
	"io/ioutil"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMultiplexer(t *testing.T) {
	assert := assert.New(t)
	assert.Nil(nil)

	l, err := net.Listen("tcp", ":49999")
	assert.Nil(err)
	defer l.Close()

	done := make(chan struct{}, 2)

	go func() {
		c1, err := l.Accept()
		assert.Nil(err)
		defer c1.Close()

		m1 := New(c1)
		defer m1.Close()

		cc1, err := m1.Accept()
		assert.Nil(err)
		bs, err := ioutil.ReadAll(cc1)
		cc1.Close()
		assert.Equal("Hello World", string(bs))

		cc2, err := m1.Accept()
		assert.Nil(err)
		bs, err = ioutil.ReadAll(cc2)
		cc2.Close()
		assert.Equal("Not Hello World", string(bs))

		done <- struct{}{}
	}()

	go func() {
		c2, err := net.Dial("tcp", l.Addr().String())
		assert.Nil(err)
		defer c2.Close()

		m2 := New(c2)
		defer m2.Close()

		cc1, err := m2.Open()
		assert.Nil(err)
		cc1.Write([]byte("Hello World"))
		cc1.Close()

		cc2, err := m2.Open()
		assert.Nil(err)
		cc2.Write([]byte("Not Hello World"))
		cc2.Close()

		done <- struct{}{}
	}()

	for i := 0; i < 2; i++ {
		<-done
	}
}
