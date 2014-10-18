boxconn adds encryption and authentication to a network connection. It uses the NaCL [box](https://code.google.com/p/go/source/browse?repo=crypto) library to encrypt messages.

# Overview

I wanted something simpler than TLS, but still assymetric. Key distribution is entirely manual: every client / server should have their own set of keys, and their public keys should be added to their corresponding counterpart. For example a server will look like this:

    listener, _ := boxconn.Listen("tcp",":5000", serverPrivateKey, serverPublicKey, clientPublicKey)

    for {
    	conn, _ := listener.Accept()

    	...
    }

And the client will look like this:

    conn, _ := boxconn.Dial("tcp", ":5000", clientPrivateKey, clientPublicKey, serverPublicKey)

If you already have a connection you can use `Handshake`:

    bc, _ := boxconn.Handshake(conn, clientPrivateKey, clientPublicKey, serverPublicKey)

To generate keys use code.google.com/p/go.crypto/nacl/box:

    // these are *[32]byte not [32]byte so you'll need to do
    //   *clientPrivateKey, *clientPublicKey, *serverPublicKey
    publicKey, privateKey, err := box.GenerateKey()

Keys are pretty small and are just byte arrays so you can store / marshal them however you want.

# Tips

* Although this library is very simple and is built on top of a pretty solid foundation, I'm not entirely sure it's secure. You're probably better off using TLS. But its a bit of a chore to setup everything. You'll need to create a root CA certificate, then sign all your private keys, and enforce verification using TLS config.
  Then again TLS hasn't had the best track record lately. Major vulnerabilites seem to be discovered about twice a year or so. [1](http://blogs.msdn.com/b/kaushal/archive/2011/10/03/taming-the-beast-browser-exploit-against-ssl-tls.aspx), [2](http://en.wikipedia.org/wiki/CRIME), [3](http://en.wikipedia.org/wiki/CRIME), [4](http://en.wikipedia.org/wiki/BREACH_(security_exploit)), [4](http://en.wikipedia.org/wiki/Lucky_Thirteen_attack), [5](http://en.wikipedia.org/wiki/POODLE), [6](http://en.wikipedia.org/wiki/Heartbleed)

* The library encrypts every `Write` as a separate message. You should probably use buffering on top of the connection (not a terrible idea anyway), or just be careful about not writing super small messages. It will work, and it's still secure, it's just inefficient.