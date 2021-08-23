package tls

import "errors"

// HandshakeWithPsk
func (c *Conn) HandshakeWithPsk() error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if err := c.handshakeErr; err != nil {
		return err
	}
	if c.handshakeComplete() {
		return nil
	}

	c.in.Lock()
	defer c.in.Unlock()

	if c.isClient {
		c.handshakeErr = c.clientHandshakeWithPsk()
	} else {
		c.handshakeErr = c.serverHandshake()
	}
	if c.handshakeErr == nil {
		c.handshakes++
	} else {
		// If an error occurred during the hadshake try to flush the
		// alert that might be left in the buffer.
		c.flush()
	}

	if c.handshakeErr == nil && !c.handshakeComplete() {
		c.handshakeErr = errors.New("tls: internal error: handshake should have had a result")
	}

	return c.handshakeErr
}
