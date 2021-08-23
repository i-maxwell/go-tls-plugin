package tls

import (
	"crypto/x509"
	"errors"
	"fmt"
	"unicode/utf8"
)

type pskKeyAgreement struct {
	identityHint []byte // provided by serrver and stashed by client
}

func (ka *pskKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {

	hint := []byte("bint")

	if hint == nil {
		return nil, nil
	}

	skx := new(serverKeyExchangeMsg)
	skx.key = make([]byte, 2+len(hint))
	skx.key[0] = byte(len(hint) >> 8)
	skx.key[1] = byte(len(hint))
	copy(skx.key[2:], hint)

	return skx, nil
}

func (ka *pskKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	if config == nil || len(config.Certificates) == 0 || len(config.Certificates[0].Certificate) < 2 {
		return nil, errClientKeyExchange
	}
	identityBytes, rest, ok := parseUint16Chunk(ckx.ciphertext)
	if !ok || len(rest) != 0 {
		return nil, errClientKeyExchange
	}
	if string(identityBytes) != string(config.Certificates[0].Certificate[0]) {
		return nil, errClientKeyExchange
	}

	// RFC 4279 5.1 says it MUST be utf8
	if !utf8.Valid(identityBytes) {
		return nil, errors.New("tls: received invalid PSK identity")
	}

	psk := config.Certificates[0].Certificate[1]
	fmt.Println(psk)
	lenPsk := len(psk)
	// TODO(movits) here is where you'd alert unknown identity

	preMasterSecret := make([]byte, 2*lenPsk+4) // RFC4279 specifies an null-filled other_secret of the same length as PSK
	preMasterSecret[0] = byte(lenPsk >> 8)
	preMasterSecret[1] = byte(lenPsk)
	preMasterSecret[lenPsk+2] = preMasterSecret[0] // the actual PSK begins here
	preMasterSecret[lenPsk+3] = preMasterSecret[1]
	copy(preMasterSecret[lenPsk+4:], psk)

	return preMasterSecret, nil
}

func (ka *pskKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	// per RFC 4279 server can send a "identity hint", so stash it in the ka
	hint, rest, ok := parseUint16Chunk(skx.key)
	if !ok || len(rest) != 0 {
		return errServerKeyExchange
	}
	ka.identityHint = hint

	return nil
}

func (ka *pskKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if config == nil || len(config.Certificates) == 0 || len(config.Certificates[0].Certificate) < 2 {
		return nil, nil, errClientKeyExchange
	}
	identity := config.Certificates[0].Certificate[0]
	lenIdentity := len(identity)

	psk := config.Certificates[0].Certificate[1]
	lenPsk := len(psk)

	ckx := new(clientKeyExchangeMsg)
	ckx.ciphertext = make([]byte, 2+lenIdentity)
	ckx.ciphertext[0] = byte(lenIdentity >> 8)
	ckx.ciphertext[1] = byte(lenIdentity)
	copy(ckx.ciphertext[2:], identity)

	preMasterSecret := make([]byte, 2*lenPsk+4) // RFC4279 specifies an null-filled other_secret of the same length as PSK
	preMasterSecret[0] = byte(lenPsk >> 8)
	preMasterSecret[1] = byte(lenPsk)
	preMasterSecret[lenPsk+2] = preMasterSecret[0] // the actual PSK begins here
	preMasterSecret[lenPsk+3] = preMasterSecret[1]
	copy(preMasterSecret[lenPsk+4:], psk)

	return preMasterSecret, ckx, nil
}

// returns chunk, rest, ok
func parseUint16Chunk(data []byte) ([]byte, []byte, bool) {
	if len(data) < 2 {
		return nil, nil, false
	}
	length := int(data[0])<<8 | int(data[1])
	if len(data) < 2+length {
		return nil, nil, false
	}
	chunk := data[2 : 2+length]
	return chunk, data[2+length:], true
}
