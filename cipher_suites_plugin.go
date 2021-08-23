package tls

const (
	TLS_PSK_WITH_AES_128_CBC_SHA uint16 = 0x008C
	TLS_PSK_WITH_AES_256_CBC_SHA uint16 = 0x008D
)

func init() {
	/*
		{TLS_PSK_WITH_AES_256_CBC_SHA, 32, 20, 16, pskKA, suiteDefaultOff, cipherAES, macSHA1, nil},
			{TLS_PSK_WITH_AES_128_CBC_SHA, 16, 20, 16, pskKA, suiteDefaultOff, cipherAES, macSHA1, nil},
	*/
	cipherSuites = append(cipherSuites, &cipherSuite{TLS_PSK_WITH_AES_256_CBC_SHA, 32, 20, 16, pskKA, suiteDefaultOff, cipherAES, macSHA1, nil})
	cipherSuites = append(cipherSuites, &cipherSuite{TLS_PSK_WITH_AES_128_CBC_SHA, 16, 20, 16, pskKA, suiteDefaultOff, cipherAES, macSHA1, nil})
}

func pskKA(version uint16) keyAgreement {
	return &pskKeyAgreement{}
}
