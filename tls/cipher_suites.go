package tls

import "crypto/cipher"

type macFunction interface {
	Size() int
	MAC(digestBuf, seq, header, data, extra []byte) []byte
}

type aead interface {
	cipher.AEAD

	// explicitIVLen returns the number of bytes used by the explicit nonce
	// that is included in the record. This is eight for older AEADs and
	// zero for modern ones.
	explicitNonceLen() int
}
