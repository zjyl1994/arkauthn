package utils

import "crypto/sha256"

func SHA256(input []byte) []byte {
	h := sha256.New()
	h.Write(input)
	return h.Sum(nil)
}
