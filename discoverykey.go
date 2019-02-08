package gohypercorecrypto

import (
	"hash"

	"golang.org/x/crypto/blake2b"
)

var hypercore []byte = []byte("hypercore")

func DiscoveryKey(tree []byte) (sum []byte) {
	var h hash.Hash
	h, _ = blake2b.New256(tree)
	h.Write(hypercore)
	return h.Sum(sum)
}
