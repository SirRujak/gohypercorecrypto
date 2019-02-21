package gohypercorecrypto

import (
	"encoding/binary"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ed25519"
)

var leafType []byte = []byte{0}
var parentType []byte = []byte{1}
var rootType []byte = []byte{2}

type KeyPair struct {
	PublicKey []byte
	SecretKey []byte
}

func GenKeyPair(seed []byte) (*KeyPair, error) {
	var publicKey, secretKey []byte
	var err error
	publicKey, secretKey, err = ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	var newKeyPair KeyPair
	newKeyPair = KeyPair{
		PublicKey: publicKey,
		SecretKey: secretKey,
	}
	return &newKeyPair, nil
}

func Sign(message, secretKey []byte) []byte {
	var signature []byte
	signature = ed25519.Sign(secretKey, message)
	return signature
}

func Verify(message, signature, publicKey []byte) bool {
	return ed25519.Verify(publicKey, message, signature)
}

func Blake2bList(byteSlices [][]byte) (sum *[]byte, err error) {
	var h hash.Hash
	h, _ = blake2b.New(32, nil)
	for i := 0; i < len(byteSlices); i++ {
		_, err = h.Write(byteSlices[i])
		if err != nil {
			return nil, err
		}
	}
	h.Sum(*sum)
	return sum, nil
}

func HashLeaf(data []byte) (sum []byte) {
	var bSize []byte
	bSize = make([]byte, 4)
	var size uint64
	size = uint64(len(data))
	binary.BigEndian.PutUint64(bSize, size)

	var h hash.Hash
	h, _ = blake2b.New(32, nil)
	h.Write(leafType)
	h.Write(bSize)
	h.Write(data)
	return h.Sum(sum)
}
