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

func HashParent(left, right Node) (*[]byte, error) {
	var node1, node2 Node
	if left.Index <= right.Index {
		node1 = left
		node2 = right
	} else {
		node1 = right
		node2 = left
	}

	var tempBytes []byte
	binary.BigEndian.PutUint64(tempBytes, uint64(node1.Length+node2.Length))

	var blakeList [][]byte
	blakeList = make([][]byte, 4)
	blakeList = append(blakeList, parentType)
	blakeList = append(blakeList, tempBytes)
	blakeList = append(blakeList, node1.Hash)
	blakeList = append(blakeList, node2.Hash)
	return Blake2bList(blakeList)
}

func HashTree(roots []Node) (*[]byte, error) {
	var hashList [][]byte
	hashList = make([][]byte, 3*len(roots)+1)

	for i := 0; i < len(roots); i++ {
		hashList = append(hashList, roots[i].Hash)
		var tempBytesIndex, tempBytesLength []byte
		tempBytesIndex = make([]byte, 8)
		tempBytesLength = make([]byte, 8)
		hashList = append(hashList, binary.BigEndian.PutUint64(tempBytesIndex, uint64(roots[i].Index)))
		hashList = append(hashList, binary.BigEndian.PutUint64(tempBytesLength, uint64(roots[i].Length)))
	}
	return Blake2bList(hashList)
}

func Data(data []byte) (*[]byte, error) {
	return Blake2bList([][]byte{data})
}
