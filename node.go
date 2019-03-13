package gohypercorecrypto

import (
	"github.com/SirRujak/goflattree"
)

type Node struct {
	Index  uint
	Hash   []uint8
	Length uint
	Parent uint
	Data   *[]uint8
}

func (node *Node) New(index uint, hash []uint8, length uint) {
	node.Index = index
	node.Hash = hash
	node.Length = length
	node.Parent = goflattree.Parent(index)
	var tempData = make([]uint8, 0, 0)
	node.Data = &tempData
}
