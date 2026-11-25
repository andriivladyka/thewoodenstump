// Package merkle builds the root that anchor records: leaves are sorted,
// and each pair is hashed in sorted order (as OpenZeppelin's MerkleProof
// expects), so a proof needs no left/right flags.
package merkle

import (
	"bytes"
	"sort"

	"github.com/ethereum/go-ethereum/crypto"
)

// Leaf hashes one credential event.
func Leaf(parts ...string) [32]byte {
	var b []byte
	for i, p := range parts {
		if i > 0 {
			b = append(b, 0)
		}
		b = append(b, p...)
	}
	return crypto.Keccak256Hash(b)
}

// Root returns the root of the leaves, or all zeros for none.
func Root(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return [32]byte{}
	}
	level := append([][32]byte(nil), leaves...)
	sort.Slice(level, func(i, j int) bool { return bytes.Compare(level[i][:], level[j][:]) < 0 })
	for len(level) > 1 {
		var next [][32]byte
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				continue
			}
			next = append(next, pair(level[i], level[i+1]))
		}
		level = next
	}
	return level[0]
}

func pair(a, b [32]byte) [32]byte {
	if bytes.Compare(a[:], b[:]) > 0 {
		a, b = b, a
	}
	return crypto.Keccak256Hash(a[:], b[:])
}
