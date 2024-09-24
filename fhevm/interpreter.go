package fhevm

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

type ScopeContext interface {
	GetMemory() Memory
	GetStack() Stack
	GetContract() Contract
}

type depthSet struct {
	m map[int]struct{}
}

func newDepthSet() *depthSet {
	s := &depthSet{}
	s.m = make(map[int]struct{})
	return s
}

func (s *depthSet) add(v int) {
	s.m[v] = struct{}{}
}

func (s *depthSet) del(v int) {
	delete(s.m, v)
}

func (s *depthSet) has(v int) bool {
	_, found := s.m[v]
	return found
}

func (s *depthSet) count() int {
	return len(s.m)
}

func (from *depthSet) clone() (to *depthSet) {
	to = newDepthSet()
	for k := range from.m {
		to.add(k)
	}
	return
}

type verifiedCiphertext struct {
	verifiedDepths *depthSet
	ciphertext     *tfhe.TfheCiphertext
}

// Returns the type of the verified ciphertext
func (vc *verifiedCiphertext) fheUintType() tfhe.FheUintType {
	return vc.ciphertext.FheUintType
}

// Returns the serialization of the verified ciphertext
func (vc *verifiedCiphertext) serialization() []byte {
	return vc.ciphertext.Serialization
}

// Returns the hash of the verified ciphertext
func (vc *verifiedCiphertext) hash() common.Hash {
	return vc.ciphertext.GetHash()
}
