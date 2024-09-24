package fhevm

import "github.com/holiman/uint256"

type Memory interface {
	Set(offset, size uint64, value []byte)
	Set32(offset uint64, val *uint256.Int)
	Resize(size uint64)
	GetCopy(offset, size int64) (cpy []byte)
	GetPtr(offset, size int64) []byte
	Len() int
	Data() []byte
}
