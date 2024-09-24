package fhevm

import "github.com/holiman/uint256"

type Stack interface {
	Pop() uint256.Int
	Peek() *uint256.Int
}
