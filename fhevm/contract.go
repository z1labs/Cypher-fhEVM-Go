package fhevm

import "github.com/ethereum/go-ethereum/common"

type Contract interface {
	Address() common.Address
}
