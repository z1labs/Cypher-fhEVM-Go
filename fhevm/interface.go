package fhevm

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

type EVMEnvironment interface {
	// StateDB related functions
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash)
	GetNonce(common.Address) uint64
	AddBalance(common.Address, *big.Int)
	GetBalance(common.Address) *big.Int

	Suicide(common.Address) bool

	// EVM call stack depth
	GetDepth() int

	// EVM Logger
	GetLogger() Logger

	// TODO: clarify meaning of the following
	IsCommitting() bool
	IsEthCall() bool
	IsReadOnly() bool

	CreateContract(caller common.Address, code []byte, gas uint64, value *big.Int, address common.Address) ([]byte, common.Address, uint64, error)
	CreateContract2(caller common.Address, code []byte, codeHash common.Hash, gas uint64, value *big.Int, address common.Address) ([]byte, common.Address, uint64, error)

	FhevmData() *FhevmData
	FhevmParams() *FhevmParams

	// This should return the context used for OpenTelemetry in the current EVM.
	// It should be considered the root context for every op that runs in the EVM, and all spans created from this context
	// would be child spans for what has been already created using the context.
	// Implementations returning nil would disable OpenTelemetry on the fhEVM
	OtelContext() context.Context
}

type FhevmData struct {
	// A map from a ciphertext hash to the ciphertext itself.
	loadedCiphertexts map[common.Hash]*tfhe.TfheCiphertext

	// A map from the hash of the ciphertext list to an array of expanded ciphertexts.
	expandedInputCiphertexts map[common.Hash][]*tfhe.TfheCiphertext

	nextCiphertextHashOnGasEst uint256.Int
}

func NewFhevmData() FhevmData {
	return FhevmData{
		loadedCiphertexts: make(map[common.Hash]*tfhe.TfheCiphertext),
	}
}
