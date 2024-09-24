package fhevm

import (
	"encoding/hex"
	"fmt"
	"math/bits"

	"github.com/holiman/uint256"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

func fheRandRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(1, len(input))]

	logger := environment.GetLogger()
	if len(input) != 1 || !tfhe.IsValidFheType(input[0]) {
		logger.Error("fheRand RequiredGas() input len must be at least 1 byte and be a valid FheUint type", "input", hex.EncodeToString(input), "len", len(input))
		return 0
	}
	t := tfhe.FheUintType(input[0])
	return environment.FhevmParams().GasCosts.FheRand[t]
}

func parseRandUpperBoundInput(input []byte) (randType tfhe.FheUintType, upperBound *uint256.Int, err error) {
	if len(input) != 33 || !tfhe.IsValidFheType(input[32]) {
		return tfhe.FheUint8, nil, fmt.Errorf("parseRandUpperBoundInput() invalid input len or type")
	}
	randType = tfhe.FheUintType(input[32])
	upperBound = uint256.NewInt(0)
	upperBound.SetBytes32(input)
	// For now, we only support bounds of up to 64 bits.
	if !upperBound.IsUint64() {
		return tfhe.FheUint8, nil, fmt.Errorf("parseRandUpperBoundInput() only supports bounds up to 64 bits")
	}
	upperBound64 := upperBound.Uint64()
	oneBits := bits.OnesCount64(upperBound64)
	if oneBits != 1 {
		return tfhe.FheUint8, nil, fmt.Errorf("parseRandUpperBoundInput() bound not a power of 2: %d", upperBound64)
	}
	return randType, upperBound, nil
}

func fheRandBoundedRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(33, len(input))]

	logger := environment.GetLogger()
	randType, _, err := parseRandUpperBoundInput(input)
	if err != nil {
		logger.Error("fheRandBounded RequiredGas() bound error", "input", hex.EncodeToString(input), "err", err)
		return 0
	}
	return environment.FhevmParams().GasCosts.FheRand[randType]
}
