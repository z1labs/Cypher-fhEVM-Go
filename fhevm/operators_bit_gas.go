package fhevm

import (
	"encoding/hex"

	"github.com/ethereum/go-ethereum/common"
)

func fheShlRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()
	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheShift RequiredGas() can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	if !isScalar {
		lhs, rhs, loadGas, err := load2Ciphertexts(environment, input)
		if err != nil {
			logger.Error("fheShift RequiredGas() ciphertext failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return loadGas
		}
		if lhs.Type() != rhs.Type() {
			logger.Error("fheShift RequiredGas() operand type mismatch", "lhs", lhs.Type(), "rhs", rhs.Type())
			return loadGas
		}
		return environment.FhevmParams().GasCosts.FheShift[lhs.Type()] + loadGas
	} else {
		lhs, _, loadGas, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheShift RequiredGas() scalar failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return loadGas
		}
		return environment.FhevmParams().GasCosts.FheScalarShift[lhs.Type()] + loadGas
	}
}

func fheShrRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of shl, because comparison costs are currently the same.
	return fheShlRequiredGas(environment, input)
}

func fheRotrRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of shl, because comparison costs are currently the same.
	return fheShlRequiredGas(environment, input)
}

func fheRotlRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of shl, because comparison costs are currently the same.
	return fheShlRequiredGas(environment, input)
}

func fheNegRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(32, len(input))]

	logger := environment.GetLogger()
	if len(input) != 32 {
		logger.Error("fheNeg input needs to contain one 256-bit sized value", "input", hex.EncodeToString(input))
		return 0
	}
	ct, loadGas := loadCiphertext(environment, common.BytesToHash(input[0:32]))
	if ct == nil {
		logger.Error("fheNeg failed to load input", "input", hex.EncodeToString(input))
		return loadGas
	}
	return environment.FhevmParams().GasCosts.FheNeg[ct.Type()] + loadGas
}

func fheNotRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(32, len(input))]

	logger := environment.GetLogger()
	if len(input) != 32 {
		logger.Error("fheNot input needs to contain one 256-bit sized value", "input", hex.EncodeToString(input))
		return 0
	}
	ct, loadGas := loadCiphertext(environment, common.BytesToHash(input[0:32]))
	if ct == nil {
		logger.Error("fheNot failed to load input", "input", hex.EncodeToString(input))
		return loadGas
	}
	return environment.FhevmParams().GasCosts.FheNot[ct.Type()] + loadGas
}

func fheBitAndRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("Bitwise op RequiredGas() can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return 0
	}

	if isScalar {
		msg := "Bitwise op RequiredGas() scalar op not supported"
		logger.Error(msg)
		return 0
	}

	lhs, rhs, loadGas, err := load2Ciphertexts(environment, input)
	if err != nil {
		logger.Error("Bitwise op RequiredGas() failed to load inputs", "err", err, "input", hex.EncodeToString(input))
		return loadGas
	}
	if lhs.Type() != rhs.Type() {
		logger.Error("Bitwise op RequiredGas() operand type mismatch", "lhs", lhs.Type(), "rhs", rhs.Type())
		return loadGas
	}
	return environment.FhevmParams().GasCosts.FheBitwiseOp[lhs.Type()] + loadGas
}

func fheBitOrRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of bitAnd, because bitwise op costs are currently the same.
	return fheBitAndRequiredGas(environment, input)
}

func fheBitXorRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of bitAnd, because bitwise op costs are currently the same.
	return fheBitAndRequiredGas(environment, input)
}
