package fhevm

import (
	"encoding/hex"

	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

func fheAddSubRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()
	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheAdd/Sub RequiredGas() can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	loadGas := uint64(0)
	var lhs, rhs *tfhe.TfheCiphertext
	if !isScalar {
		lhs, rhs, loadGas, err = load2Ciphertexts(environment, input)
		if err != nil {
			//logger.Error("fheAdd/Sub RequiredGas() ciphertext failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return loadGas
		}
		if lhs.Type() != rhs.Type() {
			//logger.Error("fheAdd/Sub RequiredGas() operand type mismatch", "lhs", lhs.Type(), "rhs", rhs.Type())
			return loadGas
		}
	} else {
		lhs, _, loadGas, err = getScalarOperands(environment, input)
		if err != nil {
			//logger.Error("fheAdd/Sub RequiredGas() scalar failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return loadGas
		}
	}

	return environment.FhevmParams().GasCosts.FheAddSub[lhs.Type()] + loadGas
}

func fheMulRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()
	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheMul RequiredGas() can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	if !isScalar {
		lhs, rhs, loadGas, err := load2Ciphertexts(environment, input)
		if err != nil {
			logger.Error("fheMul RequiredGas() ciphertext failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return loadGas
		}
		if lhs.Type() != rhs.Type() {
			logger.Error("fheMul RequiredGas() operand type mismatch", "lhs", lhs.Type(), "rhs", rhs.Type())
			return loadGas
		}
		return environment.FhevmParams().GasCosts.FheMul[lhs.Type()] + loadGas
	} else {
		lhs, _, loadGas, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheMul RequiredGas() scalar failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return loadGas
		}
		return environment.FhevmParams().GasCosts.FheScalarMul[lhs.Type()] + loadGas
	}
}

func fheDivRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()
	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheDiv RequiredGas() cannot detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return 0
	}

	if !isScalar {
		logger.Error("fheDiv RequiredGas() only scalar in division is supported, two ciphertexts received", "input", hex.EncodeToString(input))
		return 0
	} else {
		lhs, _, loadGas, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheDiv RequiredGas() scalar failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return loadGas
		}
		return environment.FhevmParams().GasCosts.FheScalarDiv[lhs.Type()] + loadGas
	}
}

func fheRemRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()
	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheRem RequiredGas() cannot detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	if !isScalar {
		logger.Error("fheRem RequiredGas() only scalar in division is supported, two ciphertexts received", "input", hex.EncodeToString(input))
		return 0
	} else {
		lhs, _, loadGas, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheRem RequiredGas() scalar failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return loadGas
		}
		return environment.FhevmParams().GasCosts.FheScalarRem[lhs.Type()] + loadGas
	}
}
