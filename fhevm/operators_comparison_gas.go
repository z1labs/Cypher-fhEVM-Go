package fhevm

import (
	"encoding/hex"
	"fmt"

	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

func fheLeRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()
	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("comparison RequiredGas() can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	var lhs, rhs *tfhe.TfheCiphertext
	loadGas := uint64(0)
	if !isScalar {
		lhs, rhs, loadGas, err = load2Ciphertexts(environment, input)
		if err != nil {
			logger.Error("comparison RequiredGas() failed to load input ciphertexts", "err", err, "input", hex.EncodeToString(input))
			return loadGas
		}
		if lhs.Type() != rhs.Type() {
			logger.Error("comparison RequiredGas() operand type mismatch", "lhs", lhs.Type(), "rhs", rhs.Type())
			return loadGas
		}
	} else {
		lhs, _, loadGas, err = getScalarOperands(environment, input)
		if err != nil {
			logger.Error("comparison RequiredGas() scalar failed to load input ciphertexts", "err", err, "input", hex.EncodeToString(input))
			return loadGas
		}
	}
	return environment.FhevmParams().GasCosts.FheLe[lhs.Type()] + loadGas
}

func fheLtRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of le, because le and lt costs are currently the same.
	return fheLeRequiredGas(environment, input)
}

func fheEqRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()
	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("comparison RequiredGas() can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	var lhs, rhs *tfhe.TfheCiphertext
	loadGas := uint64(0)
	if !isScalar {
		lhs, rhs, loadGas, err = load2Ciphertexts(environment, input)
		if err != nil {
			logger.Error("comparison RequiredGas() failed to load input ciphertexts", "err", err, "input", hex.EncodeToString(input))
			return loadGas
		}
		if lhs.Type() != rhs.Type() {
			logger.Error("comparison RequiredGas() operand type mismatch", "lhs", lhs.Type(), "rhs", rhs.Type())
			return loadGas
		}
	} else {
		lhs, _, loadGas, err = getScalarOperands(environment, input)
		if err != nil {
			logger.Error("comparison RequiredGas() scalar failed to load input ciphertexts", "err", err, "input", hex.EncodeToString(input))
			return loadGas
		}
	}
	return environment.FhevmParams().GasCosts.FheEq[lhs.Type()] + loadGas
}

func fheGeRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of le, because comparison costs are currently the same.
	return fheLeRequiredGas(environment, input)
}

func fheGtRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of le, because comparison costs are currently the same.
	return fheLeRequiredGas(environment, input)
}

func fheNeRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of le, because comparison costs are currently the same.
	return fheEqRequiredGas(environment, input)
}

func fheMinRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()
	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheMin/Max RequiredGas() can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	if !isScalar {
		lhs, rhs, loadGas, err := load2Ciphertexts(environment, input)
		if err != nil {
			logger.Error("fheMin/Max RequiredGas() failed to load input ciphertexts", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
		if lhs.Type() != rhs.Type() {
			logger.Error("fheMin/Max RequiredGas() operand type mismatch", "lhs", lhs.Type(), "rhs", rhs.Type())
			return 0
		}
		return environment.FhevmParams().GasCosts.FheMinMax[lhs.Type()] + loadGas
	} else {
		lhs, _, loadGas, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheMin/Max RequiredGas() scalar failed to load input ciphertexts", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
		return environment.FhevmParams().GasCosts.FheScalarMinMax[lhs.Type()] + loadGas
	}
}

func fheMaxRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of min, because costs are currently the same.
	return fheMinRequiredGas(environment, input)
}

func fheIfThenElseRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(96, len(input))]

	logger := environment.GetLogger()
	first, second, third, loadGas, err := load3Ciphertexts(environment, input)
	if err != nil {
		logger.Error("IfThenElse op RequiredGas()failed to load input ciphertexts", "err", err, "input", hex.EncodeToString(input))
		return loadGas
	}
	if first.Type() != tfhe.FheBool {
		logger.Error("IfThenElse op RequiredGas() invalid type for condition", "first", first.Type())
		return loadGas
	}
	if second.Type() != third.Type() {
		logger.Error("IfThenElse op RequiredGas() operand type mismatch", "second", second.Type(), "third", third.Type())
		return loadGas
	}
	return environment.FhevmParams().GasCosts.FheIfThenElse[second.Type()] + loadGas
}

func fheArrayEqRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()

	unpacked, err := arrayEqMethod.Inputs.UnpackValues(input)
	if err != nil {
		msg := "fheArrayEqRun RequiredGas() failed to unpack input"
		logger.Error(msg, "err", err)
		return 0
	}

	if len(unpacked) != 2 {
		err := fmt.Errorf("fheArrayEqRun RequiredGas() unexpected unpacked len: %d", len(unpacked))
		logger.Error(err.Error())
		return 0
	}

	lhs, lhsLoadGas, err := getVerifiedCiphertexts(environment, unpacked[0])
	if err != nil {
		msg := "fheArrayEqRun RequiredGas() failed to get lhs to verified ciphertexts"
		logger.Error(msg, "err", err)
		return lhsLoadGas
	}

	rhs, rhsLoadGas, err := getVerifiedCiphertexts(environment, unpacked[1])
	if err != nil {
		msg := "fheArrayEqRun RequiredGas() failed to get rhs to verified ciphertexts"
		logger.Error(msg, "err", err)
		return lhsLoadGas + rhsLoadGas
	}

	totalLoadGas := lhsLoadGas + rhsLoadGas

	if len(lhs) != len(rhs) || (len(lhs) == 0 && len(rhs) == 0) {
		return environment.FhevmParams().GasCosts.FheTrivialEncrypt[tfhe.FheBool] + totalLoadGas
	}

	numElements := len(lhs)
	elementType := lhs[0].Type()
	// TODO: tie to supported types in tfhe.TfheCiphertext.EqArray()
	if elementType != tfhe.FheUint4 && elementType != tfhe.FheUint8 && elementType != tfhe.FheUint16 && elementType != tfhe.FheUint32 && elementType != tfhe.FheUint64 {
		return totalLoadGas
	}
	for i := range lhs {
		if lhs[i].Type() != elementType || rhs[i].Type() != elementType {
			return totalLoadGas
		}
	}

	numBits := elementType.NumBits() * uint(numElements)
	if numBits <= 4 {
		return environment.FhevmParams().GasCosts.FheEq[tfhe.FheUint4] + totalLoadGas
	} else if numBits <= 8 {
		return environment.FhevmParams().GasCosts.FheEq[tfhe.FheUint8] + totalLoadGas
	} else if numBits <= 16 {
		return environment.FhevmParams().GasCosts.FheEq[tfhe.FheUint16] + totalLoadGas
	} else if numBits <= 32 {
		return environment.FhevmParams().GasCosts.FheEq[tfhe.FheUint32] + totalLoadGas
	} else if numBits <= 64 {
		return environment.FhevmParams().GasCosts.FheEq[tfhe.FheUint64] + totalLoadGas
	} else if numBits <= 160 {
		return environment.FhevmParams().GasCosts.FheEq[tfhe.FheUint160] + totalLoadGas
	} else {
		return ((environment.FhevmParams().GasCosts.FheEq[tfhe.FheUint160] + environment.FhevmParams().GasCosts.FheArrayEqBigArrayFactor) * (uint64(numBits) / 160)) + totalLoadGas
	}
}
