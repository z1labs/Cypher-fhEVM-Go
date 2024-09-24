package fhevm

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"go.opentelemetry.io/otel/trace"
)

func fheLeRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheLe can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, _, err := load2Ciphertexts(environment, input)
		if err != nil {
			logger.Error("fheLe failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if lhs.Type() != rhs.Type() {
			msg := "fheLe operand type mismatch"
			logger.Error(msg, "lhs", lhs.Type(), "rhs", rhs.Type())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, tfhe.FheBool), nil
		}

		result, err := lhs.Le(rhs)
		if err != nil {
			logger.Error("fheLe failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheLe success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.GetHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, _, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheLe scalar failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, tfhe.FheBool), nil
		}

		result, err := lhs.ScalarLe(rhs)
		if err != nil {
			logger.Error("fheLe failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheLe scalar success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheLtRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheLt can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, _, err := load2Ciphertexts(environment, input)
		if err != nil {
			logger.Error("fheLt failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if lhs.Type() != rhs.Type() {
			msg := "fheLt operand type mismatch"
			logger.Error(msg, "lhs", lhs.Type(), "rhs", rhs.Type())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, tfhe.FheBool), nil
		}

		result, err := lhs.Lt(rhs)
		if err != nil {
			logger.Error("fheLt failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheLt success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.GetHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, _, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheLt scalar failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, tfhe.FheBool), nil
		}

		result, err := lhs.ScalarLt(rhs)
		if err != nil {
			logger.Error("fheLt failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheLt scalar success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheEqRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheEq can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, _, err := load2Ciphertexts(environment, input)
		if err != nil {
			logger.Error("fheEq dailed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if lhs.Type() != rhs.Type() {
			msg := "fheEq operand type mismatch"
			logger.Error(msg, "lhs", lhs.Type(), "rhs", rhs.Type())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, tfhe.FheBool), nil
		}

		result, err := lhs.Eq(rhs)
		if err != nil {
			logger.Error("fheEq failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheEq success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.GetHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, _, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheEq scalar failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, tfhe.FheBool), nil
		}

		result, err := lhs.ScalarEq(rhs)
		if err != nil {
			logger.Error("fheEq failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheEq scalar success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheGeRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheGe can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, _, err := load2Ciphertexts(environment, input)
		if err != nil {
			logger.Error("fheGe failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if lhs.Type() != rhs.Type() {
			msg := "fheGe operand type mismatch"
			logger.Error(msg, "lhs", lhs.Type(), "rhs", rhs.Type())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, tfhe.FheBool), nil
		}

		result, err := lhs.Ge(rhs)
		if err != nil {
			logger.Error("fheGe failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheGe success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.GetHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, _, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheGe scalar failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, tfhe.FheBool), nil
		}

		result, err := lhs.ScalarGe(rhs)
		if err != nil {
			logger.Error("fheGe failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheGe scalar success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheGtRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheGt can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, _, err := load2Ciphertexts(environment, input)
		if err != nil {
			logger.Error("fheGt failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if lhs.Type() != rhs.Type() {
			msg := "fheGt operand type mismatch"
			logger.Error(msg, "lhs", lhs.Type(), "rhs", rhs.Type())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, tfhe.FheBool), nil
		}

		result, err := lhs.Gt(rhs)
		if err != nil {
			logger.Error("fheGt failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheGt success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.GetHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, _, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheGt scalar failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, tfhe.FheBool), nil
		}

		result, err := lhs.ScalarGt(rhs)
		if err != nil {
			logger.Error("fheGt failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheGt scalar success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheNeRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheNe can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, _, err := load2Ciphertexts(environment, input)
		if err != nil {
			logger.Error("fheNe failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if lhs.Type() != rhs.Type() {
			msg := "fheNe operand type mismatch"
			logger.Error(msg, "lhs", lhs.Type(), "rhs", rhs.Type())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, tfhe.FheBool), nil
		}

		result, err := lhs.Ne(rhs)
		if err != nil {
			logger.Error("fheNe failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheNe success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.GetHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, _, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheNe scalar failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, tfhe.FheBool), nil
		}

		result, err := lhs.ScalarNe(rhs)
		if err != nil {
			logger.Error("fheNe failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheNe scalar success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheMinRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheMin can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, _, err := load2Ciphertexts(environment, input)
		if err != nil {
			logger.Error("fheMin failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if lhs.Type() != rhs.Type() {
			msg := "fheMin operand type mismatch"
			logger.Error(msg, "lhs", lhs.Type(), "rhs", rhs.Type())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, lhs.Type()), nil
		}

		result, err := lhs.Min(rhs)
		if err != nil {
			logger.Error("fheMin failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheMin success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.GetHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, _, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheMin scalar failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, lhs.Type()), nil
		}

		result, err := lhs.ScalarMin(rhs)
		if err != nil {
			logger.Error("fheMin failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheMin scalar success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheMaxRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheMax can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, _, err := load2Ciphertexts(environment, input)
		if err != nil {
			logger.Error("fheMax failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if lhs.Type() != rhs.Type() {
			msg := "fheMax operand type mismatch"
			logger.Error(msg, "lhs", lhs.Type(), "rhs", rhs.Type())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, lhs.Type()), nil
		}

		result, err := lhs.Max(rhs)
		if err != nil {
			logger.Error("fheMax failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheMax success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.GetHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, _, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheMax scalar failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, lhs.Type()), nil
		}

		result, err := lhs.ScalarMax(rhs)
		if err != nil {
			logger.Error("fheMax failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheMax scalar success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheIfThenElseRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(96, len(input))]

	logger := environment.GetLogger()
	first, second, third, _, err := load3Ciphertexts(environment, input)
	if err != nil {
		logger.Error("fheIfThenElse failed to load inputs", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}
	otelDescribeOperands(runSpan, encryptedOperand(*first), encryptedOperand(*second), encryptedOperand(*third))

	if second.Type() != third.Type() {
		msg := "fheIfThenElse operand type mismatch"
		logger.Error(msg, "second", second.Type(), "third", third.Type())
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return insertRandomCiphertext(environment, second.Type()), nil
	}

	result, err := first.IfThenElse(second, third)
	if err != nil {
		logger.Error("fheIfThenElse failed", "err", err)
		return nil, err
	}
	resultHash := result.GetHash()
	insertCiphertextToMemory(environment, resultHash, result)

	//logger.Info("fheIfThenElse success", "first", first.GetHash().Hex(), "second", second.GetHash().Hex(), "third", third.GetHash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

// TODO: implement as part of fhelibMethods.
const fheArrayEqAbiJson = `
	[
		{
			"name": "fheArrayEq",
			"type": "function",
			"inputs": [
				{
					"name": "lhs",
					"type": "uint256[]"
				},
				{
					"name": "rhs",
					"type": "uint256[]"
				}
			],
			"outputs": [
				{
					"name": "",
					"type": "uint256"
				}
			]
		}
	]
`

var arrayEqMethod abi.Method

func init() {
	reader := strings.NewReader(fheArrayEqAbiJson)
	arrayEqAbi, err := abi.JSON(reader)
	if err != nil {
		panic(err)
	}

	var ok bool
	arrayEqMethod, ok = arrayEqAbi.Methods["fheArrayEq"]
	if !ok {
		panic("couldn't find the fheArrayEq method")
	}
}

func getVerifiedCiphertexts(environment EVMEnvironment, unpacked interface{}) ([]*tfhe.TfheCiphertext, uint64, error) {
	totalLoadGas := uint64(0)
	big, ok := unpacked.([]*big.Int)
	if !ok {
		return nil, 0, fmt.Errorf("fheArrayEq failed to cast to []*big.Int")
	}
	ret := make([]*tfhe.TfheCiphertext, 0, len(big))
	for _, b := range big {
		ct, loadGas := loadCiphertext(environment, common.BigToHash(b))
		if ct == nil {
			return nil, totalLoadGas + loadGas, fmt.Errorf("fheArrayEq unverified ciphertext")
		}
		totalLoadGas += loadGas
		ret = append(ret, ct)
	}
	return ret, totalLoadGas, nil
}

func fheArrayEqRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	logger := environment.GetLogger()

	unpacked, err := arrayEqMethod.Inputs.UnpackValues(input)
	if err != nil {
		msg := "fheArrayEqRun failed to unpack input"
		logger.Error(msg, "err", err)
		return nil, err
	}

	if len(unpacked) != 2 {
		err := fmt.Errorf("fheArrayEqRun unexpected unpacked len: %d", len(unpacked))
		logger.Error(err.Error())
		return nil, err
	}

	lhs, _, err := getVerifiedCiphertexts(environment, unpacked[0])
	if err != nil {
		msg := "fheArrayEqRun failed to get lhs to verified ciphertexts"
		logger.Error(msg, "err", err)
		return nil, err
	}

	rhs, _, err := getVerifiedCiphertexts(environment, unpacked[1])
	if err != nil {
		msg := "fheArrayEqRun failed to get rhs to verified ciphertexts"
		logger.Error(msg, "err", err)
		return nil, err
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return insertRandomCiphertext(environment, tfhe.FheBool), nil
	}

	result, err := tfhe.EqArray(lhs, rhs)
	if err != nil {
		msg := "fheArrayEqRun failed to execute"
		logger.Error(msg, "err", err)
		return nil, err
	}
	resultHash := result.GetHash()
	insertCiphertextToMemory(environment, resultHash, result)
	//logger.Info("fheArrayEqRun success", "result", resultHash.Hex())
	return resultHash[:], nil
}
