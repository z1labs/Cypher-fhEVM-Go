package fhevm

import (
	"encoding/hex"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"go.opentelemetry.io/otel/trace"
)

func fheAddRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheAdd can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, _, err := load2Ciphertexts(environment, input)
		if err != nil {
			logger.Error("fheAdd failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if lhs.Type() != rhs.Type() {
			msg := "fheAdd operand type mismatch"
			logger.Error(msg, "lhs", lhs.Type(), "rhs", rhs.Type())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, lhs.Type()), nil
		}

		result, err := lhs.Add(rhs)
		if err != nil {
			logger.Error("fheAdd failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		////logger.Info("fheAdd success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.GetHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, _, err := getScalarOperands(environment, input)

		if err != nil {
			//logger.Error("fheAdd scalar failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, lhs.Type()), nil
		}

		result, err := lhs.ScalarAdd(rhs)
		if err != nil {
			//logger.Error("fheAdd failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		////logger.Info("fheAdd scalar success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheSubRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheSub can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, _, err := load2Ciphertexts(environment, input)
		if err != nil {
			logger.Error("fheSub failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if lhs.Type() != rhs.Type() {
			msg := "fheSub operand type mismatch"
			logger.Error(msg, "lhs", lhs.Type(), "rhs", rhs.Type())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, lhs.Type()), nil
		}

		result, err := lhs.Sub(rhs)
		if err != nil {
			logger.Error("fheSub failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheSub success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.GetHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, _, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheSub scalar failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, lhs.Type()), nil
		}

		result, err := lhs.ScalarSub(rhs)
		if err != nil {
			logger.Error("fheSub failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheSub scalar success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheMulRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheMul can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, _, err := load2Ciphertexts(environment, input)
		if err != nil {
			logger.Error("fheMul failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if lhs.Type() != rhs.Type() {
			msg := "fheMul operand type mismatch"
			logger.Error(msg, "lhs", lhs.Type(), "rhs", rhs.Type())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, lhs.Type()), nil
		}

		result, err := lhs.Mul(rhs)
		if err != nil {
			logger.Error("fheMul failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheMul success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.GetHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, _, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheMul scalar failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, lhs.Type()), nil
		}

		result, err := lhs.ScalarMul(rhs)
		if err != nil {
			logger.Error("fheMul failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheMul scalar success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheDivRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheDiv cannot detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		err = errors.New("fheDiv supports only scalar input operation, two ciphertexts received")
		logger.Error("fheDiv supports only scalar input operation, two ciphertexts received", "input", hex.EncodeToString(input))
		return nil, err
	} else {
		lhs, rhs, _, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheDiv scalar failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, lhs.Type()), nil
		}

		result, err := lhs.ScalarDiv(rhs)
		if err != nil {
			logger.Error("fheDiv failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheDiv scalar success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheRemRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheRem cannot detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		err = errors.New("fheRem supports only scalar input operation, two ciphertexts received")
		logger.Error("fheRem supports only scalar input operation, two ciphertexts received", "input", hex.EncodeToString(input))
		return nil, err
	} else {
		lhs, rhs, _, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheRem scalar failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, lhs.Type()), nil
		}

		result, err := lhs.ScalarRem(rhs)
		if err != nil {
			logger.Error("fheRem failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheRem scalar success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}
